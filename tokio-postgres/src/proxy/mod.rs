#![allow(missing_docs)]

mod startup;
mod auth;

use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use bytes::Bytes;

use futures_util::{SinkExt, try_join};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, copy_bidirectional};
use tokio::net::TcpStream;
use tokio_util::codec::{Framed, FramedParts};

use postgres_protocol::message::startup::{CancelData, StartupData, StartupResponse};

use crate::{CancelToken, Config, Error, Socket};
use crate::connect_proxy::{connect_proxy, ProxyInfo};
use crate::proxy::startup::{read_frontend_startup, StartupCodec, StartupInfo};
use crate::tls::{MakeTlsConnect, TlsConnect};

/// A trait for determining if, and where, to route an incoming client connection.
pub trait ClientBouncer: Clone + Sync + Send + 'static
{
    type Tls: MakeTlsConnect<Socket> + Send + Clone + 'static;
    type Future: Future<Output=Result<AcceptConn<Self::Tls>, RejectConn>> + Send + 'static;

    /// Handles a startup message from a client.
    /// Returns a `BackendConfig` if the connection should be proxied to a backend,
    /// or an error if the connection should be rejected.
    fn handle_startup(&self, info: &StartupData) -> Self::Future;
}

/// RejectConn contains reasons for rejecting an incoming connection.
pub enum RejectConn {
    UnknownDatabase,
    UnknownUser,
    InternalError,
}

/// AcceptConn specifies how a connection should be proxied to a backend.
pub struct AcceptConn<T> {
    /// How to authenticate the client.
    pub auth_method: AuthMethod,

    /// TLS configuration to use.
    pub tls: T,

    /// Backend configuration to use.
    pub backend_config: Arc<Config>,
}

/// How to authenticate an incoming connection.
pub enum AuthMethod {
    // Trust the user implicitly without authentication.
    Trust,

    /// Authenticate the user with a password.
    Password(String),
}

#[derive(Clone)]
pub struct ProxyManager<B>
    where B: ClientBouncer
{
    bouncer: B,

    /// The cancel handles for active connections, keyed by the process ID and secret key.
    cancel_handles: Arc<tokio::sync::RwLock<HashMap<CancelKey, CancelHandle<B::Tls>>>>
}

/// Handles proxying connections from clients to backends.
impl<B> ProxyManager<B>
    where
        B: ClientBouncer,
        <B::Tls as MakeTlsConnect<Socket>>::TlsConnect: Send,
        <B::Tls as MakeTlsConnect<Socket>>::Stream: Send,
        <<B::Tls as MakeTlsConnect<Socket>>::TlsConnect as TlsConnect<Socket>>::Future: Send,
{
    pub fn new(bouncer: B) -> Self {
        Self {
            bouncer,
            cancel_handles: Arc::default(),
        }
    }

    /// Handles a TCP connection from a client.
    pub async fn handle_conn(self, client_stream: TcpStream) {
        let mut startup_stream = Framed::new(client_stream, StartupCodec::new());

        // Phase 1: client startup
        let Some(mut accept) = self.client_startup(&mut startup_stream).await else {
            return;
        };

        // Phase 2: backend startup
        let backend_info = match connect_proxy(&mut accept.tls, &accept.backend_config).await {
            Ok(backend_info) => backend_info,
            Err(err) => {
                _ = startup_stream
                    .send(StartupResponse::ErrorResponse(format!(
                        "backend connection failed: {:?}",
                        err
                    )))
                    .await;
                return;
            }
        };

        // Notify the client that authentication is successful.
        if let Err(_) = self.complete_client_init(&mut startup_stream, &backend_info).await {
            // Client is gone.
            return;
        }

        // Register the cancel handle so cancellation requests can be handled.
        let cancel_registration = {
            let reg = CancelHandleRegistration {
                key: CancelKey {
                    process_id: backend_info.process_id,
                    secret_key: backend_info.secret_key,
                },
                lock: self.cancel_handles.clone(),
            };
            reg.register(CancelHandle {
                token: CancelToken {
                    socket_config: Some(backend_info.socket_config),
                    ssl_mode: accept.backend_config.ssl_mode,
                    process_id: backend_info.process_id,
                    secret_key: backend_info.secret_key,
                },
                tls: accept.tls,
            }).await;
            reg
        };

        // Proxy data in both directions.
        let proxy_result = {
            let mut backend_parts = backend_info.backend.into_parts();
            let mut client_parts = startup_stream.into_parts();
            proxy_data(&mut client_parts, &mut backend_parts).await
        };

        // Remove the cancel registration.
        cancel_registration.deregister().await;

        match proxy_result {
            Ok(()) => log::debug!("proxy connection closed"),
            Err(err) => log::error!("proxy connection error: {}", err),
        }
    }

    /// Handles starting up a client connection.
    /// It returns None if the connection should be closed, whether for authentication issues
    /// or because the client requested cancellation.
    async fn client_startup<S>(&self, startup_stream: &mut Framed<S, StartupCodec>) -> Option<AcceptConn<B::Tls>>
        where
            S: AsyncRead + AsyncWrite + Unpin
    {
        // Read the startup message.
        match read_frontend_startup(startup_stream).await.ok()? {
            StartupInfo::Cancel(cancel) => {
                self.handle_cancel(cancel).await;
                // From https://www.postgresql.org/docs/current/protocol-flow.html#PROTOCOL-FLOW-CANCELING-REQUESTS:
                // "For security reasons, no direct reply is made to the cancel request message"
                None
            }

            StartupInfo::Startup(raw) => {
                // Determine where to route the connection.
                let startup_data = StartupData::parse(raw).ok()?;
                match self.bouncer.handle_startup(&startup_data).await {
                    Ok(accept) => {
                        // Authenticate the user.
                        match accept.auth_method.authenticate(startup_stream, &startup_data).await {
                            Ok(()) => {
                                // Successfully authenticated.
                                Some(accept)
                            }
                            Err(err) => {
                                // Failed to authenticate.
                                log::error!("authentication failed: {}", err);

                                // Ignore error from sending to client; we already have an error to return.
                                _ = startup_stream.send(StartupResponse::ErrorResponse("authentication failed".to_string())).await;
                                None
                            }
                        }
                    }
                    Err(_reject) => {
                        // Ignore error from sending to client; we already have an error to return.
                        _ = startup_stream.send(StartupResponse::ErrorResponse("connection rejected".to_string())).await;
                        None
                    }
                }
            }
        }
    }

    async fn complete_client_init<S>(&self, startup_stream: &mut Framed<S, StartupCodec>, backend_info: &ProxyInfo<B::Tls>) -> Result<(), Error>
    where S: AsyncRead + AsyncWrite + Unpin
    {
        // Notify the client the authentication is successful.
        startup_stream.feed(StartupResponse::AuthenticationOk).await.map_err(Error::io)?;

        // Send backend parameters, sorted by key.
        let mut parameters = backend_info.parameters.iter().map(|(k, v)| {
            (k.clone(), v.clone()) }).collect::<Vec<_>>();

        parameters.sort_by(|a, b| a.0.cmp(&b.0));
        for (key, value) in parameters {
            let msg = StartupResponse::ParameterStatus {
                key: key.clone(),
                value: Bytes::from(value),
            };
            startup_stream.feed(msg).await.map_err(Error::io)?;
        }

        // Send ReadyForQuery
        startup_stream.feed(StartupResponse::ReadyForQuery).await.map_err(Error::io)?;

        // Flush the stream.
        startup_stream.flush().await.map_err(Error::io)?;

        Ok(())
    }

    /// Handles a cancellation request from a client.
    async fn handle_cancel(&self, cancel: CancelData) {
        let key = CancelKey {
            process_id: cancel.process_id,
            secret_key: cancel.secret_key,
        };

        if let Some(handle) = self.cancel_handles.read().await.get(&key) {
            let tls = handle.tls.clone();
            _ = handle.token.cancel_query(tls).await;
        }
    }
}

async fn proxy_data<C, CC, S, SC>(
    client: &mut FramedParts<C, CC>,
    server: &mut FramedParts<S, SC>,
) -> Result<(), Error>
    where
        C: AsyncRead + AsyncWrite + Unpin,
        S: AsyncRead + AsyncWrite + Unpin,
{
    // Write all pending data
    write_pending(client, server).await?;

    // Copy data in both directions until EOF is reached.
    copy_bidirectional(&mut client.io, &mut server.io).await.map_err(Error::io)?;

    Ok(())
}

async fn write_pending<C, CC, S, SC>(
    client: &mut FramedParts<C, CC>,
    server: &mut FramedParts<S, SC>,
) -> Result<(), Error>
    where
        C: AsyncRead + AsyncWrite + Unpin,
        S: AsyncRead + AsyncWrite + Unpin,
{
    // Write unwritten data.
    let a = server.io.write_all(&server.write_buf);
    let b = client.io.write_all(&client.write_buf);
    try_join!(a, b).map_err(Error::io)?;

    let c = client.io.write_all(&server.read_buf);
    let d = server.io.write_all(&client.read_buf);
    try_join!(c, d).map_err(Error::io)?;
    Ok(())
}

struct CancelHandle<T> {
    token: CancelToken,
    tls: T,
}

/// The key used to identify a cancellation token.
#[derive(Clone, Hash, PartialEq, Eq)]
struct CancelKey {
    process_id: i32,
    secret_key: i32,
}


struct CancelHandleRegistration<T> {
    key: CancelKey,
    lock: Arc<tokio::sync::RwLock<HashMap<CancelKey, CancelHandle<T>>>>,
}

impl<T> CancelHandleRegistration<T> {
    pub async fn register(&self, handle: CancelHandle<T>) {
        self.lock.write().await.insert(self.key.clone(), handle);
    }

    pub async fn deregister(&self) {
        self.lock.write().await.remove(&self.key);
    }
}
