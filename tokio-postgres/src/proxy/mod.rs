#![allow(missing_docs)]

use tokio::io::{AsyncRead, AsyncWrite, copy_bidirectional};
use tokio_util::codec::Framed;

use crate::{Config, Error, Socket};
use crate::client::SocketConfig;
use crate::codec::PostgresCodec;
use crate::connect_proxy::connect_proxy;
use crate::maybe_tls_stream::MaybeTlsStream;
use crate::proxy::startup::{read_frontend_startup, StartupInfo, StartupStream};
use crate::tls::{MakeTlsConnect, TlsConnect};

mod startup;

pub struct ProxyConfig<T>
{
    /// The backend configuration to use.
    pub backend_config: Config,

    /// The TLS configuration to use.
    pub tls: T,
}

impl<T> ProxyConfig<T>
where
    T: MakeTlsConnect<Socket> + 'static + Send + Clone,
    T::TlsConnect: Send,
    T::Stream: Send,
    <T::TlsConnect as TlsConnect<Socket>>::Future: Send,
{
    pub async fn run(self, addr: impl tokio::net::ToSocketAddrs) -> Result<(), Error> {
        let proxy = Proxy {
            backend_config: self.backend_config,
            tls: self.tls,
        };
        proxy.run(addr).await
    }
}


struct Proxy<T> {
    backend_config: Config,
    tls: T,
}

impl<T> Proxy<T>
where
    T: MakeTlsConnect<Socket> + 'static + Send + Clone,
    T::TlsConnect: Send,
    T::Stream: Send,
    <T::TlsConnect as TlsConnect<Socket>>::Future: Send,
{
    async fn run(self, addr: impl tokio::net::ToSocketAddrs) -> Result<(), Error> {
        let listener = tokio::net::TcpListener::bind(addr).await.map_err(Error::io)?;
        loop {
            let (stream, _) = listener.accept().await.map_err(Error::io)?;
            let stream = Socket::new_tcp(stream);

            let config = self.backend_config.clone();
            let tls = self.tls.clone();
            tokio::spawn(async move {
                match proxy_conn(tls, &config, stream).await {
                    Ok(()) => {}
                    Err(e) => {
                        log::info!("proxy error: {}", e);
                    }
                }
            });
        }
    }
}

async fn proxy_conn<T>(tls: T, backend_config: &Config, client_stream: Socket) -> Result<(), Error>
where
    T: MakeTlsConnect<Socket> + 'static + Send,
    T::TlsConnect: Send,
    T::Stream: Send,
    <T::TlsConnect as TlsConnect<Socket>>::Future: Send,
{
    let conn = setup_conn(tls, &backend_config, client_stream).await?;
    conn.copy_data().await
}

async fn setup_conn<T>(tls: T, backend_config: &Config, mut client_stream: Socket) -> Result<ProxyConn<T::Stream>, Error>
where
  T: MakeTlsConnect<Socket> + 'static + Send,
  T::TlsConnect: Send,
  T::Stream: Send,
  <T::TlsConnect as TlsConnect<Socket>>::Future: Send,
{
    let mut startup_stream = StartupStream::new(&mut client_stream);
    match read_frontend_startup(&mut startup_stream).await? {
        StartupInfo::Cancel(_) => {
            // TODO handle cancellation
            Err(Error::unexpected_message())
        }
        StartupInfo::Startup(_) => {
            // TODO write AuthenticationOk to client.
            let (backend, socket_config) = connect_proxy(tls, backend_config).await?;
            Ok(ProxyConn::new(client_stream, backend, socket_config))
        }
    }
}


pub struct ProxyConn<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    client: Socket,
    backend: Framed<MaybeTlsStream<Socket, T>, PostgresCodec>,
    _socket_config: SocketConfig,
}

impl<T> ProxyConn<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    pub(crate) fn new(
        client: Socket,
        backend: Framed<MaybeTlsStream<Socket, T>, PostgresCodec>,
        socket_config: SocketConfig
    ) -> Self {
        Self {
            client,
            backend,
            _socket_config: socket_config,
        }
    }

    async fn copy_data(mut self) -> Result<(), Error> {
        let mut backend = self.backend.into_inner();
        copy_bidirectional(&mut self.client, &mut backend).await.map_err(Error::io)?;
        Ok(())
    }
}

