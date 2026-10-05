use std::sync::Arc;

use bytes::BytesMut;
use futures_util::{future, join, FutureExt};
use postgres_protocol::message::backend::Message;
use postgres_protocol::message::frontend;
use postgres_protocol::message::startup::StartupData;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time;
use tokio_postgres::error::SqlState;
use tokio_postgres::proxy::{AcceptConn, AuthMethod, ClientBouncer, ProxyManager, RejectConn};
use tokio_postgres::{Client, Config, NoTls};

/// Routes every client to the backend its config describes.
#[derive(Clone)]
struct Bouncer(Arc<Config>);

impl ClientBouncer for Bouncer {
    type Tls = NoTls;
    type Future = future::Ready<Result<AcceptConn<NoTls>, RejectConn>>;

    fn handle_startup(&self, _: &StartupData) -> Self::Future {
        future::ready(Ok(AcceptConn {
            auth_method: AuthMethod::Trust,
            tls: NoTls,
            backend_config: self.0.clone(),
        }))
    }
}

/// Serves a proxy to the backend `backend` describes, returning its port.
async fn proxy(backend: &str) -> u16 {
    let manager = ProxyManager::new(Bouncer(Arc::new(backend.parse().unwrap())));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            tokio::spawn(manager.clone().handle_conn(stream));
        }
    });
    port
}

/// Connects to the proxy on `port`, as a user and to a database the backend
/// does not have, with the settings in `params`.
async fn connect(port: u16, params: &str) -> Client {
    let config = format!("host=127.0.0.1 port={port} user=encore dbname=encore {params}");
    let (client, connection) = tokio_postgres::connect(&config, NoTls).await.unwrap();
    tokio::spawn(connection.map(|r| r.unwrap()));
    client
}

async fn show(client: &Client, setting: &str) -> String {
    let row = client
        .query_one(&format!("SHOW {setting}"), &[])
        .await
        .unwrap();
    row.get(0)
}

#[tokio::test]
async fn cancel_query() {
    let port = proxy("host=localhost port=5433 user=postgres").await;
    let client = connect(port, "").await;

    let cancel_token = client.cancel_token();
    let cancel = cancel_token.cancel_query(NoTls);
    let cancel = time::sleep(Duration::from_millis(100)).then(|()| cancel);

    let sleep = client.batch_execute("SELECT pg_sleep(5)");

    match join!(sleep, cancel) {
        (Err(ref e), Ok(())) if e.code() == Some(&SqlState::QUERY_CANCELED) => {}
        t => panic!("unexpected return: {:?}", t),
    }
}

#[tokio::test]
async fn client_application_name_and_options() {
    let port = proxy(
        "host=localhost port=5433 user=postgres application_name=backend \
         options='-c statement_timeout=12345 -c search_path=backend'",
    )
    .await;

    let client = connect(port, "").await;
    assert_eq!(show(&client, "application_name").await, "backend");
    assert_eq!(show(&client, "search_path").await, "backend");

    let client = connect(
        port,
        "application_name=client options='-c search_path=client'",
    )
    .await;
    assert_eq!(show(&client, "application_name").await, "client");
    assert_eq!(show(&client, "search_path").await, "client");
    assert_eq!(show(&client, "statement_timeout").await, "12345ms");
}

#[tokio::test]
async fn client_runtime_parameters() {
    let port = proxy("host=localhost port=5433 user=postgres").await;

    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let mut buf = BytesMut::new();
    frontend::startup_message(
        [
            ("user", "encore"),
            ("database", "encore"),
            ("TimeZone", "Asia/Tokyo"),
            ("_pq_.unknown_option", "on"),
        ],
        &mut buf,
    )
    .unwrap();
    stream.write_all(&buf).await.unwrap();

    let mut timezone = None;
    let mut backend_key = false;
    let mut buf = BytesMut::new();
    loop {
        match Message::parse(&mut buf).unwrap() {
            Some(Message::AuthenticationOk) => {}
            Some(Message::ParameterStatus(body)) => {
                if body.name().unwrap() == "TimeZone" {
                    timezone = Some(body.value().unwrap().to_string());
                }
            }
            Some(Message::BackendKeyData(_)) => backend_key = true,
            Some(Message::ReadyForQuery(_)) => break,
            Some(Message::ErrorResponse(_)) => panic!("the proxy refused the connection"),
            Some(_) => panic!("unexpected message"),
            None => assert_ne!(stream.read_buf(&mut buf).await.unwrap(), 0),
        }
    }
    assert_eq!(timezone.as_deref(), Some("Asia/Tokyo"));
    assert!(backend_key);
}
