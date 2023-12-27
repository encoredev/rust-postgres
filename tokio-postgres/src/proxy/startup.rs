use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Bytes, BytesMut};
use futures_util::{Sink, SinkExt, Stream, TryStreamExt};
use tokio::io;
use tokio_util::codec::{Decoder, Encoder, Framed};

use postgres_protocol::message::startup::{CancelData, StartupRequest, StartupResponse};

use crate::{Error, Socket};

pub struct StartupCodec;

impl Encoder<StartupResponse> for StartupCodec {
    type Error = io::Error;

    fn encode(&mut self, item: StartupResponse, dst: &mut BytesMut) -> Result<(), Self::Error> {
        item.encode(dst)
    }
}

impl Decoder for StartupCodec {
    type Item = StartupRequest;
    type Error = io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> io::Result<Option<StartupRequest>> {
        StartupRequest::parse(buf)
    }
}


pub struct StartupStream<'a>
{
    inner: Framed<&'a mut Socket, StartupCodec>,
}

impl<'a> StartupStream<'a> {
    pub fn new(inner: &'a mut Socket) -> Self {
        Self {
            inner: Framed::new(inner, StartupCodec),
        }
    }
}

impl Sink<StartupResponse> for StartupStream<'_> {
    type Error = std::io::Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_ready(cx)
    }

    fn start_send(mut self: Pin<&mut Self>, item: StartupResponse) -> std::io::Result<()> {
        Pin::new(&mut self.inner).start_send(item)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_close(cx)
    }
}

impl Stream for StartupStream<'_> {
    type Item = io::Result<StartupRequest>;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<io::Result<StartupRequest>>> {
        Pin::new(&mut self.inner).poll_next(cx)
    }
}

pub enum StartupInfo {
    Startup(Bytes),
    Cancel(CancelData),
}

pub async fn read_frontend_startup(
    stream: &mut StartupStream<'_>,
) -> Result<StartupInfo, Error> {
    loop {
        let Some(msg) = stream.try_next().await.map_err(Error::io)? else {
            return Err(Error::closed())
        };
        match msg {
            StartupRequest::Startup(data) => {
                return Ok(StartupInfo::Startup(data));
            }
            StartupRequest::Cancel(data) => {
                return Ok(StartupInfo::Cancel(data));
            }
            StartupRequest::SSLRequest => {
                stream.send(StartupResponse::SSLResponse(false)).await.map_err(Error::io)?;
            }
            StartupRequest::GSSEncRequest => {
                stream.send(StartupResponse::GSSEncResponse(false)).await.map_err(Error::io)?;
            }
        }
    }
}
