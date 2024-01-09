use bytes::{Bytes, BytesMut};
use futures_util::{SinkExt, TryStreamExt};
use tokio::io;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::{Decoder, Encoder, Framed};

use postgres_protocol::message::startup::{CancelData, StartupRequest, StartupResponse};

use crate::Error;

pub struct StartupCodec {
    /// Tracks whether we've seen the startup request from the client.
    /// Once true the codec transitions to parsing requests using the
    /// initial byte tag (which is not present in the startup request).
    seen_client_startup: bool,
}

impl StartupCodec {
    pub fn new() -> StartupCodec {
        StartupCodec {
            seen_client_startup: false,
        }
    }
}

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
        let req = if self.seen_client_startup {
            StartupRequest::parse_with_tag(buf)
        } else {
            StartupRequest::parse_without_tag(buf)
        }?;

        if let Some(StartupRequest::Startup(_)) = &req {
            self.seen_client_startup = true;
        }
        Ok(req)
    }
}


pub enum StartupInfo {
    Startup(Bytes),
    Cancel(CancelData),
}

pub async fn read_frontend_startup<S>(
    stream: &mut Framed<S, StartupCodec>,
) -> Result<StartupInfo, Error>
where
    S: AsyncRead + AsyncWrite + Unpin
{
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
                log::debug!("sending ssl reject");
                stream.send(StartupResponse::SSLResponse(false)).await.map_err(Error::io)?;
                log::debug!("sent ssl reject");
            }
            StartupRequest::GSSEncRequest => {
                log::debug!("sending gss reject");
                stream.send(StartupResponse::GSSEncResponse(false)).await.map_err(Error::io)?;
                log::debug!("sent gss reject");
            }
            StartupRequest::Password(_) => {
                return Err(Error::unexpected_message());
            }
        }
    }
}
