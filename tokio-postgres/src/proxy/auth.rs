use futures_util::{SinkExt, TryStreamExt, };
use rand::RngCore;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::Framed;

use postgres_protocol::authentication::md5_hash;
use postgres_protocol::message::startup::{StartupData, StartupRequest, StartupResponse};

use crate::Error;
use crate::proxy::AuthMethod;
use crate::proxy::startup::StartupCodec;

impl AuthMethod {
    pub(super) async fn authenticate<S>(&self, stream: &mut Framed<S, StartupCodec>, startup_data: &StartupData) -> Result<(), Error>
    where S: AsyncRead + AsyncWrite + Unpin
    {
        match self {
            AuthMethod::Trust => {
                // Nothing to do.
                Ok(())
            }

            AuthMethod::Password(expected_password) => {
                // Generate a random salt.
                let salt = {
                    let mut salt = [0; 4];
                    let mut rng = rand::thread_rng();
                    rng.fill_bytes(&mut salt);
                    salt
                };

                stream
                    .send(StartupResponse::AuthenticationMD5Password { salt })
                    .await
                    .map_err(Error::io)?;
                stream.flush().await.map_err(Error::io)?;

                // Read the response.
                let msg = stream
                    .try_next()
                    .await
                    .map_err(Error::io)?;

                match msg {
                    Some(StartupRequest::Password(received_hash)) => {
                        if !md5_password_equal(expected_password.as_bytes(), &received_hash, startup_data, salt) {
                            return Err(Error::authentication("invalid password".into()));
                        } else {
                            Ok(())
                        }
                    }
                    _ => Err(Error::unexpected_message())
                }
            }
        }
    }
}

fn md5_password_equal(expected_password: &[u8], received_hash: &[u8], startup: &StartupData, salt: [u8; 4]) -> bool {
    let Some(username) = startup.parameters.get("user") else {
        return false
    };

    let expected_hash = md5_hash(&username, expected_password, salt);
    constant_time_eq::constant_time_eq(&received_hash, expected_hash.as_bytes())
}