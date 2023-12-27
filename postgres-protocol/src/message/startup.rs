#![allow(missing_docs)]

use std::io;
use std::iter::FromIterator;

use byteorder::{BigEndian, ReadBytesExt};
use bytes::{BufMut, Bytes, BytesMut};
use crate::message::shared::Buffer;

pub enum StartupRequest {
    Startup(Bytes),
    Cancel(CancelData),
    SSLRequest,
    GSSEncRequest,
}

pub struct CancelData {
    pub process_id: i32,
    pub secret_key: i32,
}

impl StartupRequest {
    #[inline]
    pub fn parse(buf: &mut BytesMut) -> io::Result<Option<StartupRequest>> {
        if buf.len() < 4 {
            let to_read = 4 - buf.len();
            buf.reserve(to_read);
            return Ok(None);
        }

        let len = (&buf[0..4]).read_u32::<BigEndian>().unwrap() as usize;

        // defined in pg source
        const MIN_STARTUP_LEN: usize = 4;
        const MAX_STARTUP_LEN: usize = 10000;

        if len < MIN_STARTUP_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid message length: parsing u32",
            ));
        } else if len > MAX_STARTUP_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid message length: parsing u32",
            ));
        }

        // Read the message contents.
        if buf.len() < len {
            let to_read = len - buf.len();
            buf.reserve(to_read);
            return Ok(None);
        }

        let mut buf = Buffer {
            bytes: buf.split_to(len).freeze(),
            idx: 5,
        };

        let code = buf.read_u32::<BigEndian>()?;
        let message = match code {
            // Startup message
            196_608 => {
                let data = buf.read_all();
                StartupRequest::Startup(data)
            },

            // Cancel Request
            80_877_102 => {
                let process_id = buf.read_i32::<BigEndian>()?;
                let secret_key = buf.read_i32::<BigEndian>()?;
                StartupRequest::Cancel(CancelData {
                    process_id,
                    secret_key,
                })
            },

            // SSL Request
            80_877_103 => StartupRequest::SSLRequest,


            // GSS Encode Request
            80_877_104 => StartupRequest::GSSEncRequest,

            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unknown startup message code `{}`", code),
                ));
            }
        };

        if !buf.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid message length: expected buffer to be empty",
            ));
        }

        Ok(Some(message))
    }
}

pub struct StartupData<P> {
    pub parameters: P,
}

impl<P> StartupData<P>
    where P: FromIterator<(String, String)>
{
    pub fn parse(bytes: Bytes) -> io::Result<StartupData<P>>
    {
        let mut buf = Buffer {
            bytes,
            idx: 0,
        };

        let pairs = std::iter::from_fn(move || {
            let key = buf.read_cstr().ok()?;
            if key.is_empty() {
                return None;
            }
            let value = buf.read_cstr().ok()?;
            let key_str = String::from_utf8(key.to_vec()).ok()?;
            let value_str = String::from_utf8(value.to_vec()).ok()?;
            Some((key_str, value_str))
        });

        let parameters = P::from_iter(pairs);
        Ok(StartupData { parameters })
    }
}

pub enum StartupResponse {
    AuthenticationOk,
    SSLResponse(bool),
    GSSEncResponse(bool),
    ErrorResponse(String)
}

impl StartupResponse {
    pub fn encode(&self, dst: &mut BytesMut) -> Result<(), io::Error> {
        match self {
            StartupResponse::AuthenticationOk => {
                dst.reserve(9);
                dst.put_u8(b'R');
                dst.put_u32(8);
                dst.put_u32(0);
            }
            StartupResponse::SSLResponse(ok) => {
                dst.reserve(1);
                dst.put_u8(if *ok { b'S' } else { b'N' });
            }
            StartupResponse::GSSEncResponse(ok) => {
                dst.reserve(1);
                dst.put_u8(if *ok { b'G' } else { b'N' });
            }
            StartupResponse::ErrorResponse(err) => {
                let err_bytes = err.as_bytes();
                let len = 4 + err_bytes.len() + 1 + 1;
                dst.reserve(1 + len);
                dst.put_u8(b'F');
                dst.put_u32(len as u32);
                dst.put_slice(err_bytes);
                dst.put_u8(0);
                dst.put_u8(0);
            }
        }
        Ok(())
    }
}


