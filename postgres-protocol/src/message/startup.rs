#![allow(missing_docs)]

use std::collections::HashMap;
use std::io;
use std::iter::FromIterator;

use byteorder::{BigEndian, ReadBytesExt};
use bytes::{BufMut, Bytes, BytesMut};
use crate::message::shared::Buffer;

#[derive(Debug)]
pub enum StartupRequest {
    Startup(Bytes),
    Cancel(CancelData),
    SSLRequest,
    GSSEncRequest,
    Password(Bytes),
}

#[derive(Debug)]
pub struct CancelData {
    pub process_id: i32,
    pub secret_key: i32,
}

impl StartupRequest {
    #[inline]
    pub fn parse_without_tag(buf: &mut BytesMut) -> io::Result<Option<StartupRequest>> {
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
            idx: 4,
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

    #[inline]
    pub fn parse_with_tag(buf: &mut BytesMut) -> io::Result<Option<StartupRequest>> {
        if buf.len() < 5 {
            let to_read = 5 - buf.len();
            buf.reserve(to_read);
            return Ok(None);
        }

        let len = (&buf[1..5]).read_u32::<BigEndian>().unwrap() as usize;

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

        let tag = buf[0] as char;
        let mut buf = Buffer {
            bytes: buf.split_to(len).freeze(),
            idx: 5,
        };

        let message = match tag as char {
            // PasswordMessage
            'p' => {
                let passwd = buf.read_cstr()?;
                StartupRequest::Password(passwd)
            }

            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unknown startup message tag '{}'", tag),
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

#[derive(Debug)]
pub struct StartupData {
    pub parameters: HashMap<String, Bytes>,
}

impl StartupData {
    pub fn parse(bytes: Bytes) -> io::Result<StartupData>
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
            Some((key_str, value))
        });

        let parameters = HashMap::from_iter(pairs);
        Ok(StartupData { parameters })
    }
}

#[derive(Debug)]
pub enum StartupResponse {
    AuthenticationOk,
    AuthenticationMD5Password { salt: [u8; 4] },
    SSLResponse(bool),
    GSSEncResponse(bool),
    ErrorResponse(String),
    ParameterStatus { key: String, value: Bytes },
    ReadyForQuery,
}

impl StartupResponse {
    pub fn encode(&self, dst: &mut BytesMut) -> Result<(), io::Error> {
        match self {
            StartupResponse::AuthenticationOk => {
                dst.reserve(1 + 8);
                dst.put_u8(b'R');
                dst.put_u32(8);
                dst.put_u32(0); // auth ok
            }
            StartupResponse::AuthenticationMD5Password { salt } => {
                dst.reserve(1 + 12);
                dst.put_u8(b'R');
                dst.put_u32(12);
                dst.put_slice(&salt[..]);
                dst.put_u32(0); // salt
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
                let len = 4 + (1 + 5 + 1) + (1 + err_bytes.len() + 1) + 1;
                dst.reserve(1 + len);
                dst.put_u8(b'E');
                dst.put_u32(len as u32);

                dst.put_u8(b'S');
                dst.put_slice(b"FATAL");
                dst.put_u8(0);

                dst.put_u8(b'M');
                dst.put_slice(err_bytes);
                dst.put_u8(0);
                dst.put_u8(0);
            }

            StartupResponse::ParameterStatus { key, value } => {
                let key_bytes = key.as_bytes();
                let value_bytes = value.as_ref();

                let len = 4 + (key_bytes.len() + 1) + (value_bytes.len() + 1);
                dst.reserve(1 + len);
                dst.put_u8(b'S');
                dst.put_u32(len as u32);

                dst.put_slice(key_bytes);
                dst.put_u8(0);
                dst.put_slice(value_bytes);
                dst.put_u8(0);
            }

            StartupResponse::ReadyForQuery => {
                dst.reserve(1 + 5);
                dst.put_u8(b'Z');
                dst.put_u32(5);
                dst.put_u8(b'I');
            }
        }
        Ok(())
    }
}


