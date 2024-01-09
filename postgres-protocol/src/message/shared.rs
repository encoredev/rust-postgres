#![allow(missing_docs)]

use std::{cmp, io};
use std::io::Read;

use byteorder::{BigEndian, ByteOrder};
use bytes::Bytes;
use memchr::memchr;

#[derive(Debug, Copy, Clone)]
pub struct Header {
    tag: u8,
    len: i32,
}

#[allow(clippy::len_without_is_empty)]
impl Header {
    #[inline]
    pub fn parse(buf: &[u8]) -> io::Result<Option<Header>> {
        if buf.len() < 5 {
            return Ok(None);
        }

        let tag = buf[0];
        let len = BigEndian::read_i32(&buf[1..]);

        if len < 4 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid message length: header length < 4",
            ));
        }

        Ok(Some(Header { tag, len }))
    }

    #[inline]
    pub fn tag(self) -> u8 {
        self.tag
    }

    #[inline]
    pub fn len(self) -> i32 {
        self.len
    }
}

pub struct Buffer {
    pub bytes: Bytes,
    pub idx: usize,
}

impl Buffer {
    #[inline]
    pub fn slice(&self) -> &[u8] {
        &self.bytes[self.idx..]
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.slice().is_empty()
    }

    #[inline]
    pub fn read_cstr(&mut self) -> io::Result<Bytes> {
        match memchr(0, self.slice()) {
            Some(pos) => {
                let start = self.idx;
                let end = start + pos;
                let cstr = self.bytes.slice(start..end);
                self.idx = end + 1;
                Ok(cstr)
            }
            None => Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "unexpected EOF",
            )),
        }
    }

    #[inline]
    pub fn read_all(&mut self) -> Bytes {
        let buf = self.bytes.slice(self.idx..);
        self.idx = self.bytes.len();
        buf
    }
}

impl Read for Buffer {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let len = {
            let slice = self.slice();
            let len = cmp::min(slice.len(), buf.len());
            buf[..len].copy_from_slice(&slice[..len]);
            len
        };
        self.idx += len;
        Ok(len)
    }
}

