use bytes::{Buf, BufMut, BytesMut};
use chacha20poly1305::{
    aead::{
        generic_array::ArrayLength,
        stream::{Encryptor, NonceSize, StreamPrimitive},
    },
    AeadInPlace,
};

use std::{
    io::Write,
    ops::Sub,
    pin::Pin,
    task::{ready, Poll},
};

use tokio::io::AsyncWrite;

use crate::{DEFAULT_BUFFER_SIZE, DEFAULT_CHUNK_SIZE};

pin_project_lite::pin_project! {
    /// Async Encryption Write Half.
    ///
    /// This struct has an internal buffer to hold encrypted bytes that were not written to the
    /// inner writter. Under "normal" circunstances, the internal buffer will be seldom used.
    pub struct WriteHalf<T, U> {
        #[pin]
        pub inner: T,
        encryptor: U,
        encrypted_buffer: bytes::BytesMut,
        unencrypted_buffer: Vec<u8>,
        chunk_size: usize
    }
}

impl<T, A, S> WriteHalf<T, Encryptor<A, S>>
where
    T: AsyncWrite,
    S: StreamPrimitive<A>,
    A: AeadInPlace,
    A::NonceSize: Sub<<S as StreamPrimitive<A>>::NonceOverhead>,
    NonceSize<A, S>: ArrayLength<u8>,
{
    pub fn new(inner: T, encryptor: Encryptor<A, S>) -> Self {
        Self::with_capacity(inner, encryptor, DEFAULT_BUFFER_SIZE, DEFAULT_CHUNK_SIZE)
    }

    pub fn with_capacity(
        inner: T,
        encryptor: Encryptor<A, S>,
        size: usize,
        chunk_size: usize,
    ) -> Self {
        Self {
            inner,
            encryptor,
            encrypted_buffer: BytesMut::with_capacity(size),
            unencrypted_buffer: Vec::with_capacity(DEFAULT_CHUNK_SIZE),
            chunk_size,
        }
    }

    /// Encrypts `buf` contents and return a [`Vec<u8>`] representing the encrypted content.
    /// If the encryption fails, it returns [std::error::ErrorKind::InvalidInput]
    fn get_encrypted(&mut self, buf: &[u8]) -> std::io::Result<Vec<u8>> {
        let mut encrypted = self
            .encryptor
            .encrypt_next(buf)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidInput, err))?;

        let mut buf = Vec::with_capacity(encrypted.len());
        buf.append(&mut encrypted);

        Ok(buf)
    }

    /// encrypts the internal unencrypted buffer if possible.
    fn get_encrypted_from_internal_unencrypted_buffer(
        &mut self,
    ) -> Option<std::io::Result<Vec<u8>>> {
        if self.unencrypted_buffer.len() < self.chunk_size {
            None
        } else {
            let encryption_result = self
                .encryptor
                .encrypt_next(&self.unencrypted_buffer[..])
                .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidInput, err));

            let mut encrypted = match encryption_result {
                Ok(encrypted) => encrypted,
                Err(e) => return Some(Err(e)),
            };

            let mut buf = Vec::with_capacity(encrypted.len());
            buf.append(&mut encrypted);
            self.unencrypted_buffer.clear();
            Some(Ok(buf))
        }
    }

    /// Flush the internal buffer into the inner writer. This functions does nothing if the
    /// internal buffer is empty.   
    ///
    /// If the inner writter writes 0 bytes, this function will return an
    /// [std::io::ErrorKind::WriteZero] error.
    fn flush_buf(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut me = self.project();
        while me.encrypted_buffer.has_remaining() {
            match ready!(me.inner.as_mut().poll_write(cx, &me.encrypted_buffer[..])) {
                Ok(0) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "failed to write the buffered data",
                    )));
                }
                Ok(n) => me.encrypted_buffer.advance(n),
                Err(e) => return Poll::Ready(Err(e)),
            }
        }

        Poll::Ready(Ok(()))
    }
}

impl<T, A, S> AsyncWrite for WriteHalf<T, Encryptor<A, S>>
where
    T: AsyncWrite + Unpin,
    S: StreamPrimitive<A>,
    A: AeadInPlace,
    A::NonceSize: Sub<<S as StreamPrimitive<A>>::NonceOverhead>,
    NonceSize<A, S>: ArrayLength<u8>,
{
    /// Encrypt `buf` content, write into `self.inner` and returns the number of bytes
    /// encrypted.
    ///
    /// Since tokio runtime will call this function repeatedly with the same contents when
    /// [Poll::Pending] is returned, this function may return [Poll::Pending] only when
    /// trying to flush the internal buffer, otherwise it will always return `Poll::Ready(Ok(n))`,
    /// even if the inner writer fails.
    ///
    /// This behavior was adopted to guarantee parity with the reading counterpart,
    /// the contents of `buf` must be encrypted only once, if the internal writing operation fails,
    /// the already encrypted contents will be written into the internal buffer instead.
    ///
    /// It is guaranteed that `0 <= n <= buf.len()`
    ///
    /// Internally, the contents of `buf` will be splitted into chunks of `self.chunk_size` size,
    /// default to 1024 bytes, to avoid allocating a huge `Vec<u8>` when encrypting larger messages.
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        if !self.encrypted_buffer.is_empty() {
            ready!(self.as_mut().flush_buf(cx))?
        }

        let taken: usize = if self.unencrypted_buffer.is_empty() {
            0
        } else {
            let to_take = std::cmp::min(self.chunk_size - self.unencrypted_buffer.len(), buf.len());
            self.unencrypted_buffer.extend_from_slice(&buf[..to_take]);

            if self.unencrypted_buffer.len() == self.chunk_size {
                let encrypted = self
                    .get_encrypted_from_internal_unencrypted_buffer()
                    .expect("We have checked that there is a chunk's worth of unencrypted data")?;
                let me = self.as_mut().project();
                match me.inner.poll_write(cx, &encrypted[..]) {
                    Poll::Ready(Ok(written)) => {
                        if written < encrypted.len() {
                            self.encrypted_buffer.put(&encrypted[written..]);
                            return Poll::Ready(Ok(to_take));
                        }
                    }
                    Poll::Pending | Poll::Ready(Err(..)) => {
                        self.encrypted_buffer.put(&encrypted[..]);
                        return Poll::Ready(Ok(to_take));
                    }
                }
            }
            to_take
        };

        let buf = &buf[taken..];
        let mut total_written = taken;

        let mut chunks = buf.chunks_exact(self.chunk_size);
        for chunk in &mut chunks {
            let encrypted = self.get_encrypted(chunk)?;
            total_written += chunk.len();

            let me = self.as_mut().project();
            match me.inner.poll_write(cx, &encrypted[..]) {
                Poll::Ready(Ok(written)) => {
                    if written < encrypted.len() {
                        self.encrypted_buffer.put(&encrypted[written..]);
                        return Poll::Ready(Ok(total_written));
                    }
                }
                Poll::Pending | Poll::Ready(Err(..)) => {
                    self.encrypted_buffer.put(&encrypted[..]);
                    return Poll::Ready(Ok(total_written));
                }
            }
        }

        let leftover = chunks.remainder().len();
        self.unencrypted_buffer
            .extend_from_slice(chunks.remainder());
        total_written += leftover;

        Poll::Ready(Ok(total_written))
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        ready!(self.as_mut().flush_buf(cx))?;
        self.project().inner.poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        self.project().inner.poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use std::assert_eq;

    use chacha20poly1305::{aead::stream::EncryptorLE31, KeyInit, XChaCha20Poly1305};
    use tokio::io::AsyncWriteExt;

    use crate::get_key;

    use super::*;

    #[tokio::test]
    pub async fn test_crypto_stream_write_half() {
        let key: [u8; 32] = get_key("key", "group");
        let start_nonce = [0u8; 20];

        let mut encryptor: EncryptorLE31<XChaCha20Poly1305> =
            chacha20poly1305::aead::stream::EncryptorLE31::from_aead(
                XChaCha20Poly1305::new(key.as_ref().into()),
                start_nonce.as_ref().into(),
            );

        let expected = {
            let mut encrypted = encryptor.encrypt_next("some content".as_bytes()).unwrap();
            let mut expected = Vec::new();
            expected.extend((encrypted.len() as u32).to_le_bytes());
            expected.append(&mut encrypted);

            expected
        };

        let mut writer = WriteHalf::new(
            tokio::io::BufWriter::new(Vec::new()),
            chacha20poly1305::aead::stream::EncryptorLE31::from_aead(
                XChaCha20Poly1305::new(key.as_ref().into()),
                start_nonce.as_ref().into(),
            ),
        );

        assert_eq!(
            writer.write(b"some content").await.unwrap(),
            "some content".bytes().len()
        );

        assert_eq!(expected, writer.inner.buffer())
    }
}
