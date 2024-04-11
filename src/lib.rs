#![doc = include_str!("../README.md")]
use std::ops::Sub;

use chacha20poly1305::aead::{
    generic_array::{ArrayLength, GenericArray},
    stream::{Decryptor, Encryptor, NewStream, NonceSize, StreamPrimitive},
};

use tokio::io::{AsyncRead, AsyncWrite};

mod read_half;
pub use read_half::ReadHalf;

mod write_half;
pub use write_half::WriteHalf;

pub const DEFAULT_BUFFER_SIZE: usize = 4096;
pub const DEFAULT_CHUNK_SIZE: usize = 1024;

/// Creates a pair of [ReadHalf] and [WriteHalf] with default buffer size of
/// [self::DEFAULT_BUFFER_SIZE] and chunk size of [self::DEFAULT_CHUNK_SIZE]  
///
/// ```rust
/// use chacha20poly1305::aead::stream::{DecryptorLE31, EncryptorLE31};
/// use chacha20poly1305::XChaCha20Poly1305;
///
/// use async_encrypted_stream::{ReadHalf, WriteHalf, encrypted_stream};
///
/// let key = [0u8; 32];
/// let nonce = [0u8; 20];
///
/// let (rx, tx) = tokio::io::duplex(4096);
/// let (mut reader, mut writer): (
///     ReadHalf<_, DecryptorLE31<XChaCha20Poly1305>>,
///     WriteHalf<_, EncryptorLE31<XChaCha20Poly1305>>,
/// ) = encrypted_stream(rx, tx, key.as_ref().into(), nonce.as_ref().into());
/// ````
pub fn encrypted_stream<R: AsyncRead, W: AsyncWrite, A, S>(
    read: R,
    write: W,
    key: &GenericArray<u8, A::KeySize>,
    nonce: &GenericArray<u8, NonceSize<A, S>>,
) -> (ReadHalf<R, Decryptor<A, S>>, WriteHalf<W, Encryptor<A, S>>)
where
    S: StreamPrimitive<A> + NewStream<A>,
    A: chacha20poly1305::AeadInPlace + chacha20poly1305::KeyInit,
    A::NonceSize: Sub<<S as StreamPrimitive<A>>::NonceOverhead>,
    NonceSize<A, S>: ArrayLength<u8>,
{
    encrypted_stream_with_capacity(
        read,
        write,
        key,
        nonce,
        DEFAULT_BUFFER_SIZE,
        DEFAULT_CHUNK_SIZE,
    )
}

/// Creates a pair of [ReadHalf] and [WriteHalf] with default buffer size of
/// `buffer_size` and chunk size of `chunk_size`  
///
/// ```rust
/// use chacha20poly1305::aead::stream::{DecryptorLE31, EncryptorLE31};
/// use chacha20poly1305::XChaCha20Poly1305;
///
/// use async_encrypted_stream::{ReadHalf, WriteHalf, encrypted_stream_with_capacity};
///
/// let key = [0u8; 32];
/// let nonce = [0u8; 20];
///
/// let (rx, tx) = tokio::io::duplex(4096);
/// let (mut reader, mut writer): (
///     ReadHalf<_, DecryptorLE31<XChaCha20Poly1305>>,
///     WriteHalf<_, EncryptorLE31<XChaCha20Poly1305>>,
/// ) = encrypted_stream_with_capacity(rx, tx, key.as_ref().into(), nonce.as_ref().into(), 4096,
/// 512);
/// ````
pub fn encrypted_stream_with_capacity<R: AsyncRead, W: AsyncWrite, A, S>(
    read: R,
    write: W,
    key: &GenericArray<u8, A::KeySize>,
    nonce: &GenericArray<u8, NonceSize<A, S>>,
    buffer_size: usize,
    chunk_size: usize,
) -> (ReadHalf<R, Decryptor<A, S>>, WriteHalf<W, Encryptor<A, S>>)
where
    S: StreamPrimitive<A> + NewStream<A>,
    A: chacha20poly1305::AeadInPlace + chacha20poly1305::KeyInit,
    A::NonceSize: Sub<<S as StreamPrimitive<A>>::NonceOverhead>,
    NonceSize<A, S>: ArrayLength<u8>,
{
    let encryptor = Encryptor::new(key, nonce);
    let decryptor = Decryptor::new(key, nonce);

    (
        ReadHalf::with_capacity(read, decryptor, buffer_size, chunk_size),
        WriteHalf::with_capacity(write, encryptor, buffer_size, chunk_size),
    )
}

pub fn encrypt_write_stream_with_capacity<R: AsyncRead, W: AsyncWrite, A, S>(
    write: W,
    read: R,
    key: &GenericArray<u8, A::KeySize>,
    nonce: &GenericArray<u8, NonceSize<A, S>>,
    buffer_size: usize,
    chunk_size: usize,
) -> (WriteHalf<W, Encryptor<A, S>>, R)
where
    S: StreamPrimitive<A> + NewStream<A>,
    A: chacha20poly1305::AeadInPlace + chacha20poly1305::KeyInit,
    A::NonceSize: Sub<<S as StreamPrimitive<A>>::NonceOverhead>,
    NonceSize<A, S>: ArrayLength<u8>,
{
    let encryptor = Encryptor::new(key, nonce);
    (
        WriteHalf::with_capacity(write, encryptor, buffer_size, chunk_size),
        read,
    )
}

pub fn encrypt_read_stream_with_capacity<R: AsyncRead, W: AsyncWrite, A, S>(
    write: W,
    read: R,
    key: &GenericArray<u8, A::KeySize>,
    nonce: &GenericArray<u8, NonceSize<A, S>>,
    buffer_size: usize,
) -> (W, ReadHalf<R, Decryptor<A, S>>)
where
    S: StreamPrimitive<A> + NewStream<A>,
    A: chacha20poly1305::AeadInPlace + chacha20poly1305::KeyInit,
    A::NonceSize: Sub<<S as StreamPrimitive<A>>::NonceOverhead>,
    NonceSize<A, S>: ArrayLength<u8>,
{
    let decryptor = Decryptor::new(key, nonce);
    (
        write,
        ReadHalf::with_capacity(read, decryptor, buffer_size, DEFAULT_CHUNK_SIZE),
    )
}

#[cfg(test)]
fn get_key<const S: usize>(plain_key: &str, salt: &str) -> [u8; S] {
    const ITERATIONS: u32 = 4096;
    pbkdf2::pbkdf2_hmac_array::<sha2::Sha256, S>(plain_key.as_bytes(), salt.as_bytes(), ITERATIONS)
}

#[cfg(test)]
mod tests {
    use std::{assert_eq, fmt::write, time::Duration};

    use chacha20poly1305::{
        aead::stream::{DecryptorLE31, EncryptorLE31},
        XChaCha20Poly1305,
    };
    use futures::stream::StreamExt;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    const MB: usize = 1024 * 1024;
    #[tokio::test]
    pub async fn test_big_transfer() {
        let key: [u8; 32] = get_key("key", "group");
        let nonce = [0u8; 20];
        let content = vec![100u8; 4 * MB];
        let (rx, tx) = tokio::io::duplex(4096);
        let (mut reader, mut writer): (
            ReadHalf<_, DecryptorLE31<XChaCha20Poly1305>>,
            WriteHalf<_, EncryptorLE31<XChaCha20Poly1305>>,
        ) = super::encrypted_stream(rx, tx, key.as_ref().into(), nonce.as_ref().into());
        let read_task = tokio::spawn(async move {
            let mut total_read = 0;
            let mut read_buf = vec![0u8; 512];
            while let Ok(bytes_read) = reader.read(&mut read_buf).await {
                if bytes_read == 0 {
                    break;
                }
                assert!(read_buf.iter().all(|b| *b == 100));
                total_read += bytes_read;
            }
            total_read
        });

        let write_task = {
            let content = content.clone();
            tokio::spawn(async move {
                let _ = writer.write_all(&content).await;
                writer.shutdown().await;
            })
        };
        let total_read = read_task.await.unwrap();
        write_task.await.unwrap();
        assert_eq!(total_read, content.len());
    }
}
