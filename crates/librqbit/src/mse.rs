use std::{
    io::IoSliceMut,
    pin::Pin,
    task::{Context, Poll},
};

use num_bigint::BigUint;
use sha1w::{ISha1, Sha1};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::vectored_traits::AsyncReadVectored;
use librqbit_core::hash_id::Id20;

const PRIME: [u8; 96] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
    0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1, 0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
    0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
    0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
    0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45, 0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
    0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x3A, 0x36, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x05, 0x63,
];
const DH_LEN: usize = 96;
const MAX_PAD: usize = 512;
const CRYPTO_RC4: u32 = 2;
const DISCARD: usize = 1024;

#[derive(Clone)]
pub(crate) struct Rc4 {
    s: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4 {
    fn new(key: &[u8]) -> Self {
        let mut s = [0u8; 256];
        for (i, v) in s.iter_mut().enumerate() {
            *v = i as u8;
        }
        let mut j = 0u8;
        for i in 0..256 {
            j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
            s.swap(i, j as usize);
        }
        let mut rc4 = Self { s, i: 0, j: 0 };
        let mut skip = [0u8; DISCARD];
        rc4.apply(&mut skip);
        rc4
    }

    fn apply(&mut self, buf: &mut [u8]) {
        for byte in buf {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.s[self.i as usize]);
            self.s.swap(self.i as usize, self.j as usize);
            let k = self.s[(self.s[self.i as usize].wrapping_add(self.s[self.j as usize])) as usize];
            *byte ^= k;
        }
    }
}

fn sha1(parts: &[&[u8]]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finish()
}

fn padded(value: &BigUint) -> [u8; DH_LEN] {
    let bytes = value.to_bytes_be();
    let mut out = [0u8; DH_LEN];
    out[DH_LEN - bytes.len()..].copy_from_slice(&bytes);
    out
}

fn protocol_error(message: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message)
}

pub(crate) async fn initiate<R, W>(
    read: &mut R,
    write: &mut W,
    info_hash: Id20,
    initial_payload: &[u8],
) -> std::io::Result<(Rc4, Rc4)>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    use rand::RngExt;
    let prime = BigUint::from_bytes_be(&PRIME);
    let mut private = [0u8; 20];
    rand::fill(&mut private[..]);
    let public = padded(&BigUint::from(2u8).modpow(&BigUint::from_bytes_be(&private), &prime));
    let pad_len = rand::rng().random_range(0..=MAX_PAD / 4);
    let mut hello = Vec::with_capacity(DH_LEN + pad_len);
    hello.extend_from_slice(&public);
    hello.resize(DH_LEN + pad_len, 0);
    rand::fill(&mut hello[DH_LEN..]);
    write.write_all(&hello).await?;
    write.flush().await?;

    let mut theirs = [0u8; DH_LEN];
    read.read_exact(&mut theirs).await?;
    let secret = padded(&BigUint::from_bytes_be(&theirs).modpow(&BigUint::from_bytes_be(&private), &prime));

    let skey = info_hash.0;
    let mut enc = Rc4::new(&sha1(&[b"keyA", &secret, &skey]));
    let mut dec = Rc4::new(&sha1(&[b"keyB", &secret, &skey]));

    let req2 = sha1(&[b"req2", &skey]);
    let req3 = sha1(&[b"req3", &secret]);
    let mut reply = Vec::with_capacity(64 + initial_payload.len());
    reply.extend_from_slice(&sha1(&[b"req1", &secret]));
    reply.extend(req2.iter().zip(req3.iter()).map(|(a, b)| a ^ b));
    let mut sealed = Vec::with_capacity(16 + initial_payload.len());
    sealed.extend_from_slice(&[0u8; 8]);
    sealed.extend_from_slice(&CRYPTO_RC4.to_be_bytes());
    sealed.extend_from_slice(&0u16.to_be_bytes());
    sealed.extend_from_slice(&(initial_payload.len() as u16).to_be_bytes());
    sealed.extend_from_slice(initial_payload);
    enc.apply(&mut sealed);
    reply.extend_from_slice(&sealed);
    write.write_all(&reply).await?;
    write.flush().await?;

    let mut marker = [0u8; 8];
    dec.clone().apply(&mut marker);
    let mut window = [0u8; 8];
    let mut seen = 0usize;
    loop {
        if seen > MAX_PAD + 8 {
            return Err(protocol_error("encryption handshake marker not found"));
        }
        let mut byte = [0u8; 1];
        read.read_exact(&mut byte).await?;
        window.rotate_left(1);
        window[7] = byte[0];
        seen += 1;
        if seen >= 8 && window == marker {
            break;
        }
    }
    dec.apply(&mut window);

    let mut head = [0u8; 6];
    read.read_exact(&mut head).await?;
    dec.apply(&mut head);
    let select = u32::from_be_bytes([head[0], head[1], head[2], head[3]]);
    if select & CRYPTO_RC4 == 0 {
        return Err(protocol_error("peer selected an unsupported crypto method"));
    }
    let pad_d = u16::from_be_bytes([head[4], head[5]]) as usize;
    if pad_d > MAX_PAD {
        return Err(protocol_error("encryption handshake padding too long"));
    }
    let mut pad = vec![0u8; pad_d];
    read.read_exact(&mut pad).await?;
    dec.apply(&mut pad);
    Ok((dec, enc))
}

pub(crate) struct Rc4Reader<T> {
    inner: T,
    rc4: Rc4,
}

impl<T> Rc4Reader<T> {
    pub(crate) fn new(inner: T, rc4: Rc4) -> Self {
        Self { inner, rc4 }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for Rc4Reader<T> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        std::task::ready!(Pin::new(&mut this.inner).poll_read(cx, buf)?);
        this.rc4.apply(&mut buf.filled_mut()[before..]);
        Poll::Ready(Ok(()))
    }
}

impl<T: AsyncReadVectored> AsyncReadVectored for Rc4Reader<T> {
    fn poll_read_vectored(self: Pin<&mut Self>, cx: &mut Context<'_>, vec: &mut [IoSliceMut<'_>]) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let n = std::task::ready!(Pin::new(&mut this.inner).poll_read_vectored(cx, vec)?);
        let mut left = n;
        for slice in vec.iter_mut() {
            if left == 0 {
                break;
            }
            let take = left.min(slice.len());
            this.rc4.apply(&mut slice[..take]);
            left -= take;
        }
        Poll::Ready(Ok(n))
    }
}

pub(crate) struct Rc4Writer<T> {
    inner: T,
    rc4: Rc4,
    pending: Vec<u8>,
    sent: usize,
}

impl<T> Rc4Writer<T> {
    pub(crate) fn new(inner: T, rc4: Rc4) -> Self {
        Self { inner, rc4, pending: Vec::new(), sent: 0 }
    }
}

impl<T: AsyncWrite + Unpin> Rc4Writer<T> {
    fn drain(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        while self.sent < self.pending.len() {
            let n = std::task::ready!(Pin::new(&mut self.inner).poll_write(cx, &self.pending[self.sent..])?);
            if n == 0 {
                return Poll::Ready(Err(std::io::ErrorKind::WriteZero.into()));
            }
            self.sent += n;
        }
        self.pending.clear();
        self.sent = 0;
        Poll::Ready(Ok(()))
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Rc4Writer<T> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        std::task::ready!(this.drain(cx)?);
        this.pending.extend_from_slice(buf);
        let start = this.pending.len() - buf.len();
        this.rc4.apply(&mut this.pending[start..]);
        let _ = this.drain(cx);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        std::task::ready!(this.drain(cx)?);
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        std::task::ready!(this.drain(cx)?);
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}
