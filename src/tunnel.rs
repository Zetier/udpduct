use std::sync::Mutex;

use anyhow::{Result, anyhow, bail};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::protocol::Side;

const MAGIC: [u8; 4] = *b"UDPD";
const VERSION: u8 = 1;
const HEADER_LEN: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum FrameKind {
    Hello = 1,
    HelloAck = 2,
    Open = 3,
    Data = 4,
    Close = 5,
    Keepalive = 6,
}

impl FrameKind {
    fn from_u8(value: u8) -> Result<Self> {
        Ok(match value {
            1 => Self::Hello,
            2 => Self::HelloAck,
            3 => Self::Open,
            4 => Self::Data,
            5 => Self::Close,
            6 => Self::Keepalive,
            _ => bail!("unknown frame kind {value}"),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TunnelFrame {
    pub kind: FrameKind,
    pub rule_id: u32,
    pub flow_id: u64,
    pub payload: Vec<u8>,
}

pub struct TunnelCodec {
    session_id: [u8; 16],
    send_cipher: ChaCha20Poly1305,
    recv_cipher: ChaCha20Poly1305,
    send_nonce_prefix: [u8; 4],
    recv_nonce_prefix: [u8; 4],
    send_seq: Mutex<u64>,
    replay: Mutex<ReplayWindow>,
}

impl TunnelCodec {
    pub fn new(secret: [u8; 32], session_id: [u8; 16], side: Side) -> Result<Self> {
        let send_label = match side {
            Side::Local => b"local->remote",
            Side::Remote => b"remote->local",
        };
        let recv_label = match side {
            Side::Local => b"remote->local",
            Side::Remote => b"local->remote",
        };

        let (send_key, send_nonce_prefix) = derive_material(secret, send_label)?;
        let (recv_key, recv_nonce_prefix) = derive_material(secret, recv_label)?;
        Ok(Self {
            session_id,
            send_cipher: ChaCha20Poly1305::new(Key::from_slice(&send_key)),
            recv_cipher: ChaCha20Poly1305::new(Key::from_slice(&recv_key)),
            send_nonce_prefix,
            recv_nonce_prefix,
            send_seq: Mutex::new(0),
            replay: Mutex::new(ReplayWindow::default()),
        })
    }

    pub fn seal(&self, frame: TunnelFrame) -> Result<Vec<u8>> {
        let mut seq = self.send_seq.lock().expect("send_seq poisoned");
        let packet = self.seal_with_seq(frame, *seq)?;
        *seq += 1;
        Ok(packet)
    }

    pub fn seal_with_seq(&self, frame: TunnelFrame, seq: u64) -> Result<Vec<u8>> {
        let mut header = [0u8; HEADER_LEN];
        header[..4].copy_from_slice(&MAGIC);
        header[4] = VERSION;
        header[8..24].copy_from_slice(&self.session_id);
        header[24..32].copy_from_slice(&seq.to_be_bytes());

        let plaintext = encode_frame(frame)?;
        let ciphertext = self
            .send_cipher
            .encrypt(
                Nonce::from_slice(&nonce(self.send_nonce_prefix, seq)),
                Payload {
                    msg: &plaintext,
                    aad: &header,
                },
            )
            .map_err(|_| anyhow!("failed to encrypt tunnel frame"))?;

        let mut packet = header.to_vec();
        packet.extend_from_slice(&ciphertext);
        Ok(packet)
    }

    pub fn open(&self, packet: &[u8]) -> Result<TunnelFrame> {
        if packet.len() < HEADER_LEN + 16 {
            bail!("packet too short");
        }
        if packet[..4] != MAGIC {
            bail!("invalid magic");
        }
        if packet[4] != VERSION {
            bail!("unsupported version {}", packet[4]);
        }
        if packet[8..24] != self.session_id {
            bail!("session mismatch");
        }
        let seq = u64::from_be_bytes(packet[24..32].try_into()?);
        let mut replay = self.replay.lock().expect("replay poisoned");
        if !replay.accept(seq) {
            bail!("replayed or stale packet");
        }

        let plaintext = self
            .recv_cipher
            .decrypt(
                Nonce::from_slice(&nonce(self.recv_nonce_prefix, seq)),
                Payload {
                    msg: &packet[HEADER_LEN..],
                    aad: &packet[..HEADER_LEN],
                },
            )
            .map_err(|_| anyhow!("failed to decrypt tunnel frame"))?;
        decode_frame(&plaintext)
    }
}

fn derive_material(secret: [u8; 32], label: &[u8]) -> Result<([u8; 32], [u8; 4])> {
    let hkdf = Hkdf::<Sha256>::new(None, &secret);
    let mut key = [0u8; 32];
    let mut nonce_prefix = [0u8; 4];
    hkdf.expand(&[b"udpduct key ", label].concat(), &mut key)
        .map_err(|_| anyhow!("failed to derive tunnel key"))?;
    hkdf.expand(&[b"udpduct nonce ", label].concat(), &mut nonce_prefix)
        .map_err(|_| anyhow!("failed to derive tunnel nonce"))?;
    Ok((key, nonce_prefix))
}

fn encode_frame(frame: TunnelFrame) -> Result<Vec<u8>> {
    if frame.payload.len() > u16::MAX as usize {
        bail!("payload too large");
    }
    let mut bytes = Vec::with_capacity(1 + 4 + 8 + 2 + frame.payload.len());
    bytes.push(frame.kind as u8);
    bytes.extend_from_slice(&frame.rule_id.to_be_bytes());
    bytes.extend_from_slice(&frame.flow_id.to_be_bytes());
    bytes.extend_from_slice(&(frame.payload.len() as u16).to_be_bytes());
    bytes.extend_from_slice(&frame.payload);
    Ok(bytes)
}

fn decode_frame(bytes: &[u8]) -> Result<TunnelFrame> {
    if bytes.len() < 15 {
        bail!("frame too short");
    }
    let kind = FrameKind::from_u8(bytes[0])?;
    let rule_id = u32::from_be_bytes(bytes[1..5].try_into()?);
    let flow_id = u64::from_be_bytes(bytes[5..13].try_into()?);
    let len = u16::from_be_bytes(bytes[13..15].try_into()?) as usize;
    if bytes.len() != 15 + len {
        bail!("frame payload length mismatch");
    }
    Ok(TunnelFrame {
        kind,
        rule_id,
        flow_id,
        payload: bytes[15..].to_vec(),
    })
}

fn nonce(prefix: [u8; 4], seq: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..4].copy_from_slice(&prefix);
    nonce[4..].copy_from_slice(&seq.to_be_bytes());
    nonce
}

#[derive(Default)]
struct ReplayWindow {
    max_seq: Option<u64>,
    bitmap: u64,
}

impl ReplayWindow {
    fn accept(&mut self, seq: u64) -> bool {
        match self.max_seq {
            None => {
                self.max_seq = Some(seq);
                self.bitmap = 1;
                true
            }
            Some(max_seq) if seq > max_seq => {
                let shift = (seq - max_seq).min(64) as u32;
                self.bitmap = if shift >= 64 {
                    1
                } else {
                    (self.bitmap << shift) | 1
                };
                self.max_seq = Some(seq);
                true
            }
            Some(max_seq) => {
                let delta = max_seq - seq;
                if delta >= 64 {
                    return false;
                }
                let mask = 1u64 << delta;
                if self.bitmap & mask != 0 {
                    return false;
                }
                self.bitmap |= mask;
                true
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{FrameKind, TunnelCodec, TunnelFrame};
    use crate::protocol::Side;

    #[test]
    fn round_trip_frame() {
        let secret = [7u8; 32];
        let session = [9u8; 16];
        let sender = TunnelCodec::new(secret, session, Side::Local).unwrap();
        let receiver = TunnelCodec::new(secret, session, Side::Remote).unwrap();
        let packet = sender
            .seal(TunnelFrame {
                kind: FrameKind::Data,
                rule_id: 3,
                flow_id: 99,
                payload: b"hello".to_vec(),
            })
            .unwrap();
        let decoded = receiver.open(&packet).unwrap();
        assert_eq!(decoded.kind, FrameKind::Data);
        assert_eq!(decoded.rule_id, 3);
        assert_eq!(decoded.flow_id, 99);
        assert_eq!(decoded.payload, b"hello");
    }

    #[test]
    fn rejects_replay() {
        let secret = [3u8; 32];
        let session = [1u8; 16];
        let sender = TunnelCodec::new(secret, session, Side::Local).unwrap();
        let receiver = TunnelCodec::new(secret, session, Side::Remote).unwrap();
        let packet = sender
            .seal_with_seq(
                TunnelFrame {
                    kind: FrameKind::Keepalive,
                    rule_id: 0,
                    flow_id: 0,
                    payload: Vec::new(),
                },
                42,
            )
            .unwrap();
        assert!(receiver.open(&packet).is_ok());
        assert!(receiver.open(&packet).is_err());
    }
}
