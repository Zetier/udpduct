use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Serialize};

use crate::spec::{BoundListener, ForwardSpec};

pub const PROTOCOL_VERSION: u16 = 1;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BootstrapRequest {
    pub version: u16,
    pub session_id: [u8; 16],
    pub secret_b64: String,
    pub forwards: Vec<ForwardSpec>,
    pub udp_bind_port: Option<u16>,
    pub udp_port_range: Option<(u16, u16)>,
    pub keepalive_secs: u64,
    pub idle_timeout_secs: u64,
    pub max_dgram: usize,
    pub family: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BootstrapReply {
    pub version: u16,
    pub udp_port: u16,
    pub remote_udp_bind: SocketAddr,
    pub bound_listeners: Vec<BoundListener>,
    pub capabilities: Vec<String>,
    pub error: Option<String>,
}

impl BootstrapRequest {
    pub fn secret_bytes(&self) -> Result<[u8; 32]> {
        let bytes = BASE64
            .decode(self.secret_b64.as_bytes())
            .context("invalid base64 session secret")?;
        bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid session secret length"))
    }

    pub fn keepalive(&self) -> Duration {
        Duration::from_secs(self.keepalive_secs)
    }

    pub fn idle_timeout(&self) -> Duration {
        Duration::from_secs(self.idle_timeout_secs)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Side {
    Local,
    Remote,
}

impl Side {
    pub fn flow_prefix(self) -> u64 {
        match self {
            Self::Local => 0,
            Self::Remote => 1u64 << 63,
        }
    }
}

pub fn encode_line<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut payload = serde_json::to_vec(value)?;
    payload.push(b'\n');
    Ok(payload)
}

pub fn decode_line<T: for<'de> Deserialize<'de>>(line: &[u8]) -> Result<T> {
    Ok(serde_json::from_slice(line)?)
}

#[cfg(test)]
mod tests {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as BASE64;

    use super::{
        BootstrapReply, BootstrapRequest, PROTOCOL_VERSION, Side, decode_line, encode_line,
    };
    use crate::spec::{BoundListener, ForwardSpec, ListenSide};

    fn sample_request(secret_b64: String) -> BootstrapRequest {
        BootstrapRequest {
            version: PROTOCOL_VERSION,
            session_id: [7u8; 16],
            secret_b64,
            forwards: vec![ForwardSpec {
                rule_id: 1,
                listen_side: ListenSide::Local,
                bind_host: None,
                listen_port: 4000,
                target_host: "127.0.0.1".to_string(),
                target_port: 53,
            }],
            udp_bind_port: Some(6000),
            udp_port_range: Some((6000, 6010)),
            keepalive_secs: 15,
            idle_timeout_secs: 60,
            max_dgram: 1200,
            family: Some("ipv4".to_string()),
        }
    }

    #[test]
    fn decodes_secret_bytes() {
        let request = sample_request(BASE64.encode([9u8; 32]));
        assert_eq!(request.secret_bytes().unwrap(), [9u8; 32]);
        assert_eq!(request.keepalive().as_secs(), 15);
        assert_eq!(request.idle_timeout().as_secs(), 60);
    }

    #[test]
    fn rejects_bad_secret_payloads() {
        let invalid_b64 = sample_request("%%%".to_string());
        assert!(invalid_b64.secret_bytes().is_err());

        let invalid_len = sample_request(BASE64.encode([1u8; 31]));
        assert!(invalid_len.secret_bytes().is_err());
    }

    #[test]
    fn round_trips_json_lines() {
        let reply = BootstrapReply {
            version: PROTOCOL_VERSION,
            udp_port: 6001,
            remote_udp_bind: "127.0.0.1:6001".parse().unwrap(),
            bound_listeners: vec![BoundListener {
                rule_id: 1,
                listen_side: ListenSide::Remote,
                requested: "0:127.0.0.1:53".to_string(),
                bound: "127.0.0.1:53000".parse().unwrap(),
            }],
            capabilities: vec!["fixed-session".to_string()],
            error: None,
        };

        let encoded = encode_line(&reply).unwrap();
        assert_eq!(encoded.last(), Some(&b'\n'));
        let decoded: BootstrapReply = decode_line(&encoded).unwrap();
        assert_eq!(decoded.udp_port, 6001);
        assert_eq!(decoded.bound_listeners.len(), 1);
    }

    #[test]
    fn side_prefixes_split_local_and_remote_flows() {
        assert_eq!(Side::Local.flow_prefix(), 0);
        assert_eq!(Side::Remote.flow_prefix(), 1u64 << 63);
    }
}
