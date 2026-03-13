use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use tokio::net::lookup_host;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ListenSide {
    Local,
    Remote,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IpFamily {
    V4,
    V6,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ForwardSpec {
    pub rule_id: u32,
    pub listen_side: ListenSide,
    pub bind_host: Option<String>,
    pub listen_port: u16,
    pub target_host: String,
    pub target_port: u16,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BoundListener {
    pub rule_id: u32,
    pub listen_side: ListenSide,
    pub requested: String,
    pub bound: SocketAddr,
}

impl ForwardSpec {
    pub fn display(&self) -> String {
        let bind = self
            .bind_host
            .as_deref()
            .map(bracket_if_ipv6)
            .map(|host| format!("{host}:"))
            .unwrap_or_default();
        format!(
            "{bind}{}:{}:{}",
            self.listen_port,
            bracket_if_ipv6(&self.target_host),
            self.target_port
        )
    }

    pub fn requested(&self) -> String {
        self.display()
    }
}

pub fn bracket_if_ipv6(value: &str) -> String {
    if value.contains(':') && !value.starts_with('[') && !value.ends_with(']') {
        format!("[{value}]")
    } else {
        value.to_string()
    }
}

pub fn parse_forward_spec(
    input: &str,
    listen_side: ListenSide,
    rule_id: u32,
) -> Result<ForwardSpec> {
    let mut parts = split_spec(input)?;
    if parts.len() == 3 {
        parts.insert(0, String::new());
    }
    if parts.len() != 4 {
        bail!("invalid forwarding spec `{input}`");
    }

    let bind_host = if parts[0].is_empty() {
        None
    } else {
        Some(unbracket(&parts[0]).to_string())
    };
    let listen_port = parse_port(&parts[1]).context("invalid listen port")?;
    let target_host = unbracket(&parts[2]).to_string();
    if target_host.is_empty() {
        bail!("missing target host in `{input}`");
    }
    let target_port = parse_port(&parts[3]).context("invalid target port")?;

    Ok(ForwardSpec {
        rule_id,
        listen_side,
        bind_host,
        listen_port,
        target_host,
        target_port,
    })
}

fn parse_port(value: &str) -> Result<u16> {
    value
        .parse::<u16>()
        .map_err(|_| anyhow!("invalid port `{value}`"))
}

fn split_spec(input: &str) -> Result<Vec<String>> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut bracket_depth = 0usize;

    for ch in input.chars() {
        match ch {
            '[' => {
                bracket_depth += 1;
                current.push(ch);
            }
            ']' => {
                if bracket_depth == 0 {
                    bail!("unmatched `]` in `{input}`");
                }
                bracket_depth -= 1;
                current.push(ch);
            }
            ':' if bracket_depth == 0 => {
                parts.push(current);
                current = String::new();
            }
            _ => current.push(ch),
        }
    }

    if bracket_depth != 0 {
        bail!("unmatched `[` in `{input}`");
    }

    parts.push(current);
    Ok(parts)
}

fn unbracket(value: &str) -> &str {
    value
        .strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
        .unwrap_or(value)
}

pub async fn resolve_bind_addr(
    bind_host: Option<&str>,
    port: u16,
    family: Option<IpFamily>,
) -> Result<SocketAddr> {
    if let Some(host) = bind_host {
        resolve_single(host, port, family).await
    } else {
        Ok(default_loopback(port, family))
    }
}

pub async fn resolve_target_addr(
    host: &str,
    port: u16,
    family: Option<IpFamily>,
) -> Result<SocketAddr> {
    resolve_single(host, port, family).await
}

pub async fn resolve_udp_peer(
    host: &str,
    port: u16,
    family: Option<IpFamily>,
) -> Result<SocketAddr> {
    resolve_single(host, port, family).await
}

fn default_loopback(port: u16, family: Option<IpFamily>) -> SocketAddr {
    match family {
        Some(IpFamily::V6) => SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port),
        _ => SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
    }
}

pub fn wildcard_addr(port: u16, family: Option<IpFamily>) -> SocketAddr {
    match family {
        Some(IpFamily::V6) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port),
        _ => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port),
    }
}

async fn resolve_single(host: &str, port: u16, family: Option<IpFamily>) -> Result<SocketAddr> {
    let mut candidates = lookup_host((host, port))
        .await
        .with_context(|| format!("failed to resolve `{host}:{port}`"))?;
    candidates
        .find(|addr| matches_family(*addr, family))
        .ok_or_else(|| anyhow!("no address found for `{host}:{port}` matching requested family"))
}

fn matches_family(addr: SocketAddr, family: Option<IpFamily>) -> bool {
    match family {
        Some(IpFamily::V4) => addr.is_ipv4(),
        Some(IpFamily::V6) => addr.is_ipv6(),
        None => true,
    }
}

impl fmt::Display for ListenSide {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Local => f.write_str("local"),
            Self::Remote => f.write_str("remote"),
        }
    }
}

impl FromStr for IpFamily {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "4" | "ipv4" => Ok(Self::V4),
            "6" | "ipv6" => Ok(Self::V6),
            _ => bail!("invalid family `{s}`"),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::{
        ForwardSpec, IpFamily, ListenSide, bracket_if_ipv6, parse_forward_spec, resolve_bind_addr,
        resolve_target_addr, wildcard_addr,
    };

    #[test]
    fn parses_three_part_forward() {
        let spec = parse_forward_spec("5000:example.com:53", ListenSide::Local, 7).unwrap();
        assert_eq!(
            spec,
            ForwardSpec {
                rule_id: 7,
                listen_side: ListenSide::Local,
                bind_host: None,
                listen_port: 5000,
                target_host: "example.com".to_string(),
                target_port: 53,
            }
        );
    }

    #[test]
    fn parses_four_part_forward_with_ipv6() {
        let spec = parse_forward_spec("[::1]:0:[2001:db8::1]:5353", ListenSide::Remote, 9).unwrap();
        assert_eq!(spec.bind_host.as_deref(), Some("::1"));
        assert_eq!(spec.listen_port, 0);
        assert_eq!(spec.target_host, "2001:db8::1");
        assert_eq!(spec.target_port, 5353);
    }

    #[test]
    fn rejects_bad_brackets() {
        assert!(parse_forward_spec("[::1:53:target:80", ListenSide::Local, 1).is_err());
    }

    #[test]
    fn brackets_ipv6_addresses_for_display() {
        assert_eq!(bracket_if_ipv6("2001:db8::1"), "[2001:db8::1]");
        assert_eq!(bracket_if_ipv6("127.0.0.1"), "127.0.0.1");
    }

    #[tokio::test]
    async fn resolves_default_bind_loopback_by_family() {
        let v4 = resolve_bind_addr(None, 8080, Some(IpFamily::V4))
            .await
            .unwrap();
        let v6 = resolve_bind_addr(None, 8080, Some(IpFamily::V6))
            .await
            .unwrap();
        assert_eq!(v4.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(v6.ip(), IpAddr::V6(Ipv6Addr::LOCALHOST));
    }

    #[tokio::test]
    async fn resolves_localhost_targets() {
        let addr = resolve_target_addr("localhost", 8080, None).await.unwrap();
        assert_eq!(addr.port(), 8080);
    }

    #[test]
    fn wildcard_address_matches_family() {
        assert_eq!(
            wildcard_addr(9000, Some(IpFamily::V4)).ip(),
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        );
        assert_eq!(
            wildcard_addr(9000, Some(IpFamily::V6)).ip(),
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        );
    }
}
