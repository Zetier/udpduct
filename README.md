# udpduct

`udpduct` is an SSH-authenticated UDP forwarding tool with `ssh`-style `-L` and `-R` semantics.

It uses the system `ssh` client to authenticate to the remote machine and start a hidden helper there, then switches the data plane to a direct encrypted UDP tunnel. The intent is closer to "UDP port forwarding with an SSH login path" than "UDP tunneled inside SSH/TCP".

## Status

This is an early implementation. The core pieces exist:

- `ssh` bootstrap and hidden remote `agent` mode
- direct encrypted UDP tunnel with replay protection
- `-L` and `-R` forwarding rules
- per-flow UDP socket handling for request/reply traffic
- keepalives and idle flow cleanup

Current limitations:

- the remote host must already have `udpduct` installed and in `PATH`, or you must pass `--remote-path`
- the client must be able to reach the remote host over UDP after SSH bootstrap succeeds
- no roaming, resume, multicast, broadcast, fragmentation/reassembly, or source-IP spoofing
- no live smoke-test coverage against a real SSH server yet

## Installation

Build from source with Cargo:

```bash
cargo build --release
```

Install locally:

```bash
cargo install --path .
```

The same binary must be available on both the local and remote machine.

## Usage

Local forwarding, equivalent in shape to `ssh -L`:

```bash
udpduct user@example.com -L 5353:127.0.0.1:53
```

This binds UDP port `5353` locally and forwards traffic to `127.0.0.1:53` on the remote side.

Remote forwarding, equivalent in shape to `ssh -R`:

```bash
udpduct user@example.com -R 5353:127.0.0.1:53
```

This binds UDP port `5353` on the remote side and forwards traffic to `127.0.0.1:53` on the local side.

Multiple rules are allowed:

```bash
udpduct user@example.com \
  -L 5000:127.0.0.1:5000 \
  -R 6000:127.0.0.1:6000
```

Useful options:

- `-p`, `-i`, `-J`, `-o`, `-F`, `-l`: passed through to the system `ssh` client
- `-4` / `-6`: constrain address family
- `--remote-path`: remote binary path, defaults to `udpduct`
- `--udp-host`: override which hostname/IP the client uses for the UDP data-plane peer
- `--udp-port`: request a specific remote UDP tunnel port
- `--udp-port-range`: constrain remote UDP tunnel allocation
- `--keepalive`: tunnel heartbeat interval, default `15s`
- `--idle-timeout`: per-flow idle expiry, default `60s`
- `--max-dgram`: maximum forwarded datagram size, default `1200`

Show full CLI help:

```bash
udpduct --help
```

## How It Works

1. The local client parses forwarding rules and binds any local listeners needed for `-L`.
2. It starts `ssh -T <destination> 'udpduct agent --stdio'`.
3. Client and agent exchange a bootstrap message over stdio that includes the forwarding rules and a session secret.
4. The remote agent binds any remote listeners needed for `-R` plus a UDP tunnel socket.
5. The client connects to that UDP socket, performs an authenticated handshake, and then all forwarded datagrams move over the encrypted UDP tunnel.

Each observed UDP source behind a forwarding rule becomes an internal flow, so replies can be routed back to the original sender.

## Security Model

- SSH handles remote authentication and process startup.
- Tunnel traffic is encrypted with `ChaCha20-Poly1305`.
- Directional keys are derived from a per-session secret via HKDF-SHA256.
- Tunnel packets carry sequence numbers and a replay window.

This does not inherit OpenSSH's built-in TCP forwarding policy controls, because forwarding is implemented by a remote program launched after login rather than by the SSH server itself.

## Development

Run tests:

```bash
cargo test
```

Format the code:

```bash
cargo fmt
```

## License

Licensed under either of these, at your option:

- Apache License, Version 2.0, in [LICENSE-APACHE](LICENSE-APACHE)
- MIT license, in [LICENSE-MIT](LICENSE-MIT)

