use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use rand::Rng;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};
use tracing::{info, warn};

use crate::cli::{ClientArgs, GlobalOptions};
use crate::protocol::{BootstrapReply, BootstrapRequest, PROTOCOL_VERSION, Side, encode_line};
use crate::spec::{
    BoundListener, ForwardSpec, IpFamily, ListenSide, resolve_bind_addr, resolve_target_addr,
    resolve_udp_peer, wildcard_addr,
};
use crate::ssh::RemoteAgentProcess;
use crate::tunnel::{FrameKind, TunnelCodec, TunnelFrame};

pub async fn run_client(args: ClientArgs, global: GlobalOptions) -> Result<()> {
    let args = args.parse(global)?;
    let session_id: [u8; 16] = rand::random();
    let secret: [u8; 32] = rand::random();

    let (local_rules, local_bound) =
        bind_ingress_rules(&args.forwards, ListenSide::Local, args.family).await?;
    let request = BootstrapRequest {
        version: PROTOCOL_VERSION,
        session_id,
        secret_b64: BASE64.encode(secret),
        forwards: args.forwards.clone(),
        udp_bind_port: args.udp_port,
        udp_port_range: args.udp_port_range,
        keepalive_secs: args.keepalive.as_secs(),
        idle_timeout_secs: args.idle_timeout.as_secs(),
        max_dgram: args.max_dgram,
        family: args.family.map(family_name),
    };

    let (agent, reply) = RemoteAgentProcess::start(&args.ssh, &args.remote_path, &request).await?;
    validate_reply(&reply)?;
    let remote_udp_host = args
        .udp_host
        .clone()
        .unwrap_or_else(|| extract_host(&args.ssh.destination));
    let remote_udp_addr = resolve_udp_peer(&remote_udp_host, reply.udp_port, args.family)
        .await
        .with_context(|| format!("failed to resolve UDP peer `{remote_udp_host}`"))?;

    let tunnel_socket = Arc::new(
        UdpSocket::bind(wildcard_addr(
            0,
            family_for_addr(args.family, remote_udp_addr),
        ))
        .await?,
    );
    tunnel_socket.connect(remote_udp_addr).await?;
    let codec = Arc::new(TunnelCodec::new(secret, session_id, Side::Local)?);

    perform_local_handshake(
        tunnel_socket.clone(),
        codec.clone(),
        args.keepalive,
        args.max_dgram,
    )
    .await?;
    print_bindings(&local_bound, &reply.bound_listeners);

    let monitor = tokio::spawn(async move { agent.wait().await });
    run_forwarding(
        Side::Local,
        tunnel_socket,
        codec,
        args.forwards,
        local_rules,
        RuntimeConfig {
            family: args.family,
            keepalive: args.keepalive,
            idle_timeout: args.idle_timeout,
            max_dgram: args.max_dgram,
        },
        Some(monitor),
    )
    .await
}

pub async fn run_agent_stdio() -> Result<()> {
    let stdin = tokio::io::stdin();
    let mut reader = BufReader::new(stdin);
    let mut line = String::new();
    let count = reader.read_line(&mut line).await?;
    if count == 0 {
        bail!("expected bootstrap request on stdin");
    }
    let request: BootstrapRequest =
        serde_json::from_str(&line).context("failed to parse bootstrap request")?;
    if request.version != PROTOCOL_VERSION {
        bail!(
            "unsupported protocol version {}, expected {}",
            request.version,
            PROTOCOL_VERSION
        );
    }
    let secret = request.secret_bytes()?;
    let family = parse_family(request.family.as_deref())?;
    let keepalive = request.keepalive();
    let idle_timeout = request.idle_timeout();
    let forwards = request.forwards.clone();
    let (remote_rules, bound_listeners) =
        bind_ingress_rules(&forwards, ListenSide::Remote, family).await?;
    let tunnel_socket =
        Arc::new(bind_tunnel_socket(family, request.udp_bind_port, request.udp_port_range).await?);
    let local_addr = tunnel_socket.local_addr()?;
    let reply = BootstrapReply {
        version: PROTOCOL_VERSION,
        udp_port: local_addr.port(),
        remote_udp_bind: local_addr,
        bound_listeners,
        capabilities: vec!["fixed-session".to_string()],
        error: None,
    };
    let mut stdout = tokio::io::stdout();
    stdout.write_all(&encode_line(&reply)?).await?;
    stdout.flush().await?;

    let codec = Arc::new(TunnelCodec::new(secret, request.session_id, Side::Remote)?);
    accept_remote_handshake(
        tunnel_socket.clone(),
        codec.clone(),
        keepalive,
        request.max_dgram,
    )
    .await?;

    run_forwarding(
        Side::Remote,
        tunnel_socket,
        codec,
        forwards,
        remote_rules,
        RuntimeConfig {
            family,
            keepalive,
            idle_timeout,
            max_dgram: request.max_dgram,
        },
        None,
    )
    .await
}

#[derive(Clone, Copy)]
struct RuntimeConfig {
    family: Option<IpFamily>,
    keepalive: Duration,
    idle_timeout: Duration,
    max_dgram: usize,
}

struct IngressRule {
    spec: ForwardSpec,
    socket: Arc<UdpSocket>,
    state: Arc<Mutex<IngressState>>,
}

#[derive(Default)]
struct IngressState {
    by_client: HashMap<SocketAddr, IngressFlow>,
    by_flow: HashMap<u64, SocketAddr>,
}

struct IngressFlow {
    flow_id: u64,
    last_activity: Instant,
}

struct EgressManager {
    specs: HashMap<u32, ForwardSpec>,
    family: Option<IpFamily>,
    max_dgram: usize,
    outbound: mpsc::Sender<TunnelFrame>,
    flows: Arc<Mutex<HashMap<u64, EgressFlow>>>,
}

struct EgressFlow {
    socket: Arc<UdpSocket>,
    close_tx: oneshot::Sender<()>,
    last_activity: Arc<Mutex<Instant>>,
}

struct ReceiverContext {
    side: Side,
    last_received: Arc<Mutex<Instant>>,
    max_dgram: usize,
    shutdown_rx: watch::Receiver<bool>,
    error_tx: mpsc::UnboundedSender<String>,
}

async fn run_forwarding(
    side: Side,
    tunnel_socket: Arc<UdpSocket>,
    codec: Arc<TunnelCodec>,
    forwards: Vec<ForwardSpec>,
    ingress_rules: Vec<Arc<IngressRule>>,
    config: RuntimeConfig,
    external_monitor: Option<JoinHandle<Result<()>>>,
) -> Result<()> {
    let (outbound_tx, outbound_rx) = mpsc::channel::<TunnelFrame>(512);
    let (error_tx, mut error_rx) = mpsc::unbounded_channel::<String>();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let last_received = Arc::new(Mutex::new(Instant::now()));
    let next_flow = Arc::new(AtomicU64::new(1));
    let ingress_index = Arc::new(index_ingress_rules(ingress_rules));

    let egress_manager = Arc::new(EgressManager::new(
        &forwards,
        opposite_listen_side(side),
        config.family,
        config.max_dgram,
        outbound_tx.clone(),
    ));

    let mut tasks = Vec::<JoinHandle<()>>::new();
    tasks.push(spawn_sender(
        tunnel_socket.clone(),
        codec.clone(),
        outbound_rx,
        shutdown_rx.clone(),
        error_tx.clone(),
    ));
    tasks.push(spawn_receiver(
        tunnel_socket.clone(),
        codec,
        ingress_index.clone(),
        egress_manager.clone(),
        ReceiverContext {
            side,
            last_received: last_received.clone(),
            max_dgram: config.max_dgram,
            shutdown_rx: shutdown_rx.clone(),
            error_tx: error_tx.clone(),
        },
    ));

    for rule in ingress_index.values() {
        tasks.push(spawn_ingress_task(
            side,
            rule.clone(),
            outbound_tx.clone(),
            next_flow.clone(),
            config.max_dgram,
            shutdown_rx.clone(),
            error_tx.clone(),
        ));
        tasks.push(spawn_ingress_cleanup_task(
            rule.clone(),
            outbound_tx.clone(),
            config.idle_timeout,
            shutdown_rx.clone(),
        ));
    }

    tasks.push(spawn_egress_cleanup_task(
        egress_manager.clone(),
        config.idle_timeout,
        shutdown_rx.clone(),
    ));
    tasks.push(spawn_keepalive_task(
        outbound_tx.clone(),
        config.keepalive,
        shutdown_rx.clone(),
    ));
    tasks.push(spawn_watchdog_task(
        last_received,
        config.keepalive,
        shutdown_rx.clone(),
        error_tx.clone(),
    ));

    let outcome = async {
        tokio::select! {
            maybe_error = error_rx.recv() => {
                match maybe_error {
                    Some(message) => Err(anyhow!(message)),
                    None => Ok(()),
                }
            }
            result = wait_monitor(external_monitor) => result,
        }
    }
    .await;

    let _ = shutdown_tx.send(true);
    for task in tasks {
        task.abort();
    }
    outcome
}

async fn wait_monitor(monitor: Option<JoinHandle<Result<()>>>) -> Result<()> {
    match monitor {
        Some(handle) => match handle.await {
            Ok(result) => result,
            Err(err) => Err(anyhow!("monitor task failed: {err}")),
        },
        None => std::future::pending::<Result<()>>().await,
    }
}

fn spawn_sender(
    socket: Arc<UdpSocket>,
    codec: Arc<TunnelCodec>,
    mut outbound_rx: mpsc::Receiver<TunnelFrame>,
    mut shutdown_rx: watch::Receiver<bool>,
    error_tx: mpsc::UnboundedSender<String>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                changed = shutdown_rx.changed() => {
                    if changed.is_err() || *shutdown_rx.borrow() {
                        break;
                    }
                }
                maybe_frame = outbound_rx.recv() => {
                    let Some(frame) = maybe_frame else { break };
                    match codec.seal(frame) {
                        Ok(packet) => {
                            if let Err(err) = socket.send(&packet).await {
                                let _ = error_tx.send(format!("failed to send tunnel packet: {err}"));
                                break;
                            }
                        }
                        Err(err) => {
                            let _ = error_tx.send(format!("failed to encode tunnel packet: {err:#}"));
                            break;
                        }
                    }
                }
            }
        }
    })
}

fn spawn_receiver(
    socket: Arc<UdpSocket>,
    codec: Arc<TunnelCodec>,
    ingress_index: Arc<HashMap<u32, Arc<IngressRule>>>,
    egress_manager: Arc<EgressManager>,
    mut context: ReceiverContext,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut buffer = vec![0u8; context.max_dgram + 512];
        loop {
            tokio::select! {
                changed = context.shutdown_rx.changed() => {
                    if changed.is_err() || *context.shutdown_rx.borrow() {
                        break;
                    }
                }
                recv = socket.recv(&mut buffer) => {
                    let size = match recv {
                        Ok(size) => size,
                        Err(err) => {
                            let _ = context.error_tx.send(format!("failed to receive tunnel packet: {err}"));
                            break;
                        }
                    };
                    let frame = match codec.open(&buffer[..size]) {
                        Ok(frame) => frame,
                        Err(err) => {
                            warn!("dropping invalid tunnel packet: {err}");
                            continue;
                        }
                    };
                    *context.last_received.lock().await = Instant::now();
                    if let Err(err) = handle_frame(context.side, frame, &ingress_index, &egress_manager).await {
                        let _ = context.error_tx.send(format!("tunnel processing failed: {err:#}"));
                        break;
                    }
                }
            }
        }
    })
}

async fn handle_frame(
    side: Side,
    frame: TunnelFrame,
    ingress_index: &HashMap<u32, Arc<IngressRule>>,
    egress_manager: &EgressManager,
) -> Result<()> {
    match frame.kind {
        FrameKind::Hello | FrameKind::HelloAck | FrameKind::Keepalive => Ok(()),
        FrameKind::Open => {
            if !flow_belongs_to(side, frame.flow_id) {
                egress_manager
                    .ensure_flow(frame.rule_id, frame.flow_id)
                    .await?;
            }
            Ok(())
        }
        FrameKind::Data => {
            if flow_belongs_to(side, frame.flow_id) {
                let rule = ingress_index
                    .get(&frame.rule_id)
                    .ok_or_else(|| anyhow!("unknown ingress rule {}", frame.rule_id))?;
                rule.route_reply(frame.flow_id, &frame.payload).await?;
            } else {
                egress_manager
                    .send_to_target(frame.rule_id, frame.flow_id, frame.payload)
                    .await?;
            }
            Ok(())
        }
        FrameKind::Close => {
            if flow_belongs_to(side, frame.flow_id) {
                if let Some(rule) = ingress_index.get(&frame.rule_id) {
                    rule.close_flow(frame.flow_id).await;
                }
            } else {
                egress_manager.close_flow(frame.flow_id).await;
            }
            Ok(())
        }
    }
}

fn spawn_ingress_task(
    side: Side,
    rule: Arc<IngressRule>,
    outbound_tx: mpsc::Sender<TunnelFrame>,
    next_flow: Arc<AtomicU64>,
    max_dgram: usize,
    mut shutdown_rx: watch::Receiver<bool>,
    error_tx: mpsc::UnboundedSender<String>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut buffer = vec![0u8; max_dgram.max(2048)];
        loop {
            tokio::select! {
                changed = shutdown_rx.changed() => {
                    if changed.is_err() || *shutdown_rx.borrow() {
                        break;
                    }
                }
                recv = rule.socket.recv_from(&mut buffer) => {
                    let (size, client_addr) = match recv {
                        Ok(value) => value,
                        Err(err) => {
                            let _ = error_tx.send(format!("failed to receive on {}: {err}", rule.spec.display()));
                            break;
                        }
                    };
                    if size > max_dgram {
                        warn!("dropping oversized datagram from {client_addr} on {}", rule.spec.display());
                        continue;
                    }
                    let (flow_id, created) = rule.touch_or_create(client_addr, || next_flow_id(side, &next_flow)).await;
                    if created && outbound_tx.send(TunnelFrame {
                        kind: FrameKind::Open,
                        rule_id: rule.spec.rule_id,
                        flow_id,
                        payload: Vec::new(),
                    }).await.is_err() {
                        break;
                    }
                    if outbound_tx.send(TunnelFrame {
                        kind: FrameKind::Data,
                        rule_id: rule.spec.rule_id,
                        flow_id,
                        payload: buffer[..size].to_vec(),
                    }).await.is_err() {
                        break;
                    }
                }
            }
        }
    })
}

fn spawn_ingress_cleanup_task(
    rule: Arc<IngressRule>,
    outbound_tx: mpsc::Sender<TunnelFrame>,
    idle_timeout: Duration,
    mut shutdown_rx: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let interval = cleanup_interval(idle_timeout);
        loop {
            tokio::select! {
                changed = shutdown_rx.changed() => {
                    if changed.is_err() || *shutdown_rx.borrow() {
                        break;
                    }
                }
                _ = sleep(interval) => {
                    let expired = rule.expire_flows(idle_timeout).await;
                    for flow_id in expired {
                        let _ = outbound_tx.send(TunnelFrame {
                            kind: FrameKind::Close,
                            rule_id: rule.spec.rule_id,
                            flow_id,
                            payload: Vec::new(),
                        }).await;
                    }
                }
            }
        }
    })
}

fn spawn_egress_cleanup_task(
    manager: Arc<EgressManager>,
    idle_timeout: Duration,
    mut shutdown_rx: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let interval = cleanup_interval(idle_timeout);
        loop {
            tokio::select! {
                changed = shutdown_rx.changed() => {
                    if changed.is_err() || *shutdown_rx.borrow() {
                        break;
                    }
                }
                _ = sleep(interval) => {
                    if let Err(err) = manager.expire_flows(idle_timeout).await {
                        warn!("egress cleanup failed: {err:#}");
                    }
                }
            }
        }
    })
}

fn spawn_keepalive_task(
    outbound_tx: mpsc::Sender<TunnelFrame>,
    keepalive: Duration,
    mut shutdown_rx: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                changed = shutdown_rx.changed() => {
                    if changed.is_err() || *shutdown_rx.borrow() {
                        break;
                    }
                }
                _ = sleep(keepalive) => {
                    if outbound_tx.send(TunnelFrame {
                        kind: FrameKind::Keepalive,
                        rule_id: 0,
                        flow_id: 0,
                        payload: Vec::new(),
                    }).await.is_err() {
                        break;
                    }
                }
            }
        }
    })
}

fn spawn_watchdog_task(
    last_received: Arc<Mutex<Instant>>,
    keepalive: Duration,
    mut shutdown_rx: watch::Receiver<bool>,
    error_tx: mpsc::UnboundedSender<String>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let timeout_after = Duration::from_secs_f64(keepalive.as_secs_f64() * 3.0);
        loop {
            tokio::select! {
                changed = shutdown_rx.changed() => {
                    if changed.is_err() || *shutdown_rx.borrow() {
                        break;
                    }
                }
                _ = sleep(keepalive) => {
                    if last_received.lock().await.elapsed() > timeout_after {
                        let _ = error_tx.send(format!("tunnel timed out after {:?} without inbound traffic", timeout_after));
                        break;
                    }
                }
            }
        }
    })
}

async fn bind_ingress_rules(
    forwards: &[ForwardSpec],
    listen_side: ListenSide,
    family: Option<IpFamily>,
) -> Result<(Vec<Arc<IngressRule>>, Vec<BoundListener>)> {
    let mut rules = Vec::new();
    let mut listeners = Vec::new();
    for spec in forwards
        .iter()
        .filter(|spec| spec.listen_side == listen_side)
    {
        let bind_addr =
            resolve_bind_addr(spec.bind_host.as_deref(), spec.listen_port, family).await?;
        let socket = Arc::new(UdpSocket::bind(bind_addr).await.with_context(|| {
            format!(
                "failed to bind {} listener `{}`",
                listen_side,
                spec.display()
            )
        })?);
        let local_addr = socket.local_addr()?;
        listeners.push(BoundListener {
            rule_id: spec.rule_id,
            listen_side: spec.listen_side,
            requested: spec.requested(),
            bound: local_addr,
        });
        rules.push(Arc::new(IngressRule {
            spec: spec.clone(),
            socket,
            state: Arc::new(Mutex::new(IngressState::default())),
        }));
    }
    Ok((rules, listeners))
}

impl IngressRule {
    async fn touch_or_create<F>(&self, client_addr: SocketAddr, next_flow: F) -> (u64, bool)
    where
        F: FnOnce() -> u64,
    {
        let mut state = self.state.lock().await;
        let now = Instant::now();
        if let Some(flow) = state.by_client.get_mut(&client_addr) {
            flow.last_activity = now;
            return (flow.flow_id, false);
        }
        let flow_id = next_flow();
        state.by_client.insert(
            client_addr,
            IngressFlow {
                flow_id,
                last_activity: now,
            },
        );
        state.by_flow.insert(flow_id, client_addr);
        (flow_id, true)
    }

    async fn route_reply(&self, flow_id: u64, payload: &[u8]) -> Result<()> {
        let client_addr = {
            let mut state = self.state.lock().await;
            let client_addr =
                state.by_flow.get(&flow_id).copied().ok_or_else(|| {
                    anyhow!("unknown flow {flow_id} for rule {}", self.spec.rule_id)
                })?;
            if let Some(flow) = state.by_client.get_mut(&client_addr) {
                flow.last_activity = Instant::now();
            }
            client_addr
        };
        self.socket.send_to(payload, client_addr).await?;
        Ok(())
    }

    async fn expire_flows(&self, idle_timeout: Duration) -> Vec<u64> {
        let mut state = self.state.lock().await;
        let now = Instant::now();
        let expired: Vec<(SocketAddr, u64)> = state
            .by_client
            .iter()
            .filter_map(|(client, flow)| {
                if now.duration_since(flow.last_activity) > idle_timeout {
                    Some((*client, flow.flow_id))
                } else {
                    None
                }
            })
            .collect();
        for (client, flow_id) in &expired {
            state.by_client.remove(client);
            state.by_flow.remove(flow_id);
        }
        expired.into_iter().map(|(_, flow_id)| flow_id).collect()
    }

    async fn close_flow(&self, flow_id: u64) {
        let mut state = self.state.lock().await;
        if let Some(client) = state.by_flow.remove(&flow_id) {
            state.by_client.remove(&client);
        }
    }
}

impl EgressManager {
    fn new(
        forwards: &[ForwardSpec],
        listen_side: ListenSide,
        family: Option<IpFamily>,
        max_dgram: usize,
        outbound: mpsc::Sender<TunnelFrame>,
    ) -> Self {
        let specs = forwards
            .iter()
            .filter(|spec| spec.listen_side == listen_side)
            .map(|spec| (spec.rule_id, spec.clone()))
            .collect();
        Self {
            specs,
            family,
            max_dgram,
            outbound,
            flows: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    async fn ensure_flow(&self, rule_id: u32, flow_id: u64) -> Result<()> {
        if self.flows.lock().await.contains_key(&flow_id) {
            return Ok(());
        }
        let spec = self
            .specs
            .get(&rule_id)
            .cloned()
            .ok_or_else(|| anyhow!("unknown egress rule {rule_id}"))?;
        let target_addr =
            resolve_target_addr(&spec.target_host, spec.target_port, self.family).await?;
        let socket = Arc::new(
            UdpSocket::bind(wildcard_addr(0, family_for_addr(self.family, target_addr))).await?,
        );
        socket.connect(target_addr).await?;
        let last_activity = Arc::new(Mutex::new(Instant::now()));
        let (close_tx, mut close_rx) = oneshot::channel::<()>();
        let outbound = self.outbound.clone();
        let flow_socket = socket.clone();
        let flow_last_activity = last_activity.clone();
        let max_dgram = self.max_dgram;
        tokio::spawn(async move {
            let mut buffer = vec![0u8; max_dgram.max(2048)];
            loop {
                tokio::select! {
                    _ = &mut close_rx => break,
                    recv = flow_socket.recv(&mut buffer) => {
                        match recv {
                            Ok(size) => {
                                *flow_last_activity.lock().await = Instant::now();
                                if size > max_dgram {
                                    warn!("dropping oversized datagram from target for rule {rule_id}");
                                    continue;
                                }
                                if outbound.send(TunnelFrame {
                                    kind: FrameKind::Data,
                                    rule_id,
                                    flow_id,
                                    payload: buffer[..size].to_vec(),
                                }).await.is_err() {
                                    break;
                                }
                            }
                            Err(err) => {
                                warn!("egress receive failed for rule {rule_id}: {err}");
                                let _ = outbound.send(TunnelFrame {
                                    kind: FrameKind::Close,
                                    rule_id,
                                    flow_id,
                                    payload: Vec::new(),
                                }).await;
                                break;
                            }
                        }
                    }
                }
            }
        });

        self.flows.lock().await.insert(
            flow_id,
            EgressFlow {
                socket,
                close_tx,
                last_activity,
            },
        );
        Ok(())
    }

    async fn send_to_target(&self, rule_id: u32, flow_id: u64, payload: Vec<u8>) -> Result<()> {
        self.ensure_flow(rule_id, flow_id).await?;
        let socket = {
            let mut flows = self.flows.lock().await;
            let flow = flows
                .get_mut(&flow_id)
                .ok_or_else(|| anyhow!("egress flow {flow_id} vanished"))?;
            *flow.last_activity.lock().await = Instant::now();
            flow.socket.clone()
        };
        socket.send(&payload).await?;
        Ok(())
    }

    async fn close_flow(&self, flow_id: u64) {
        if let Some(flow) = self.flows.lock().await.remove(&flow_id) {
            let _ = flow.close_tx.send(());
        }
    }

    async fn expire_flows(&self, idle_timeout: Duration) -> Result<()> {
        let flow_ids: Vec<u64> = {
            let flows = self.flows.lock().await;
            let mut expired = Vec::new();
            for (flow_id, flow) in flows.iter() {
                if flow.last_activity.lock().await.elapsed() > idle_timeout {
                    expired.push(*flow_id);
                }
            }
            expired
        };
        for flow_id in flow_ids {
            if let Some(flow) = self.flows.lock().await.remove(&flow_id) {
                let _ = flow.close_tx.send(());
            }
        }
        Ok(())
    }
}

async fn bind_tunnel_socket(
    family: Option<IpFamily>,
    udp_bind_port: Option<u16>,
    udp_port_range: Option<(u16, u16)>,
) -> Result<UdpSocket> {
    if let Some(port) = udp_bind_port {
        return Ok(UdpSocket::bind(wildcard_addr(port, family)).await?);
    }
    if let Some((start, end)) = udp_port_range {
        let mut rng = rand::rng();
        let offset = rng.random_range(0..=(end - start));
        for delta in 0..=(end - start) {
            let port = start + ((offset + delta) % (end - start + 1));
            match UdpSocket::bind(wildcard_addr(port, family)).await {
                Ok(socket) => return Ok(socket),
                Err(_) => continue,
            }
        }
        bail!("failed to bind any UDP port in range {start}:{end}");
    }
    Ok(UdpSocket::bind(wildcard_addr(0, family)).await?)
}

async fn perform_local_handshake(
    socket: Arc<UdpSocket>,
    codec: Arc<TunnelCodec>,
    keepalive: Duration,
    max_dgram: usize,
) -> Result<()> {
    let deadline = Instant::now() + keepalive.max(Duration::from_secs(5));
    let mut buffer = vec![0u8; max_dgram + 512];
    while Instant::now() < deadline {
        let packet = codec.seal(TunnelFrame {
            kind: FrameKind::Hello,
            rule_id: 0,
            flow_id: 0,
            payload: Vec::new(),
        })?;
        socket.send(&packet).await?;
        match timeout(Duration::from_millis(500), socket.recv(&mut buffer)).await {
            Ok(Ok(size)) => {
                let frame = match codec.open(&buffer[..size]) {
                    Ok(frame) => frame,
                    Err(_) => continue,
                };
                if frame.kind == FrameKind::HelloAck {
                    info!("UDP tunnel established");
                    return Ok(());
                }
            }
            Ok(Err(err)) => return Err(err.into()),
            Err(_) => {}
        }
    }
    bail!("timed out waiting for UDP tunnel handshake")
}

async fn accept_remote_handshake(
    socket: Arc<UdpSocket>,
    codec: Arc<TunnelCodec>,
    keepalive: Duration,
    max_dgram: usize,
) -> Result<()> {
    let deadline = Instant::now() + keepalive.max(Duration::from_secs(10));
    let mut buffer = vec![0u8; max_dgram + 512];
    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let recv = timeout(remaining, socket.recv_from(&mut buffer)).await;
        let (size, peer) = match recv {
            Ok(Ok(value)) => value,
            Ok(Err(err)) => return Err(err.into()),
            Err(_) => break,
        };
        let frame = match codec.open(&buffer[..size]) {
            Ok(frame) => frame,
            Err(_) => continue,
        };
        if frame.kind != FrameKind::Hello {
            continue;
        }
        socket.connect(peer).await?;
        let packet = codec.seal(TunnelFrame {
            kind: FrameKind::HelloAck,
            rule_id: 0,
            flow_id: 0,
            payload: Vec::new(),
        })?;
        socket.send(&packet).await?;
        info!("accepted UDP tunnel from {peer}");
        return Ok(());
    }
    bail!("timed out waiting for client UDP handshake")
}

fn index_ingress_rules(rules: Vec<Arc<IngressRule>>) -> HashMap<u32, Arc<IngressRule>> {
    rules
        .into_iter()
        .map(|rule| (rule.spec.rule_id, rule))
        .collect()
}

fn next_flow_id(side: Side, next_flow: &AtomicU64) -> u64 {
    side.flow_prefix() | next_flow.fetch_add(1, Ordering::Relaxed)
}

fn flow_belongs_to(side: Side, flow_id: u64) -> bool {
    (flow_id >> 63) == (side.flow_prefix() >> 63)
}

fn opposite_listen_side(side: Side) -> ListenSide {
    match side {
        Side::Local => ListenSide::Remote,
        Side::Remote => ListenSide::Local,
    }
}

fn cleanup_interval(idle_timeout: Duration) -> Duration {
    let half = Duration::from_secs_f64((idle_timeout.as_secs_f64() / 2.0).max(1.0));
    half.min(Duration::from_secs(5))
}

fn validate_reply(reply: &BootstrapReply) -> Result<()> {
    if reply.version != PROTOCOL_VERSION {
        bail!(
            "remote agent returned protocol version {}, expected {}",
            reply.version,
            PROTOCOL_VERSION
        );
    }
    Ok(())
}

fn print_bindings(local: &[BoundListener], remote: &[BoundListener]) {
    for bound in local.iter().chain(remote.iter()) {
        println!(
            "{} {} -> {}",
            bound.listen_side, bound.requested, bound.bound
        );
    }
}

fn extract_host(destination: &str) -> String {
    destination
        .rsplit_once('@')
        .map(|(_, host)| host)
        .unwrap_or(destination)
        .to_string()
}

fn family_name(family: IpFamily) -> String {
    match family {
        IpFamily::V4 => "ipv4".to_string(),
        IpFamily::V6 => "ipv6".to_string(),
    }
}

fn parse_family(value: Option<&str>) -> Result<Option<IpFamily>> {
    match value {
        Some("ipv4") => Ok(Some(IpFamily::V4)),
        Some("ipv6") => Ok(Some(IpFamily::V6)),
        Some(other) => bail!("unsupported family `{other}`"),
        None => Ok(None),
    }
}

fn family_for_addr(explicit: Option<IpFamily>, addr: SocketAddr) -> Option<IpFamily> {
    explicit.or_else(|| {
        Some(if addr.is_ipv6() {
            IpFamily::V6
        } else {
            IpFamily::V4
        })
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use anyhow::Result;
    use tokio::net::UdpSocket;
    use tokio::sync::{mpsc, oneshot};
    use tokio::task::JoinHandle;
    use tokio::time::timeout;

    use super::{
        EgressManager, IngressRule, IngressState, RuntimeConfig, accept_remote_handshake,
        bind_ingress_rules, bind_tunnel_socket, cleanup_interval, extract_host, family_for_addr,
        flow_belongs_to, perform_local_handshake, run_forwarding, wildcard_addr,
    };
    use crate::protocol::Side;
    use crate::spec::{ForwardSpec, IpFamily, ListenSide};
    use crate::tunnel::TunnelCodec;

    #[test]
    fn extracts_host_after_user_prefix() {
        assert_eq!(extract_host("joe@example.com"), "example.com");
        assert_eq!(extract_host("host-alias"), "host-alias");
    }

    #[test]
    fn flow_owner_uses_high_bit() {
        assert!(flow_belongs_to(Side::Local, 42));
        assert!(!flow_belongs_to(Side::Local, (1u64 << 63) | 42));
        assert!(flow_belongs_to(Side::Remote, (1u64 << 63) | 42));
    }

    #[test]
    fn cleanup_interval_is_capped() {
        assert_eq!(
            cleanup_interval(Duration::from_secs(2)),
            Duration::from_secs(1)
        );
        assert_eq!(
            cleanup_interval(Duration::from_secs(30)),
            Duration::from_secs(5)
        );
    }

    #[test]
    fn infers_family_from_socket_address() {
        assert_eq!(
            family_for_addr(None, "127.0.0.1:4172".parse().unwrap()),
            Some(IpFamily::V4)
        );
        assert_eq!(
            family_for_addr(None, "[::1]:4172".parse().unwrap()),
            Some(IpFamily::V6)
        );
        assert_eq!(
            family_for_addr(Some(IpFamily::V4), "[::1]:4172".parse().unwrap()),
            Some(IpFamily::V4)
        );
    }

    #[tokio::test]
    async fn binds_requested_tunnel_port_and_range() {
        let socket = bind_tunnel_socket(Some(IpFamily::V4), None, Some((41000, 41005)))
            .await
            .unwrap();
        let port = socket.local_addr().unwrap().port();
        assert!((41000..=41005).contains(&port));

        let specific = bind_tunnel_socket(Some(IpFamily::V4), Some(0), None)
            .await
            .unwrap();
        assert!(specific.local_addr().unwrap().port() > 0);
    }

    #[tokio::test]
    async fn handshake_succeeds_between_local_and_remote_sockets() {
        let secret = [5u8; 32];
        let session_id = [8u8; 16];
        let local_socket = Arc::new(
            UdpSocket::bind(wildcard_addr(0, Some(IpFamily::V4)))
                .await
                .unwrap(),
        );
        let remote_socket = Arc::new(
            UdpSocket::bind(wildcard_addr(0, Some(IpFamily::V4)))
                .await
                .unwrap(),
        );
        local_socket
            .connect(remote_socket.local_addr().unwrap())
            .await
            .unwrap();

        let remote_task = tokio::spawn(accept_remote_handshake(
            remote_socket.clone(),
            Arc::new(TunnelCodec::new(secret, session_id, Side::Remote).unwrap()),
            Duration::from_secs(1),
            1200,
        ));
        perform_local_handshake(
            local_socket.clone(),
            Arc::new(TunnelCodec::new(secret, session_id, Side::Local).unwrap()),
            Duration::from_secs(1),
            1200,
        )
        .await
        .unwrap();
        remote_task.await.unwrap().unwrap();

        local_socket.send(b"ping").await.unwrap();
        let mut buffer = [0u8; 16];
        let size = timeout(Duration::from_secs(1), remote_socket.recv(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buffer[..size], b"ping");
    }

    #[tokio::test]
    async fn ingress_rule_tracks_and_expires_flows() {
        let listener = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();
        let rule = IngressRule {
            spec: make_spec(
                1,
                ListenSide::Local,
                listener.local_addr().unwrap().port(),
                "127.0.0.1",
                9999,
            ),
            socket: listener,
            state: Arc::new(tokio::sync::Mutex::new(IngressState::default())),
        };

        let (flow_id, created) = rule.touch_or_create(client_addr, || 77).await;
        assert!(created);
        let (same_flow, created_again) = rule.touch_or_create(client_addr, || 88).await;
        assert_eq!(flow_id, same_flow);
        assert!(!created_again);

        rule.route_reply(flow_id, b"pong").await.unwrap();
        let mut buffer = [0u8; 16];
        let size = timeout(Duration::from_secs(1), client.recv(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buffer[..size], b"pong");

        {
            let mut state = rule.state.lock().await;
            state.by_client.get_mut(&client_addr).unwrap().last_activity =
                Instant::now() - Duration::from_secs(10);
        }
        let expired = rule.expire_flows(Duration::from_millis(1)).await;
        assert_eq!(expired, vec![flow_id]);

        rule.close_flow(flow_id).await;
        let state = rule.state.lock().await;
        assert!(state.by_client.is_empty());
        assert!(state.by_flow.is_empty());
    }

    #[tokio::test]
    async fn egress_manager_sends_to_target_and_receives_reply() {
        let (target_addr, target_task) = spawn_udp_echo_server().await;
        let spec = make_spec(9, ListenSide::Remote, 0, "127.0.0.1", target_addr.port());
        let (outbound_tx, mut outbound_rx) = mpsc::channel(8);
        let manager = EgressManager::new(
            &[spec],
            ListenSide::Remote,
            Some(IpFamily::V4),
            1200,
            outbound_tx,
        );

        manager
            .send_to_target(9, 42, b"hello".to_vec())
            .await
            .unwrap();
        let frame = timeout(Duration::from_secs(1), outbound_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(frame.rule_id, 9);
        assert_eq!(frame.flow_id, 42);
        assert_eq!(frame.payload, b"hello");

        {
            let flows = manager.flows.lock().await;
            assert_eq!(flows.len(), 1);
        }

        manager.close_flow(42).await;
        {
            let flows = manager.flows.lock().await;
            assert!(flows.is_empty());
        }

        target_task.abort();
    }

    #[tokio::test]
    async fn forwarding_runtime_handles_local_and_remote_rules_end_to_end() {
        let secret = [11u8; 32];
        let session_id = [12u8; 16];
        let keepalive = Duration::from_millis(200);
        let idle_timeout = Duration::from_secs(5);

        let (remote_target_addr, remote_target_task) = spawn_udp_echo_server().await;
        let (local_target_addr, local_target_task) = spawn_udp_echo_server().await;

        let forward_l = make_spec(
            1,
            ListenSide::Local,
            0,
            "127.0.0.1",
            remote_target_addr.port(),
        );
        let forward_r = make_spec(
            2,
            ListenSide::Remote,
            0,
            "127.0.0.1",
            local_target_addr.port(),
        );
        let forwards = vec![forward_l.clone(), forward_r.clone()];

        let (local_rules, local_bounds) =
            bind_ingress_rules(&forwards, ListenSide::Local, Some(IpFamily::V4))
                .await
                .unwrap();
        let (remote_rules, remote_bounds) =
            bind_ingress_rules(&forwards, ListenSide::Remote, Some(IpFamily::V4))
                .await
                .unwrap();
        assert_eq!(local_bounds.len(), 1);
        assert_eq!(remote_bounds.len(), 1);

        let local_tunnel = Arc::new(
            UdpSocket::bind(wildcard_addr(0, Some(IpFamily::V4)))
                .await
                .unwrap(),
        );
        let remote_tunnel = Arc::new(
            UdpSocket::bind(wildcard_addr(0, Some(IpFamily::V4)))
                .await
                .unwrap(),
        );
        local_tunnel
            .connect(remote_tunnel.local_addr().unwrap())
            .await
            .unwrap();

        let remote_handshake = tokio::spawn(accept_remote_handshake(
            remote_tunnel.clone(),
            Arc::new(TunnelCodec::new(secret, session_id, Side::Remote).unwrap()),
            keepalive,
            1200,
        ));
        perform_local_handshake(
            local_tunnel.clone(),
            Arc::new(TunnelCodec::new(secret, session_id, Side::Local).unwrap()),
            keepalive,
            1200,
        )
        .await
        .unwrap();
        remote_handshake.await.unwrap().unwrap();

        let (local_stop_tx, local_stop_rx) = oneshot::channel();
        let (remote_stop_tx, remote_stop_rx) = oneshot::channel();
        let local_runtime = tokio::spawn(run_forwarding(
            Side::Local,
            local_tunnel,
            Arc::new(TunnelCodec::new(secret, session_id, Side::Local).unwrap()),
            forwards.clone(),
            local_rules.clone(),
            RuntimeConfig {
                family: Some(IpFamily::V4),
                keepalive,
                idle_timeout,
                max_dgram: 1200,
            },
            Some(shutdown_monitor(local_stop_rx)),
        ));
        let remote_runtime = tokio::spawn(run_forwarding(
            Side::Remote,
            remote_tunnel,
            Arc::new(TunnelCodec::new(secret, session_id, Side::Remote).unwrap()),
            forwards,
            remote_rules.clone(),
            RuntimeConfig {
                family: Some(IpFamily::V4),
                keepalive,
                idle_timeout,
                max_dgram: 1200,
            },
            Some(shutdown_monitor(remote_stop_rx)),
        ));

        let local_client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        local_client
            .send_to(
                b"through-local",
                local_rules[0].socket.local_addr().unwrap(),
            )
            .await
            .unwrap();
        let mut buffer = [0u8; 64];
        let size = timeout(Duration::from_secs(2), local_client.recv(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buffer[..size], b"through-local");

        let remote_client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        remote_client
            .send_to(
                b"through-remote",
                remote_rules[0].socket.local_addr().unwrap(),
            )
            .await
            .unwrap();
        let size = timeout(Duration::from_secs(2), remote_client.recv(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buffer[..size], b"through-remote");

        let _ = local_stop_tx.send(());
        let _ = remote_stop_tx.send(());
        local_runtime.await.unwrap().unwrap();
        remote_runtime.await.unwrap().unwrap();
        remote_target_task.abort();
        local_target_task.abort();
    }

    fn make_spec(
        rule_id: u32,
        listen_side: ListenSide,
        listen_port: u16,
        target_host: &str,
        target_port: u16,
    ) -> ForwardSpec {
        ForwardSpec {
            rule_id,
            listen_side,
            bind_host: Some("127.0.0.1".to_string()),
            listen_port,
            target_host: target_host.to_string(),
            target_port,
        }
    }

    async fn spawn_udp_echo_server() -> (std::net::SocketAddr, JoinHandle<()>) {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut buffer = [0u8; 2048];
            loop {
                let (size, peer) = socket.recv_from(&mut buffer).await.unwrap();
                socket.send_to(&buffer[..size], peer).await.unwrap();
            }
        });
        (addr, task)
    }

    fn shutdown_monitor(stop_rx: oneshot::Receiver<()>) -> JoinHandle<Result<()>> {
        tokio::spawn(async move {
            let _ = stop_rx.await;
            Ok(())
        })
    }
}
