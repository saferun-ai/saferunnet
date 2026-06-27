use saferunnet_app::{
    AppKernel, DnsResolverModule, IdentityModule, LinkMessageModule, LinkSessionStateModule,
    NODE_IDENTITY_SERVICE_KEY, PathManagerModule, SessionCoordinatorModule,
};
use saferunnet_config::load_from_path;
use saferunnet_crypto::{Ed25519KeyGenerator, KeyAlgorithm};
use saferunnet_dht::NetworkDht;
use saferunnet_dns::resolver::DhtClient;
use saferunnet_identity::{FileIdentityRepository, IdentitySpec, NodeIdentity};
use saferunnet_platform::TunDevice;
#[cfg(windows)]
use saferunnet_platform::WinTunDevice;
use saferunnet_rpc::RpcServer;

mod forwarder;
mod updater;
use forwarder::OnionForwarder;
use saferunnet_transport::{LinkTransport, UdpTransport};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

const DEFAULT_KEYFILE_NAME: &str = "identity.key";

/// Generate a session nonce from system entropy (startup time + PID).
fn make_session_nonce() -> [u8; 32] {
    use std::hash::{Hash, Hasher};
    use std::time::SystemTime;
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    SystemTime::now().hash(&mut hasher);
    std::process::id().hash(&mut hasher);
    let seed = hasher.finish();
    let mut nonce = [0u8; 32];
    nonce[..8].copy_from_slice(&seed.to_le_bytes());
    let seed_upper = seed.wrapping_mul(0x9E3779B97F4A7C15);
    nonce[24..].copy_from_slice(&seed_upper.to_le_bytes());
    nonce
}

/// Run the TUN read/write loop. Reads IP packets, resolves .loki DNS queries,
/// and forwards non-DNS packets through the onion network.
fn run_tun_loop(
    mut tun: WinTunDevice,
    dht: Arc<dyn DhtClient>,
    forwarder: Arc<OnionForwarder>,
    transport: Arc<UdpTransport>,
    rt_handle: tokio::runtime::Handle,
    session_nonce: [u8; 32],
) {
    let mut buf = vec![0u8; 4096];
    let mut path_counter: u64 = 0;
    loop {
        match tun.read(&mut buf) {
            Ok(len) if len > 0 => {
                let packet = &buf[..len];
                if let Some(response) = handle_dns_query(packet, &*dht) {
                    let _ = tun.write(&response);
                }
                if !is_dns_packet(packet) {
                    let dest_key = forwarder::derive_dest_key_from_ip(&packet[16..20]);
                    let mut nonce = session_nonce;
                    let counter_bytes = path_counter.to_le_bytes();
                    for (i, b) in counter_bytes.iter().enumerate() {
                        nonce[i] ^= b;
                    }
                    match forwarder.resolve_and_forward_with_addr(
                        packet,
                        dht.as_ref(),
                        &dest_key,
                        &nonce,
                        path_counter,
                    ) {
                        Ok((frame, first_addr)) => {
                            let frame_bytes = frame.encode();
                            let result =
                                rt_handle.block_on(transport.send_to(&frame_bytes, first_addr));
                            match result {
                                Ok(n) => tracing::debug!(
                                    bytes = n,
                                    path_id = frame.path_id,
                                    "onion frame sent"
                                ),
                                Err(e) => tracing::warn!(error = %e, "transport send failed"),
                            }
                        }
                        Err(e) => tracing::warn!(error = %e, "onion forward failed"),
                    }
                    path_counter += 1;
                }
            }
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(error = %e, "TUN read error");
                break;
            }
        }
    }
}

/// Check if an IP packet contains DNS traffic (UDP port 53).
fn is_dns_packet(packet: &[u8]) -> bool {
    if packet.len() < 20 {
        return false;
    }
    if (packet[0] >> 4) != 4 {
        return false;
    }
    if packet[9] != 17 {
        return false;
    }
    let ip_hdr_len = ((packet[0] & 0x0F) * 4) as usize;
    if packet.len() < ip_hdr_len + 4 {
        return false;
    }
    let sport = u16::from_be_bytes([packet[ip_hdr_len], packet[ip_hdr_len + 1]]);
    let dport = u16::from_be_bytes([packet[ip_hdr_len + 2], packet[ip_hdr_len + 3]]);
    sport == 53 || dport == 53
}

/// Handle a DNS query from the TUN. If it is a .loki query, resolve via DHT
/// and return a DNS response packet. Returns None for non-.loki queries.
fn handle_dns_query(packet: &[u8], dht: &dyn DhtClient) -> Option<Vec<u8>> {
    let (dns_start, _dns_id, dns_flags) = parse_dns_header(packet)?;

    if (dns_flags & 0x8000) != 0 {
        return None;
    }

    let (qname, qtype, qclass, _qname_end) = parse_dns_question(packet, dns_start + 12)?;

    if !qname.ends_with(".loki") || qtype != 1 || qclass != 1 {
        return None;
    }

    tracing::debug!(%qname, "TUN: .loki DNS query");

    let lookup_key = name_to_public_key(&qname);
    let results = dht.lookup_intro_set(&lookup_key);

    let mapped_ip = if results.is_empty() {
        return Some(build_dns_error_response(packet, dns_start, &qname));
    } else {
        let pk_bytes = &results[0].public_key.to_bytes();
        [10, pk_bytes[29], pk_bytes[30], pk_bytes[31]]
    };

    tracing::info!(%qname, ip = %std::net::Ipv4Addr::from(mapped_ip), "TUN: resolved .loki name");

    Some(build_dns_a_response(packet, dns_start, &qname, mapped_ip))
}

fn parse_dns_header(packet: &[u8]) -> Option<(usize, u16, u16)> {
    if packet.len() < 20 {
        return None;
    }
    if (packet[0] >> 4) != 4 {
        return None;
    }
    let ip_hdr_len = ((packet[0] & 0x0F) * 4) as usize;
    if packet.len() < ip_hdr_len + 8 + 12 {
        return None;
    }
    let dns_start = ip_hdr_len + 8;
    let id = u16::from_be_bytes([packet[dns_start], packet[dns_start + 1]]);
    let flags = u16::from_be_bytes([packet[dns_start + 2], packet[dns_start + 3]]);
    Some((dns_start, id, flags))
}

fn parse_dns_question(packet: &[u8], start: usize) -> Option<(String, u16, u16, usize)> {
    let (name, pos) = decode_dns_name_full(packet, start)?;
    if packet.len() < pos + 4 {
        return None;
    }
    let qtype = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
    let qclass = u16::from_be_bytes([packet[pos + 2], packet[pos + 3]]);
    Some((name, qtype, qclass, pos + 4))
}

fn decode_dns_name_full(packet: &[u8], start: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut pos = start;
    let mut jumped = false;
    let mut jump_end = start;
    loop {
        if pos >= packet.len() {
            return None;
        }
        let len = packet[pos];
        if len == 0 {
            pos += 1;
            if !jumped {
                jump_end = pos;
            }
            break;
        }
        if (len & 0xC0) == 0xC0 {
            if pos + 1 >= packet.len() {
                return None;
            }
            let offset = ((len as usize & 0x3F) << 8) | packet[pos + 1] as usize;
            if !jumped {
                jump_end = pos + 2;
            }
            jumped = true;
            pos = offset;
            continue;
        }
        pos += 1;
        if pos + len as usize > packet.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&packet[pos..pos + len as usize]).to_string());
        pos += len as usize;
    }
    Some((labels.join("."), jump_end))
}

fn build_dns_a_response(original: &[u8], dns_start: usize, qname: &str, ip: [u8; 4]) -> Vec<u8> {
    let id = u16::from_be_bytes([original[dns_start], original[dns_start + 1]]);
    let (_qname_end, _) = decode_dns_name_full(original, dns_start + 12)
        .unwrap_or((qname.to_string(), dns_start + 12));

    let qname_wire_len = qname.len() + 2;
    let answer_len = qname_wire_len + 2 + 2 + 4 + 2 + 4;

    let mut resp = Vec::with_capacity(dns_start + 12 + qname_wire_len + 4 + answer_len);

    let ip_hdr_len = ((original[0] & 0x0F) * 4) as usize;
    resp.extend_from_slice(&original[..ip_hdr_len]);
    let src_ip_start = 12;
    let dst_ip_start = 16;
    resp[src_ip_start..src_ip_start + 4].copy_from_slice(&original[dst_ip_start..dst_ip_start + 4]);
    resp[dst_ip_start..dst_ip_start + 4].copy_from_slice(&original[src_ip_start..src_ip_start + 4]);
    resp[10] = 0;
    resp[11] = 0;
    let ip_total = (ip_hdr_len + 8 + 12 + 4 + answer_len) as u16;
    resp[2] = (ip_total >> 8) as u8;
    resp[3] = ip_total as u8;

    let udp_start = ip_hdr_len;
    resp.push(original[udp_start + 2]);
    resp.push(original[udp_start + 3]);
    resp.push(original[udp_start]);
    resp.push(original[udp_start + 1]);
    let udp_len = (8 + 12 + 4 + answer_len) as u16;
    resp.push((udp_len >> 8) as u8);
    resp.push(udp_len as u8);
    resp.push(0);
    resp.push(0);

    resp.push((id >> 8) as u8);
    resp.push(id as u8);
    let flags: u16 = 0x8180;
    resp.push((flags >> 8) as u8);
    resp.push(flags as u8);
    resp.push(0);
    resp.push(1);
    resp.push(0);
    resp.push(1);
    resp.push(0);
    resp.push(0);
    resp.push(0);
    resp.push(0);

    let qname_start = dns_start + 12;
    let (_, qname_end_pos) =
        decode_dns_name_full(original, qname_start).unwrap_or((String::new(), qname_start + 2));
    let qsection_len = qname_end_pos - qname_start + 4;
    resp.extend_from_slice(&original[qname_start..qname_start + qsection_len]);

    let name_ptr: u16 = 0xC000 | 12;
    resp.push((name_ptr >> 8) as u8);
    resp.push(name_ptr as u8);
    resp.push(0);
    resp.push(1);
    resp.push(0);
    resp.push(1);
    resp.push(0);
    resp.push(0);
    resp.push(1);
    resp.push(0x2C);
    resp.push(0);
    resp.push(4);
    resp.extend_from_slice(&ip);

    let csum = ip_checksum(&resp[..ip_hdr_len]);
    resp[10] = (csum >> 8) as u8;
    resp[11] = csum as u8;

    resp
}

fn build_dns_error_response(original: &[u8], dns_start: usize, _qname: &str) -> Vec<u8> {
    let mut resp = original[..std::cmp::min(dns_start + 512, original.len())].to_vec();
    if resp.len() < dns_start + 12 {
        return resp;
    }

    let ip_hdr_len = ((original[0] & 0x0F) * 4) as usize;
    resp[12..16].copy_from_slice(&original[16..20]);
    resp[16..20].copy_from_slice(&original[12..16]);
    resp[10] = 0;
    resp[11] = 0;
    let csum = ip_checksum(&resp[..ip_hdr_len]);
    resp[10] = (csum >> 8) as u8;
    resp[11] = csum as u8;

    let udp = ip_hdr_len;
    let tmp_hi = resp[udp];
    let tmp_lo = resp[udp + 1];
    resp[udp] = resp[udp + 2];
    resp[udp + 1] = resp[udp + 3];
    resp[udp + 2] = tmp_hi;
    resp[udp + 3] = tmp_lo;
    resp[udp + 6] = 0;
    resp[udp + 7] = 0;

    resp[dns_start + 2] = 0x81;
    resp[dns_start + 3] = 0x83;

    resp
}

fn ip_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for i in (0..header.len()).step_by(2) {
        let word = if i + 1 < header.len() {
            u16::from_be_bytes([header[i], header[i + 1]]) as u32
        } else {
            (header[i] as u32) << 8
        };
        sum = sum.wrapping_add(word);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

fn name_to_public_key(name: &str) -> saferunnet_crypto::PublicKey {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    name.hash(&mut hasher);
    let h = hasher.finish();
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&h.to_le_bytes());
    bytes[8..16].copy_from_slice(&h.to_le_bytes());
    saferunnet_crypto::PublicKey::from_bytes(saferunnet_crypto::KeyAlgorithm::Ed25519, bytes)
}

#[cfg(windows)]
mod service {
    #[derive(Debug, PartialEq)]
    pub enum ServiceStatus {
        Running,
        Stopped,
        NotInstalled,
    }

    /// Build the `sc.exe create` command arguments (testable without process execution).
    pub fn build_install_args(bin_path: &str, config_path: &str) -> Vec<String> {
        vec![
            "create".to_string(),
            "saferunnet".to_string(),
            format!("binPath= {bin_path} daemon --config {config_path}"),
            "start=".to_string(),
            "auto".to_string(),
            "DisplayName=".to_string(),
            "Saferunnet LLARP Service".to_string(),
        ]
    }

    pub fn install_service(bin_path: &str, config_path: &str) {
        let args = build_install_args(bin_path, config_path);
        let status = std::process::Command::new("sc.exe").args(&args).output();
        match status {
            Ok(out) if out.status.success() => {
                println!("Service installed. Start with: sc.exe start saferunnet");
            }
            Ok(out) => {
                eprintln!("Failed: {}", String::from_utf8_lossy(&out.stderr));
            }
            Err(e) => eprintln!("Failed to run sc.exe: {e}"),
        }
    }

    pub fn uninstall_service() {
        let status = std::process::Command::new("sc.exe")
            .args(["delete", "saferunnet"])
            .output();
        match status {
            Ok(out) if out.status.success() => println!("Service uninstalled."),
            Ok(out) => eprintln!("Failed: {}", String::from_utf8_lossy(&out.stderr)),
            Err(e) => eprintln!("Failed to run sc.exe: {e}"),
        }
    }

    pub fn query_service_status() -> ServiceStatus {
        match std::process::Command::new("sc.exe")
            .args(["query", "saferunnet"])
            .output()
        {
            Ok(out) => {
                let stdout = String::from_utf8_lossy(&out.stdout).to_uppercase();
                if stdout.contains("RUNNING") {
                    ServiceStatus::Running
                } else if stdout.contains("STOPPED") {
                    ServiceStatus::Stopped
                } else {
                    ServiceStatus::NotInstalled
                }
            }
            Err(_) => ServiceStatus::NotInstalled,
        }
    }
}

fn main() {
    saferunnet_observability::install("info").expect("install tracing");

    let args: Vec<String> = std::env::args().collect();

    if args.len() >= 3 && args[1] == "--check-config" {
        load_from_path(&args[2]).expect("load config");
        println!("config ok");
        return;
    }

    if args.len() >= 3 && args[1] == "--bootstrap" {
        run_bootstrap(Path::new(&args[2]));
        return;
    }

    if args.len() >= 2 && args[1] == "--check-services" {
        run_service_check();
        return;
    }

    if args.len() >= 3 && args[1] == "daemon" {
        let config_path = if args[2] == "--config" && args.len() >= 4 {
            PathBuf::from(&args[3])
        } else {
            PathBuf::from(&args[2])
        };
        run_daemon(&config_path);
        return;
    }

    #[cfg(windows)]
    if args.len() >= 2 && args[1] == "--service-install" {
        let config_path = if args.len() >= 3 {
            &args[2]
        } else {
            "saferunnet.ini"
        };
        let bin_path = std::env::current_exe()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "saferunnet.exe".into());
        service::install_service(&bin_path, config_path);
        return;
    }

    #[cfg(windows)]
    if args.len() >= 2 && args[1] == "--service-uninstall" {
        service::uninstall_service();
        return;
    }

    #[cfg(windows)]
    if args.len() >= 2 && args[1] == "--service-status" {
        match service::query_service_status() {
            service::ServiceStatus::Running => println!("RUNNING"),
            service::ServiceStatus::Stopped => println!("STOPPED"),
            service::ServiceStatus::NotInstalled => println!("NOT INSTALLED"),
        }
        return;
    }

    if args.len() >= 2 && args[1] == "--update-check" {
        let host = args.get(2).map(|s| s.as_str());
        match updater::check_for_updates(host) {
            Ok(status) => match status {
                updater::UpdateStatus::UpToDate { current, latest } => {
                    println!("Up to date: {current} (latest: {latest})");
                }
                updater::UpdateStatus::UpdateAvailable {
                    current,
                    latest,
                    manifest,
                } => {
                    println!("Update available: {current} -> {latest}");
                    if let Some(ref notes) = manifest.release_notes {
                        println!("Notes: {notes}");
                    }
                }
            },
            Err(e) => eprintln!("Update check failed: {e}"),
        }
        return;
    }

    if args.len() >= 2 && args[1] == "--update-apply" {
        let host = args.get(2).map(|s| s.as_str());
        println!("Checking for updates...");
        match updater::check_for_updates(host) {
            Ok(updater::UpdateStatus::UpdateAvailable { manifest, .. }) => {
                println!("Downloading update v{}...", manifest.version);
                match updater::download_update(&manifest, host) {
                    Ok(temp_path) => {
                        println!("Applying update...");
                        if let Err(e) = updater::apply_update(&temp_path) {
                            eprintln!("Failed to apply update: {e}");
                        }
                    }
                    Err(e) => eprintln!("Download failed: {e}"),
                }
            }
            Ok(updater::UpdateStatus::UpToDate { .. }) => {
                println!("Already up to date.");
            }
            Err(e) => eprintln!("Update check failed: {e}"),
        }
        return;
    }

    println!("saferunnet bootstrap ok");
}

fn run_daemon(config_path: &Path) {
    let config = load_from_path(config_path).expect("load config");
    let config_dir = config_path.parent().unwrap_or_else(|| Path::new("."));
    let data_dir = resolve_data_dir(config_dir, &config.router.data_dir);
    let keyfile = resolve_keyfile_path(&data_dir, config.network.keyfile.as_deref());

    if let Some(parent) = keyfile.parent() {
        std::fs::create_dir_all(parent).expect("create parent dirs for identity key");
    }

    let rt = tokio::runtime::Runtime::new().expect("create tokio runtime");

    let mut kernel = AppKernel::new();
    kernel.register(Box::new(IdentityModule::from_runtime_settings(
        config.router.nickname.clone(),
        keyfile.clone(),
    )));
    kernel.register(Box::new(LinkMessageModule::new()));
    kernel.register(Box::new(LinkSessionStateModule::default()));
    kernel.register(Box::new(PathManagerModule::new()));
    kernel.register(Box::new(DnsResolverModule::new()));
    kernel.register(Box::new(SessionCoordinatorModule::new()));

    kernel.start().expect("start kernel");
    let node_id = kernel
        .services()
        .get::<Arc<NodeIdentity>>()
        .expect("missing identity service")
        .clone();
    let local_key = node_id.public_key.clone();

    let bind_port = config.router.bind_port;
    let bind_addr: SocketAddr = format!("0.0.0.0:{bind_port}")
        .parse()
        .expect("parse bind address");
    let transport = rt
        .block_on(async { UdpTransport::bind(bind_addr).await })
        .expect("bind UDP transport");
    let transport = Arc::new(transport);

    tracing::info!(%bind_addr, "UDP transport bound");

    let bootstrap_addrs: Vec<SocketAddr> = config
        .network
        .bootstrap_routers
        .iter()
        .filter_map(|entry| parse_bootstrap_addr(entry))
        .collect();

    tracing::info!(
        bootstrap_count = bootstrap_addrs.len(),
        "DHT bootstrap routers loaded"
    );

    let dht = Arc::new(NetworkDht::new(
        local_key,
        transport.clone(),
        bootstrap_addrs,
    ));

    let dht_bg = dht.clone();
    rt.spawn(async move {
        if let Err(e) = dht_bg.bootstrap().await {
            tracing::error!(error = %e, "DHT bootstrap failed");
        } else {
            tracing::info!("DHT bootstrap complete");
        }
    });

    if let Some(ref ifaddr) = config.network.ifaddr {
        #[cfg(windows)]
        {
            let tun_ip = ifaddr.split('/').next().unwrap_or("10.0.0.1");
            match WinTunDevice::create("Saferunnet", tun_ip, 1500) {
                Ok(tun) => {
                    tracing::info!(%tun_ip, mtu = tun.mtu(), "TUN device created");
                    let forwarder = Arc::new(OnionForwarder::new());
                    let dht_tun = dht.clone();
                    let dns_client: Arc<dyn DhtClient> = dht_tun.clone();
                    let fwd_clone = forwarder.clone();
                    let transport_tun = transport.clone();
                    let rt_handle = rt.handle().clone();
                    let session_nonce = make_session_nonce();
                    rt.spawn_blocking(move || {
                        run_tun_loop(
                            tun,
                            dns_client,
                            fwd_clone,
                            transport_tun,
                            rt_handle,
                            session_nonce,
                        )
                    });
                }
                Err(e) => {
                    tracing::warn!(error = %e, "failed to create TUN device");
                }
            }
        }
        #[cfg(not(windows))]
        {
            tracing::info!("TUN device not supported on this platform");
        }
    }

    let rpc_port = config.router.rpc_port;
    let rpc_addr: SocketAddr = format!("127.0.0.1:{rpc_port}")
        .parse()
        .expect("parse RPC address");
    let dht_rpc = dht.clone();
    let rpc_server = RpcServer::new(rpc_addr)
        .with_node_state(|| "running".into())
        .with_peer_count(move || dht_rpc.peer_count());

    rt.spawn(async move {
        if let Err(e) = rpc_server.serve().await {
            tracing::error!(error = %e, "RPC server error");
        }
    });

    tracing::info!(%rpc_addr, "RPC admin server started");
    tracing::info!("saferunnet daemon running — press Ctrl+C to stop");

    rt.block_on(async {
        tokio::signal::ctrl_c()
            .await
            .expect("install ctrl-c handler");
        tracing::info!("shutdown signal received");
    });

    kernel.stop().expect("stop kernel");
    tracing::info!("saferunnet daemon stopped");
}

fn run_bootstrap(config_path: &Path) {
    let config = load_from_path(config_path).expect("load config");
    let config_dir = config_path.parent().unwrap_or_else(|| Path::new("."));
    let data_dir = resolve_data_dir(config_dir, &config.router.data_dir);
    let keyfile = resolve_keyfile_path(&data_dir, config.network.keyfile.as_deref());
    if let Some(parent) = keyfile.parent() {
        std::fs::create_dir_all(parent).expect("create identity directory");
    }

    let mut kernel = AppKernel::new();
    kernel.register(Box::new(IdentityModule::from_runtime_settings(
        config.router.nickname,
        keyfile,
    )));
    kernel.start().expect("start kernel");
    if !kernel.services().contains_key(NODE_IDENTITY_SERVICE_KEY) {
        panic!("missing identity service");
    }
    println!("identity bootstrap ok");
}

fn run_service_check() {
    let tmp_dir = std::env::temp_dir().join(format!("saferunnet-svc-{}", std::process::id()));
    std::fs::create_dir_all(&tmp_dir).expect("create temp dir");
    let keyfile = tmp_dir.join("identity.key");

    let identity = IdentityModule::new(
        FileIdentityRepository::new(keyfile),
        IdentitySpec {
            nickname: "svc-check".to_string(),
            algorithm: KeyAlgorithm::Ed25519,
        },
        Box::new(Ed25519KeyGenerator::new()),
    );

    let mut kernel = AppKernel::new();
    kernel.register(Box::new(identity));
    kernel.register(Box::new(LinkMessageModule::new()));
    kernel.register(Box::new(LinkSessionStateModule::default()));
    kernel.register(Box::new(PathManagerModule::new()));
    kernel.register(Box::new(DnsResolverModule::new()));
    kernel.register(Box::new(SessionCoordinatorModule::new()));

    kernel.start().expect("start kernel");
    println!("services ok");
    kernel.stop().expect("stop kernel");
    println!("shutdown ok");
}

fn resolve_data_dir(config_dir: &Path, data_dir: &str) -> PathBuf {
    let data_dir = Path::new(data_dir);
    if data_dir.is_absolute() {
        data_dir.to_path_buf()
    } else {
        config_dir.join(data_dir)
    }
}

fn resolve_keyfile_path(data_dir: &Path, keyfile: Option<&str>) -> PathBuf {
    match keyfile {
        Some(keyfile) => {
            let keyfile = Path::new(keyfile);
            if keyfile.is_absolute() {
                keyfile.to_path_buf()
            } else {
                data_dir.join(keyfile)
            }
        }
        None => data_dir.join(DEFAULT_KEYFILE_NAME),
    }
}

fn parse_bootstrap_addr(entry: &str) -> Option<SocketAddr> {
    let (_pubkey, addr_part) = entry.split_once('@')?;
    addr_part.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use saferunnet_crypto::KeyAlgorithm;
    use saferunnet_dns::resolver::{DhtClient, DhtIntroResult};

    const DNS_START: usize = 20 + 8;

    struct MockDht {
        results: Vec<DhtIntroResult>,
    }
    impl DhtClient for MockDht {
        fn lookup_intro_set(&self, _target: &saferunnet_crypto::PublicKey) -> Vec<DhtIntroResult> {
            self.results.clone()
        }
    }

    fn make_intro_result(tail: [u8; 3]) -> DhtIntroResult {
        let mut bytes = [0u8; 32];
        bytes[29] = tail[0];
        bytes[30] = tail[1];
        bytes[31] = tail[2];
        DhtIntroResult {
            public_key: saferunnet_crypto::PublicKey::from_bytes(KeyAlgorithm::Ed25519, bytes),
            addresses: vec![],
        }
    }

    fn build_test_dns_packet(query_name: &str, dns_id: u16) -> Vec<u8> {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00,
        ]);
        pkt.extend_from_slice(&[10, 0, 0, 2]);
        pkt.extend_from_slice(&[10, 0, 0, 1]);
        pkt.push(0x30);
        pkt.push(0x39);
        pkt.push(0x00);
        pkt.push(0x35);
        let udp_len_pos = pkt.len();
        pkt.push(0x00);
        pkt.push(0x00);
        pkt.push(0x00);
        pkt.push(0x00);
        pkt.push((dns_id >> 8) as u8);
        pkt.push(dns_id as u8);
        pkt.push(0x01);
        pkt.push(0x00);
        pkt.push(0x00);
        pkt.push(0x01);
        pkt.push(0x00);
        pkt.push(0x00);
        pkt.push(0x00);
        pkt.push(0x00);
        pkt.push(0x00);
        pkt.push(0x00);
        for label in query_name.split('.') {
            pkt.push(label.len() as u8);
            pkt.extend_from_slice(label.as_bytes());
        }
        pkt.push(0x00);
        pkt.push(0x00);
        pkt.push(0x01);
        pkt.push(0x00);
        pkt.push(0x01);
        let ip_len = pkt.len() as u16;
        pkt[2] = (ip_len >> 8) as u8;
        pkt[3] = ip_len as u8;
        let udp_len = (pkt.len() - 20) as u16;
        pkt[udp_len_pos] = (udp_len >> 8) as u8;
        pkt[udp_len_pos + 1] = udp_len as u8;
        pkt
    }

    // ─── ip_checksum ───────────────────────────────────────────

    #[test]
    fn empty_header_returns_ffff() {
        assert_eq!(ip_checksum(&[]), 0xFFFF);
    }

    #[test]
    fn known_vector() {
        let header = [
            0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00,
        ];
        let csum = ip_checksum(&header);
        assert!(csum > 0);
    }

    // ─── parse_dns_header ──────────────────────────────────────

    #[test]
    fn valid_packet() {
        let pkt = build_test_dns_packet("test.loki", 0x1234);
        let result = parse_dns_header(&pkt);
        assert!(result.is_some());
        let (dns_start, id, _flags) = result.unwrap();
        assert_eq!(dns_start, DNS_START);
        assert_eq!(id, 0x1234);
    }

    #[test]
    fn too_short_returns_none() {
        assert!(parse_dns_header(&[0x45]).is_none());
    }

    #[test]
    fn non_ipv4_returns_none() {
        let mut pkt = build_test_dns_packet("test.loki", 0);
        pkt[0] = 0x60;
        assert!(parse_dns_header(&pkt).is_none());
    }

    // ─── parse_dns_question ────────────────────────────────────

    #[test]
    fn example_com() {
        let pkt = build_test_dns_packet("example.com", 0xAABB);
        let (dns_start, _, _) = parse_dns_header(&pkt).unwrap();
        let result = parse_dns_question(&pkt, dns_start + 12);
        assert!(result.is_some());
        let (name, qtype, qclass, _) = result.unwrap();
        assert_eq!(name, "example.com");
        assert_eq!(qtype, 1);
        assert_eq!(qclass, 1);
    }

    #[test]
    fn invalid_start_returns_none() {
        let pkt = build_test_dns_packet("test.loki", 0);
        assert!(parse_dns_question(&pkt, 9999).is_none());
    }

    // ─── decode_dns_name_full ──────────────────────────────────

    #[test]
    fn single_label_name() {
        let wire = b"\x04test\x00";
        let (name, pos) = decode_dns_name_full(wire, 0).unwrap();
        assert_eq!(name, "test");
        assert_eq!(pos, 6);
    }

    #[test]
    fn multi_label_name() {
        let wire = b"\x03foo\x04loki\x00";
        let (name, pos) = decode_dns_name_full(wire, 0).unwrap();
        assert_eq!(name, "foo.loki");
        assert_eq!(pos, 10);
    }

    #[test]
    fn compression_pointer() {
        // Question 1: "example" (offset 12), Question 2: pointer to "example" at offset 25
        let mut pkt = build_test_dns_packet("example.com", 0x1111);
        // Append a second question with a compression pointer
        let q_end = pkt.len();
        pkt.push(0xC0);
        pkt.push(0x28); // pointer to DNS offset 40 (DNS_START + 12)
        pkt.push(0x00);
        pkt.push(0x01); // QTYPE=A
        pkt.push(0x00);
        pkt.push(0x01); // QCLASS=IN
        let (name, _) = decode_dns_name_full(&pkt, q_end).unwrap();
        assert_eq!(name, "example.com");
    }

    // ─── build_dns_a_response ──────────────────────────────────

    #[test]
    fn build_a_response_flags() {
        let pkt = build_test_dns_packet("test.loki", 0xBEEF);
        let dns_start = DNS_START;
        let resp = build_dns_a_response(&pkt, dns_start, "test.loki", [10, 0, 0, 1]);
        let flags = u16::from_be_bytes([resp[dns_start + 2], resp[dns_start + 3]]);
        assert_eq!(flags & 0x8000, 0x8000, "QR should be 1");
        assert_eq!(flags & 0x0100, 0x0100, "RD should be 1");
        assert_eq!(flags & 0x0080, 0x0080, "RA should be 1");
    }

    #[test]
    fn build_a_response_ancount_one() {
        let pkt = build_test_dns_packet("test.loki", 0xCAFE);
        let dns_start = DNS_START;
        let resp = build_dns_a_response(&pkt, dns_start, "test.loki", [10, 0, 0, 1]);
        let ancount = u16::from_be_bytes([resp[dns_start + 6], resp[dns_start + 7]]);
        assert_eq!(ancount, 1);
    }

    #[test]
    fn build_a_response_answer_contains_ip() {
        let pkt = build_test_dns_packet("test.loki", 0xDEAD);
        let dns_start = DNS_START;
        let target_ip = [10, 0, 0, 1];
        let resp = build_dns_a_response(&pkt, dns_start, "test.loki", target_ip);
        let ip_in_resp = &resp[resp.len() - 4..];
        assert_eq!(ip_in_resp, &target_ip);
    }

    #[test]
    fn build_a_response_swaps_ip_src_dst() {
        let pkt = build_test_dns_packet("test.loki", 0xABCD);
        let dns_start = DNS_START;
        let resp = build_dns_a_response(&pkt, dns_start, "test.loki", [10, 0, 0, 1]);
        assert_eq!(&resp[12..16], &[10, 0, 0, 1]);
        assert_eq!(&resp[16..20], &[10, 0, 0, 2]);
    }

    #[test]
    fn build_a_response_swaps_udp_ports() {
        let pkt = build_test_dns_packet("test.loki", 0xEF01);
        let ip_hdr_len = 20;
        let dns_start = DNS_START;
        let resp = build_dns_a_response(&pkt, dns_start, "test.loki", [10, 0, 0, 1]);
        let udp_start = ip_hdr_len;
        let resp_src = u16::from_be_bytes([resp[udp_start], resp[udp_start + 1]]);
        let resp_dst = u16::from_be_bytes([resp[udp_start + 2], resp[udp_start + 3]]);
        assert_eq!(resp_src, 53);
        assert_eq!(resp_dst, 12345);
    }

    // ─── build_dns_error_response ──────────────────────────────

    #[test]
    fn build_error_response_has_rcode_nxdomain() {
        let pkt = build_test_dns_packet("bogus.loki", 0x5555);
        let dns_start = DNS_START;
        let resp = build_dns_error_response(&pkt, dns_start, "bogus.loki");
        let flags = u16::from_be_bytes([resp[dns_start + 2], resp[dns_start + 3]]);
        assert_eq!(flags & 0x000F, 3, "RCODE should be 3 (NXDOMAIN)");
    }

    #[test]
    fn build_error_response_has_qr_set() {
        let pkt = build_test_dns_packet("bogus.loki", 0x6666);
        let dns_start = DNS_START;
        let resp = build_dns_error_response(&pkt, dns_start, "bogus.loki");
        let flags = u16::from_be_bytes([resp[dns_start + 2], resp[dns_start + 3]]);
        assert_eq!(flags & 0x8000, 0x8000, "QR should be 1");
    }

    // ─── handle_dns_query ──────────────────────────────────────

    #[test]
    fn handle_dns_query_non_dns_returns_none() {
        let non_dns = vec![0x60, 0x00, 0x00, 0x00];
        let dht = MockDht { results: vec![] };
        assert!(handle_dns_query(&non_dns, &dht).is_none());
    }

    #[test]
    fn handle_dns_query_non_loki_returns_none() {
        let pkt = build_test_dns_packet("example.com", 0x7777);
        let dht = MockDht { results: vec![] };
        assert!(handle_dns_query(&pkt, &dht).is_none());
    }

    #[test]
    fn handle_dns_query_loki_non_a_query_returns_none() {
        let mut pkt = build_test_dns_packet("node.loki", 0xAAAA);
        let qtype_pos = pkt.len() - 4;
        pkt[qtype_pos] = 0x00;
        pkt[qtype_pos + 1] = 0x0F;
        let dht = MockDht {
            results: vec![make_intro_result([0, 0, 55])],
        };
        assert!(handle_dns_query(&pkt, &dht).is_none());
    }

    #[test]
    fn handle_dns_query_loki_with_results_returns_response() {
        let pkt = build_test_dns_packet("node.loki", 0x8888);
        let dht = MockDht {
            results: vec![make_intro_result([0, 0, 55])],
        };
        let result = handle_dns_query(&pkt, &dht);
        assert!(result.is_some());
        let resp = result.unwrap();
        let dns_start = DNS_START;
        let flags = u16::from_be_bytes([resp[dns_start + 2], resp[dns_start + 3]]);
        assert_eq!(flags & 0x8000, 0x8000);
        assert_eq!(flags & 0x000F, 0);
    }

    #[test]
    fn handle_dns_query_loki_empty_results_returns_nxdomain() {
        let pkt = build_test_dns_packet("missing.loki", 0x9999);
        let dht = MockDht { results: vec![] };
        let result = handle_dns_query(&pkt, &dht);
        assert!(result.is_some());
        let resp = result.unwrap();
        let dns_start = DNS_START;
        let flags = u16::from_be_bytes([resp[dns_start + 2], resp[dns_start + 3]]);
        assert_eq!(flags & 0x8000, 0x8000);
        assert_eq!(flags & 0x000F, 3);
    }

    // ─── session_nonce ─────────────────────────────────────────

    #[test]
    fn session_nonce_is_not_zero() {
        let nonce = make_session_nonce();
        assert_ne!(nonce, [0u8; 32]);
    }

    // ─── Windows service ───────────────────────────────────────

    #[test]
    #[cfg(windows)]
    fn service_status_enum_debug() {
        let status = super::service::ServiceStatus::Running;
        let debug_str = format!("{:?}", status);
        assert!(debug_str.contains("Running"));
    }

    #[test]
    #[cfg(windows)]
    fn install_service_args_well_formed() {
        let bin_path = r"C:\saferunnet\saferunnet.exe";
        let config_path = "saferunnet.ini";
        let args = super::service::build_install_args(bin_path, config_path);
        assert_eq!(args[0], "create");
        assert_eq!(args[1], "saferunnet");
        assert!(args[2].starts_with("binPath= "));
        assert!(args[2].contains(bin_path));
        assert!(args[2].contains(config_path));
        assert_eq!(args[3], "start=");
        assert_eq!(args[4], "auto");
        assert_eq!(args[5], "DisplayName=");
        assert_eq!(args[6], "Saferunnet LLARP Service");
    }
}
