//! Android VPN tunnel — runs on top of a TUN fd created by VpnService.Builder and a UDP
//! socket created here and exempted via VpnService.protect(int).
//!
//! Wire protocol is byte-for-byte identical to AivpnCrypto.kt so that both can talk to the
//! same Rust server without any server-side changes.

use std::net::{SocketAddr, SocketAddrV4};
use std::os::fd::OwnedFd;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use jni::objects::GlobalRef;
use jni::JavaVM;
use tokio::io::unix::AsyncFd;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time;

use aivpn_common::client_wire::{
    build_inner_packet, build_zero_mdh_packet, decode_packet_with_mdh_len,
    obfuscate_client_eph_pub, process_server_hello_with_mdh_len, RecvWindow, DEFAULT_ZERO_MDH,
};
use aivpn_common::crypto::{
    self, derive_session_keys, KeyPair, SessionKeys,
};
use aivpn_common::error::{Error, Result};
use aivpn_common::mask::MaskProfile;
use aivpn_common::protocol::{ControlPayload, InnerType};
use aivpn_common::upload_pipeline::{self, PacketEncryptor, UploadConfig};

// ──────────── Constants ────────────

const BUF_SIZE: usize = 1500;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);  // closer to WireGuard roaming behavior
const RX_SILENCE: Duration = Duration::from_secs(45);          // fail fast on stale/mobile path
const RX_CHECK_INTERVAL: Duration = Duration::from_secs(2);
const TX_WITHOUT_RX_TIMEOUT: Duration = Duration::from_secs(12);
const TX_WITHOUT_RX_MIN_BYTES: u64 = 16 * 1024;
const REKEY_INTERVAL: Duration = Duration::from_secs(1800); // 30 min
const CHANNEL_SIZE: usize = 8192;

// ──────────── Session runtime (read by JNI exports in lib.rs) ────────────

pub struct SessionRuntime {
    udp_fd: AtomicI32,
    upload_bytes: AtomicU64,
    download_bytes: AtomicU64,
}

#[derive(Debug, Clone)]
struct TelemetrySnapshot {
    packet_loss_bps: u16,
    rtt_ms: u16,
    jitter_ms: u16,
    buffer_pct: u8,
}

struct TelemetryState {
    pending_keepalive_sent_at: Option<Instant>,
    keepalive_sent: u32,
    keepalive_acked: u32,
    keepalive_lost: u32,
    ewma_rtt_ms: f64,
    ewma_jitter_ms: f64,
}

impl TelemetryState {
    fn new() -> Self {
        Self {
            pending_keepalive_sent_at: None,
            keepalive_sent: 0,
            keepalive_acked: 0,
            keepalive_lost: 0,
            ewma_rtt_ms: 0.0,
            ewma_jitter_ms: 0.0,
        }
    }

    fn on_keepalive_sent(&mut self) {
        let now = Instant::now();
        if let Some(previous) = self.pending_keepalive_sent_at {
            if now.duration_since(previous) > Duration::from_secs(30) {
                self.keepalive_lost = self.keepalive_lost.saturating_add(1);
            }
        }
        self.pending_keepalive_sent_at = Some(now);
        self.keepalive_sent = self.keepalive_sent.saturating_add(1);
    }

    fn on_keepalive_ack(&mut self) {
        let Some(sent_at) = self.pending_keepalive_sent_at.take() else {
            return;
        };
        let sample_rtt_ms = sent_at.elapsed().as_secs_f64() * 1000.0;
        if self.ewma_rtt_ms == 0.0 {
            self.ewma_rtt_ms = sample_rtt_ms;
            self.ewma_jitter_ms = 0.0;
        } else {
            let delta = (sample_rtt_ms - self.ewma_rtt_ms).abs();
            self.ewma_jitter_ms = self.ewma_jitter_ms * 0.75 + delta * 0.25;
            self.ewma_rtt_ms = self.ewma_rtt_ms * 0.875 + sample_rtt_ms * 0.125;
        }
        self.keepalive_acked = self.keepalive_acked.saturating_add(1);
    }

    fn snapshot(&self) -> TelemetrySnapshot {
        let sent = self.keepalive_sent.max(1) as f64;
        let loss_ratio = (self.keepalive_lost as f64 / sent).clamp(0.0, 1.0);
        TelemetrySnapshot {
            packet_loss_bps: (loss_ratio * 10_000.0).round() as u16,
            rtt_ms: self.ewma_rtt_ms.clamp(0.0, u16::MAX as f64).round() as u16,
            jitter_ms: self.ewma_jitter_ms.clamp(0.0, u16::MAX as f64).round() as u16,
            buffer_pct: 0,
        }
    }
}

impl SessionRuntime {
    fn new() -> Self {
        Self {
            udp_fd: AtomicI32::new(-1),
            upload_bytes: AtomicU64::new(0),
            download_bytes: AtomicU64::new(0),
        }
    }
}

static ACTIVE_SESSION: Mutex<Option<Arc<SessionRuntime>>> = Mutex::new(None);

struct ActiveSessionGuard {
    session: Arc<SessionRuntime>,
}

impl Drop for ActiveSessionGuard {
    fn drop(&mut self) {
        self.session.udp_fd.store(-1, Ordering::SeqCst);
        if let Ok(mut guard) = ACTIVE_SESSION.lock() {
            if let Some(current) = guard.as_ref() {
                if Arc::ptr_eq(current, &self.session) {
                    *guard = None;
                }
            }
        }
    }
}

fn activate_session(session: Arc<SessionRuntime>) -> Result<ActiveSessionGuard> {
    let mut guard = ACTIVE_SESSION
        .lock()
        .map_err(|_| Error::Session("Active session lock poisoned".into()))?;

    if guard.is_some() {
        return Err(Error::Session(
            "Another Android tunnel session is already active".into(),
        ));
    }

    *guard = Some(session.clone());
    Ok(ActiveSessionGuard { session })
}

pub fn stop_active_tunnel() {
    let fd = ACTIVE_SESSION
        .lock()
        .ok()
        .and_then(|guard| guard.as_ref().map(|s| s.udp_fd.swap(-1, Ordering::SeqCst)))
        .unwrap_or(-1);

    if fd >= 0 {
        unsafe {
            let _ = libc::shutdown(fd, libc::SHUT_RDWR);
        };
    }
}

pub fn get_active_upload_bytes() -> u64 {
    ACTIVE_SESSION
        .lock()
        .ok()
        .and_then(|guard| guard.as_ref().map(|s| s.upload_bytes.load(Ordering::Relaxed)))
        .unwrap_or(0)
}

pub fn get_active_download_bytes() -> u64 {
    ACTIVE_SESSION
        .lock()
        .ok()
        .and_then(|guard| guard.as_ref().map(|s| s.download_bytes.load(Ordering::Relaxed)))
        .unwrap_or(0)
}

// ──────────── Entry point ────────────

/// Blocking async function that runs the whole tunnel session.
/// All errors cause the Kotlin reconnect loop to kick in.
pub async fn run_tunnel_android(
    vm: JavaVM,
    vpn_service: GlobalRef,
    tun_fd_int: RawFd,
    server_host: String,
    server_port: u16,
    server_key: [u8; 32],
    psk: [u8; 32],
    server_signing_pub: [u8; 32],
) -> Result<()> {
    let session = Arc::new(SessionRuntime::new());
    let _active_session_guard = activate_session(session.clone())?;

    // ── 1. Ephemeral keypair + initial session keys (Zero-RTT like existing Kotlin) ──
    let keypair = KeyPair::generate();
    let dh = keypair.compute_shared(&server_key)?;
    let mut keys = derive_session_keys(&dh, Some(&psk), &keypair.public_key_bytes());

    // ── 2. Create and protect UDP socket ──
    // Resolve host (async DNS so we don't block the tokio thread).
    let dest_str = format!("{}:{}", server_host, server_port);
    let dest: SocketAddr = tokio::net::lookup_host(&dest_str)
        .await
        .map_err(|e| Error::Io(e))?
        .find(|a| a.is_ipv4())
        .ok_or_else(|| Error::Session("Cannot resolve server host to IPv4".into()))?;

    let raw_udp_fd = create_protected_udp_socket(&vm, &vpn_service, dest, &session)?;

    // ── 3. Set TUN fd to non-blocking for AsyncFd ──
    unsafe { libc::fcntl(tun_fd_int, libc::F_SETFL, libc::O_NONBLOCK) };
    // SAFETY: we own this fd (Kotlin called detachFd()).
    let owned_tun = unsafe { OwnedFd::from_raw_fd(tun_fd_int) };
    let tun = AsyncFd::new(owned_tun)?;

    // Convert the raw UDP fd to a tokio UdpSocket (already connected to server).
    let std_udp = unsafe { std::net::UdpSocket::from_raw_fd(raw_udp_fd) };
    std_udp.set_nonblocking(true)?;
    let udp = Arc::new(UdpSocket::from_std(std_udp)?);

    // ── 4. Send init handshake (Control/Keepalive + obfuscated eph_pub) ──
    let mut send_counter: u64 = 0;
    let mut send_seq: u16 = 0;
    {
        let keepalive = ControlPayload::Keepalive.encode()?;
        let inner = build_inner_packet(InnerType::Control, send_seq, &keepalive);
        send_seq = send_seq.wrapping_add(1);
        let obf_pub = obfuscate_client_eph_pub(&keypair, &server_key);
        let pkt = build_zero_mdh_packet(&keys, &mut send_counter, &inner, Some(&obf_pub))?;
        udp.send(&pkt).await?;
    }

    // ── 5. Wait for ServerHello with timeout ──
    let mut recv_buf = vec![0u8; BUF_SIZE];
    let n = time::timeout(HANDSHAKE_TIMEOUT, udp.recv(&mut recv_buf))
        .await
        .map_err(|_| Error::Session("Handshake timeout (10 s)".into()))??;

    let mut recv_win = RecvWindow::new();
    process_server_hello_with_mdh_len(
        &recv_buf[..n],
        &mut keys,
        &keypair,
        &mut recv_win,
        &mut send_counter,
        DEFAULT_ZERO_MDH.len(),
        &server_signing_pub,
    )?;
    let mut transition_recv_keys: Option<SessionKeys> = Some(derive_session_keys(
        &dh,
        Some(&psk),
        &keypair.public_key_bytes(),
    ));
    let mut transition_recv_win = std::mem::take(&mut recv_win);
    notify_tunnel_ready(&vm, &vpn_service, &server_host);
    log::info!("aivpn: handshake + PFS ratchet complete");

    // ── 6. Main forwarding loop ──
    let mut udp_buf = vec![0u8; BUF_SIZE];
    let mut last_rx = Instant::now();
    let mut upload_at_last_rx = session.upload_bytes.load(Ordering::Relaxed);

    // Split upload into a dedicated pipeline:
    // TUN reader task -> channel -> UDP sender/encrypt task.
    let (tun_tx, mut tun_rx) = mpsc::channel::<Vec<u8>>(CHANNEL_SIZE);
    let (control_tx, mut control_rx) = mpsc::channel::<ControlPayload>(64);
    let (err_tx, mut err_rx) = mpsc::channel::<String>(16);
    let tun_err_tx = err_tx.clone();
    let sender_err_tx = err_tx.clone();

    let read_fd = unsafe { libc::dup(tun.as_raw_fd()) };
    if read_fd < 0 {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }
    let owned_tun_read = unsafe { OwnedFd::from_raw_fd(read_fd) };
    let tun_read = AsyncFd::new(owned_tun_read)?;

    let tun_reader_task = tokio::spawn(async move {
        let mut tun_buf = vec![0u8; BUF_SIZE];
        loop {
            match tun_async_read(&tun_read, &mut tun_buf).await {
                Ok(n) => {
                    if n == 0 {
                        continue;
                    }
                    if tun_buf[0] >> 4 != 4 {
                        continue;
                    }
                    if tun_tx.send(tun_buf[..n].to_vec()).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    let _ = tun_err_tx.send(format!("TUN read failed: {e}")).await;
                    break;
                }
            }
        }
    });

    let udp_tx = udp.clone();
    struct AndroidCryptoState {
        keys: SessionKeys,
        counter: u64,
        seq: u16,
    }
    let upload_state = Arc::new(Mutex::new(AndroidCryptoState {
        keys: keys.clone(),
        counter: send_counter,
        seq: send_seq,
    }));
    let telemetry_state = Arc::new(Mutex::new(TelemetryState::new()));
    let upload_state_for_sender = upload_state.clone();
    let telemetry_state_for_sender = telemetry_state.clone();
    let session_for_upload = session.clone();
    let upload_sender_task = tokio::spawn(async move {
        // Wrap zero-MDH encryption with UPLOAD_BYTES tracking.
        struct AndroidEncryptor {
            upload_state: Arc<Mutex<AndroidCryptoState>>,
            session: Arc<SessionRuntime>,
            telemetry_state: Arc<Mutex<TelemetryState>>,
        }

        impl PacketEncryptor for AndroidEncryptor {
            fn encrypt_data(&mut self, payload: &[u8]) -> aivpn_common::error::Result<Vec<u8>> {
                let mut state = self.upload_state.lock().expect("android upload state poisoned");
                let inner = build_inner_packet(InnerType::Data, state.seq, payload);
                state.seq = state.seq.wrapping_add(1);
                let keys = state.keys.clone();
                build_zero_mdh_packet(&keys, &mut state.counter, &inner, None)
            }
            fn encrypt_keepalive(&mut self) -> aivpn_common::error::Result<Vec<u8>> {
                self.telemetry_state
                    .lock()
                    .expect("android telemetry state poisoned")
                    .on_keepalive_sent();
                self.encrypt_control(&ControlPayload::Keepalive)
            }
            fn encrypt_control(&mut self, control: &ControlPayload) -> aivpn_common::error::Result<Vec<u8>> {
                let mut state = self.upload_state.lock().expect("android upload state poisoned");
                let encoded = control.encode()?;
                let inner = build_inner_packet(InnerType::Control, state.seq, &encoded);
                state.seq = state.seq.wrapping_add(1);
                let keys = state.keys.clone();
                build_zero_mdh_packet(&keys, &mut state.counter, &inner, None)
            }
            fn on_data_sent(&mut self, payload_len: usize) {
                self.session
                    .upload_bytes
                    .fetch_add(payload_len as u64, Ordering::Relaxed);
            }
        }

        let mut enc = AndroidEncryptor {
            upload_state: upload_state_for_sender,
            session: session_for_upload,
            telemetry_state: telemetry_state_for_sender,
        };
        let config = UploadConfig {
            keepalive_interval: KEEPALIVE_INTERVAL,
            ..Default::default()
        };

        if let Err(e) = upload_pipeline::run_upload_loop(&mut tun_rx, &mut control_rx, &udp_tx, &mut enc, &config).await {
            let _ = sender_err_tx.send(format!("Upload pipeline: {e}")).await;
        }
    });
    let mut rekey_tick = time::interval(REKEY_INTERVAL);
    rekey_tick.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
    rekey_tick.tick().await;
    let mut pending_ratchet_keypair: Option<KeyPair> = None;

    // Periodic check for RX silence — uses a proper Interval so it's not
    // recreated every select! iteration (which would reset the timer).
    let mut rx_check = time::interval(RX_CHECK_INTERVAL);
    rx_check.set_missed_tick_behavior(time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            biased;

            // ── Rekey ──
            _ = rekey_tick.tick() => {
                if pending_ratchet_keypair.is_none() {
                    let ratchet_keypair = KeyPair::generate();
                    let control = ControlPayload::KeyRotate {
                        new_eph_pub: ratchet_keypair.public_key_bytes(),
                    };
                    pending_ratchet_keypair = Some(ratchet_keypair);
                    if control_tx.send(control).await.is_err() {
                        tun_reader_task.abort();
                        upload_sender_task.abort();
                        return Err(Error::Channel("control upload channel closed".into()));
                    }
                    log::info!("aivpn: key rotation requested");
                } else {
                    log::warn!("aivpn: key rotation still pending");
                }
            }

            // ── UDP → TUN (inbound from server) ──
            r = udp.recv(&mut udp_buf) => {
                let n = r?;
                last_rx = Instant::now();
                upload_at_last_rx = session.upload_bytes.load(Ordering::Relaxed);
                let decoded = match decode_packet_with_mdh_len(
                    &udp_buf[..n],
                    &keys,
                    &mut recv_win,
                    DEFAULT_ZERO_MDH.len(),
                ) {
                    Ok(decoded) => {
                        if transition_recv_keys.take().is_some() {
                            transition_recv_win.reset();
                            log::info!("aivpn: receive ratchet complete");
                        }
                        Some(decoded)
                    }
                    Err(_) => {
                        if let Some(previous_keys) = transition_recv_keys.as_ref() {
                            decode_packet_with_mdh_len(
                                &udp_buf[..n],
                                previous_keys,
                                &mut transition_recv_win,
                                DEFAULT_ZERO_MDH.len(),
                            ).ok()
                        } else {
                            None
                        }
                    }
                };

                if let Some(decoded) = decoded {
                    if decoded.header.inner_type == InnerType::Data && !decoded.payload.is_empty() {
                        tun_async_write(&tun, &decoded.payload).await?;
                        session
                            .download_bytes
                            .fetch_add(decoded.payload.len() as u64, Ordering::Relaxed);
                    } else if decoded.header.inner_type == InnerType::Control {
                        match ControlPayload::decode(&decoded.payload)? {
                            ControlPayload::MaskUpdate { mask_data, signature } => {
                                crypto::verify_mask_update_signature(
                                    &server_signing_pub,
                                    &mask_data,
                                    &signature,
                                )?;
                                let new_mask: MaskProfile = rmp_serde::from_slice(&mask_data)
                                    .map_err(|e| Error::Serialization(format!("Invalid MaskUpdate payload: {e}")))?;
                                if new_mask.header_template.as_slice() == DEFAULT_ZERO_MDH {
                                    log::info!("aivpn: zero-MDH MaskUpdate verified for {}", new_mask.mask_id);
                                } else {
                                    log::warn!(
                                        "aivpn: verified MaskUpdate for {} but advanced masks are not applied on Android zero-MDH client yet",
                                        new_mask.mask_id
                                    );
                                }
                            }
                            ControlPayload::ServerHello { server_eph_pub, signature } => {
                                let ratchet_keypair = pending_ratchet_keypair
                                    .take()
                                    .ok_or_else(|| Error::Session("Unexpected ServerHello".into()))?;
                                crypto::verify_server_hello_signature(
                                    &server_signing_pub,
                                    &server_eph_pub,
                                    &ratchet_keypair.public_key_bytes(),
                                    &signature,
                                )?;
                                let dh2 = ratchet_keypair.compute_shared(&server_eph_pub)?;
                                let current_key = keys.session_key;
                                let ratcheted = derive_session_keys(
                                    &dh2,
                                    Some(&current_key),
                                    &ratchet_keypair.public_key_bytes(),
                                );
                                transition_recv_keys = Some(keys.clone());
                                transition_recv_win = std::mem::take(&mut recv_win);
                                keys = ratcheted.clone();
                                {
                                    let mut state = upload_state.lock().expect("android upload state poisoned");
                                    state.keys = ratcheted;
                                    state.counter = 0;
                                }
                                log::info!("aivpn: key rotation applied");
                            }
                            ControlPayload::Keepalive => {}
                            ControlPayload::TelemetryRequest { .. } => {
                                let snapshot = telemetry_state
                                    .lock()
                                    .expect("android telemetry state poisoned")
                                    .snapshot();
                                if control_tx
                                    .send(ControlPayload::TelemetryResponse {
                                        packet_loss: snapshot.packet_loss_bps,
                                        rtt_ms: snapshot.rtt_ms,
                                        jitter_ms: snapshot.jitter_ms,
                                        buffer_pct: snapshot.buffer_pct,
                                    })
                                    .await
                                    .is_err()
                                {
                                    tun_reader_task.abort();
                                    upload_sender_task.abort();
                                    return Err(Error::Channel("control upload channel closed".into()));
                                }
                            }
                            ControlPayload::ControlAck { ack_for_subtype, .. } => {
                                if ack_for_subtype == aivpn_common::protocol::ControlSubtype::Keepalive as u8 {
                                    telemetry_state
                                        .lock()
                                        .expect("android telemetry state poisoned")
                                        .on_keepalive_ack();
                                }
                            }
                            other => {
                                log::debug!("aivpn: control from server: {:?}", other);
                            }
                        }
                    }
                    // Any successfully decoded packet (including keepalive responses)
                    // proves the link is alive.
                }
            }

            maybe_err = err_rx.recv() => {
                if let Some(msg) = maybe_err {
                    tun_reader_task.abort();
                    upload_sender_task.abort();
                    return Err(Error::Session(msg));
                }
            }

            // ── RX silence detector (proper interval, not recreated each iteration) ──
            _ = rx_check.tick() => {
                let silence = last_rx.elapsed();
                let uploaded_total = session.upload_bytes.load(Ordering::Relaxed);
                let uploaded_since_rx = uploaded_total.saturating_sub(upload_at_last_rx);

                // Half-open path detector: TX is actively flowing, but no RX returns.
                // This catches "connected but dead" states faster after network switches.
                if silence > TX_WITHOUT_RX_TIMEOUT && uploaded_since_rx >= TX_WITHOUT_RX_MIN_BYTES {
                    tun_reader_task.abort();
                    upload_sender_task.abort();
                    return Err(Error::Session(
                        format!(
                            "TX without RX: {} bytes sent in {:?} since last RX — reconnecting",
                            uploaded_since_rx,
                            silence
                        )
                    ));
                }

                if silence > RX_SILENCE {
                    tun_reader_task.abort();
                    upload_sender_task.abort();
                    return Err(Error::Session(
                        format!("No RX for {:?} — reconnecting", silence)
                    ));
                }
            }
        }
    }
}

fn notify_tunnel_ready(vm: &JavaVM, vpn_service: &GlobalRef, host: &str) {
    let mut env = match vm.attach_current_thread() {
        Ok(env) => env,
        Err(e) => {
            log::warn!("aivpn: JNI attach failed for onTunnelReady callback: {e}");
            return;
        }
    };

    let host_j = match env.new_string(host) {
        Ok(s) => s,
        Err(e) => {
            log::warn!("aivpn: JNI new_string failed for onTunnelReady callback: {e}");
            return;
        }
    };

    let host_obj = jni::objects::JObject::from(host_j);

    if let Err(e) = env.call_method(
        vpn_service,
        "onTunnelReady",
        "(Ljava/lang/String;)V",
        &[jni::objects::JValue::Object(&host_obj)],
    ) {
        log::warn!("aivpn: onTunnelReady callback failed: {e}");
        return;
    }

    match env.exception_check() {
        Ok(true) => {
            let _ = env.exception_describe();
            let _ = env.exception_clear();
            log::warn!("aivpn: onTunnelReady callback threw Java exception");
        }
        Ok(false) => {}
        Err(e) => {
            log::warn!("aivpn: exception_check failed after onTunnelReady callback: {e}");
        }
    }
}

// ──────────── Protected UDP socket creation ────────────

fn create_protected_udp_socket(
    vm: &JavaVM,
    vpn_service: &GlobalRef,
    dest: SocketAddr,
    session: &Arc<SessionRuntime>,
) -> Result<RawFd> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }

    // Call Android VpnService.protect(int) to exempt this socket from the VPN.
    let mut guard = vm
        .attach_current_thread()
        .map_err(|e| Error::Session(format!("JNI attach: {}", e)))?;

    let protected = guard
        .call_method(
            vpn_service,
            "protect",
            "(I)Z",
            &[jni::objects::JValue::Int(fd)],
        )
        .and_then(|v| v.z())
        .unwrap_or(false);

    if !protected {
        unsafe { libc::close(fd) };
        return Err(Error::Session("VpnService.protect() returned false".into()));
    }

    // Increase OS socket buffers to reduce drops/backpressure on high-throughput links.
    // Ignore errors: kernels may cap/override values.
    let sock_buf: libc::c_int = 4 * 1024 * 1024;
    unsafe {
        let _ = libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            &sock_buf as *const _ as *const libc::c_void,
            std::mem::size_of_val(&sock_buf) as libc::socklen_t,
        );
        let _ = libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &sock_buf as *const _ as *const libc::c_void,
            std::mem::size_of_val(&sock_buf) as libc::socklen_t,
        );
    }

    // Connect to server (sets default destination for send/recv, non-blocking for UDP).
    let SocketAddr::V4(v4) = dest else {
        unsafe { libc::close(fd) };
        return Err(Error::Session("Only IPv4 server addresses are supported".into()));
    };
    let sa = to_sockaddr_in(&v4);
    let rc = unsafe {
        libc::connect(
            fd,
            &sa as *const libc::sockaddr_in as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        unsafe { libc::close(fd) };
        return Err(Error::Io(std::io::Error::last_os_error()));
    }

    session.udp_fd.store(fd, Ordering::SeqCst);

    Ok(fd)
}

fn to_sockaddr_in(addr: &SocketAddrV4) -> libc::sockaddr_in {
    libc::sockaddr_in {
        #[cfg(any(
            target_os = "macos",
            target_os = "ios",
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd",
            target_os = "dragonfly"
        ))]
        sin_len: std::mem::size_of::<libc::sockaddr_in>() as u8,
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: addr.port().to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(addr.ip().octets()),
        },
        sin_zero: [0; 8],
    }
}

// ──────────── Async TUN I/O ────────────

async fn tun_async_read(tun: &AsyncFd<OwnedFd>, buf: &mut [u8]) -> std::io::Result<usize> {
    loop {
        let mut guard = tun.readable().await?;
        match guard.try_io(|inner| {
            let n = unsafe {
                libc::read(
                    inner.as_raw_fd(),
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                )
            };
            if n < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(n as usize)
            }
        }) {
            Ok(r) => return r,
            Err(_would_block) => continue,
        }
    }
}

async fn tun_async_write(tun: &AsyncFd<OwnedFd>, data: &[u8]) -> std::io::Result<()> {
    let mut written = 0usize;
    while written < data.len() {
        let mut guard = tun.writable().await?;
        match guard.try_io(|inner| {
            let n = unsafe {
                libc::write(
                    inner.as_raw_fd(),
                    data[written..].as_ptr() as *const libc::c_void,
                    data.len() - written,
                )
            };

            if n < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::WouldBlock {
                    Err(std::io::Error::from(std::io::ErrorKind::WouldBlock))
                } else {
                    Err(err)
                }
            } else {
                Ok(n as usize)
            }
        }) {
            Ok(Ok(0)) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "TUN write returned 0",
                ));
            }
            Ok(Ok(n)) => {
                written += n;
            }
            Ok(Err(e)) => {
                return Err(e);
            }
            Err(_would_block) => continue,
        }
    }
    Ok(())
}
