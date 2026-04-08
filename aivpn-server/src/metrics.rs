//! Prometheus Metrics (Phase 5)
//!
//! Implements monitoring and metrics export for AIVPN
//!
//! Features:
//! - Session count and state
//! - Packet processing rates
//! - Bandwidth usage
//! - Mask rotation events
//! - Neural module health
//! - DPI attack detection

#[cfg(feature = "metrics")]
use prometheus::{Counter, Encoder, Gauge, Histogram, HistogramOpts, Opts, Registry, TextEncoder};
#[cfg(feature = "metrics")]
use std::sync::Arc;
#[cfg(feature = "metrics")]
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
#[cfg(feature = "metrics")]
use tracing::{info, warn};

/// Metrics collector
pub struct MetricsCollector {
    #[cfg(feature = "metrics")]
    registry: Registry,

    #[cfg(feature = "metrics")]
    sessions_total: Gauge,

    #[cfg(feature = "metrics")]
    sessions_active: Gauge,

    #[cfg(feature = "metrics")]
    packets_received: Counter,

    #[cfg(feature = "metrics")]
    packets_sent: Counter,

    #[cfg(feature = "metrics")]
    handshakes_success: Counter,

    #[cfg(feature = "metrics")]
    handshakes_failed: Counter,

    #[cfg(feature = "metrics")]
    psk_mismatches: Counter,

    #[cfg(feature = "metrics")]
    decrypt_failures: Counter,

    #[cfg(feature = "metrics")]
    nat_forward_failures: Counter,

    #[cfg(feature = "metrics")]
    bytes_received: Counter,

    #[cfg(feature = "metrics")]
    bytes_sent: Counter,

    #[cfg(feature = "metrics")]
    packet_processing_time: Histogram,

    #[cfg(feature = "metrics")]
    tag_validation_time: Histogram,

    #[cfg(feature = "metrics")]
    mask_rotations: Counter,

    #[cfg(feature = "metrics")]
    key_rotations: Counter,

    #[cfg(feature = "metrics")]
    neural_checks_total: Counter,

    #[cfg(feature = "metrics")]
    neural_checks_failed: Counter,

    #[cfg(feature = "metrics")]
    dpi_attacks_detected: Counter,
}

impl MetricsCollector {
    /// Create new metrics collector
    pub fn new() -> Self {
        #[cfg(feature = "metrics")]
        {
            let registry = Registry::new();

            // Session metrics
            let sessions_total = Gauge::with_opts(Opts::new(
                "aivpn_sessions_total",
                "Total number of sessions",
            ))
            .unwrap();
            registry.register(Box::new(sessions_total.clone())).unwrap();

            let sessions_active = Gauge::with_opts(Opts::new(
                "aivpn_sessions_active",
                "Number of active sessions",
            ))
            .unwrap();
            registry
                .register(Box::new(sessions_active.clone()))
                .unwrap();

            // Packet metrics
            let packets_received = Counter::with_opts(Opts::new(
                "aivpn_packets_received_total",
                "Total packets received",
            ))
            .unwrap();
            registry
                .register(Box::new(packets_received.clone()))
                .unwrap();

            let packets_sent =
                Counter::with_opts(Opts::new("aivpn_packets_sent_total", "Total packets sent"))
                    .unwrap();
            registry.register(Box::new(packets_sent.clone())).unwrap();

            // Handshake and error metrics
            let handshakes_success = Counter::with_opts(Opts::new(
                "aivpn_handshakes_success_total",
                "Total successful handshakes",
            ))
            .unwrap();
            registry
                .register(Box::new(handshakes_success.clone()))
                .unwrap();

            let handshakes_failed = Counter::with_opts(Opts::new(
                "aivpn_handshakes_failed_total",
                "Total failed handshakes",
            ))
            .unwrap();
            registry
                .register(Box::new(handshakes_failed.clone()))
                .unwrap();

            let psk_mismatches = Counter::with_opts(Opts::new(
                "aivpn_psk_mismatches_total",
                "Total handshakes rejected because no client PSK matched",
            ))
            .unwrap();
            registry
                .register(Box::new(psk_mismatches.clone()))
                .unwrap();

            let decrypt_failures = Counter::with_opts(Opts::new(
                "aivpn_decrypt_failures_total",
                "Total payload decrypt failures",
            ))
            .unwrap();
            registry
                .register(Box::new(decrypt_failures.clone()))
                .unwrap();

            let nat_forward_failures = Counter::with_opts(Opts::new(
                "aivpn_nat_forward_failures_total",
                "Total NAT forward failures",
            ))
            .unwrap();
            registry
                .register(Box::new(nat_forward_failures.clone()))
                .unwrap();

            // Bandwidth metrics
            let bytes_received = Counter::with_opts(Opts::new(
                "aivpn_bytes_received_total",
                "Total bytes received",
            ))
            .unwrap();
            registry.register(Box::new(bytes_received.clone())).unwrap();

            let bytes_sent =
                Counter::with_opts(Opts::new("aivpn_bytes_sent_total", "Total bytes sent"))
                    .unwrap();
            registry.register(Box::new(bytes_sent.clone())).unwrap();

            // Performance metrics
            let packet_processing_time = Histogram::with_opts(HistogramOpts::new(
                "aivpn_packet_processing_seconds",
                "Packet processing time",
            ))
            .unwrap();
            registry
                .register(Box::new(packet_processing_time.clone()))
                .unwrap();

            let tag_validation_time = Histogram::with_opts(HistogramOpts::new(
                "aivpn_tag_validation_seconds",
                "Tag validation time",
            ))
            .unwrap();
            registry
                .register(Box::new(tag_validation_time.clone()))
                .unwrap();

            // Rotation metrics
            let mask_rotations = Counter::with_opts(Opts::new(
                "aivpn_mask_rotations_total",
                "Total mask rotations",
            ))
            .unwrap();
            registry.register(Box::new(mask_rotations.clone())).unwrap();

            let key_rotations = Counter::with_opts(Opts::new(
                "aivpn_key_rotations_total",
                "Total key rotations",
            ))
            .unwrap();
            registry.register(Box::new(key_rotations.clone())).unwrap();

            // Neural module metrics
            let neural_checks_total = Counter::with_opts(Opts::new(
                "aivpn_neural_checks_total",
                "Total neural resonance checks",
            ))
            .unwrap();
            registry
                .register(Box::new(neural_checks_total.clone()))
                .unwrap();

            let neural_checks_failed = Counter::with_opts(Opts::new(
                "aivpn_neural_checks_failed_total",
                "Failed neural resonance checks",
            ))
            .unwrap();
            registry
                .register(Box::new(neural_checks_failed.clone()))
                .unwrap();

            // Security metrics
            let dpi_attacks_detected = Counter::with_opts(Opts::new(
                "aivpn_dpi_attacks_detected_total",
                "DPI attacks detected",
            ))
            .unwrap();
            registry
                .register(Box::new(dpi_attacks_detected.clone()))
                .unwrap();

            Self {
                registry,
                sessions_total,
                sessions_active,
                packets_received,
                packets_sent,
                handshakes_success,
                handshakes_failed,
                psk_mismatches,
                decrypt_failures,
                nat_forward_failures,
                bytes_received,
                bytes_sent,
                packet_processing_time,
                tag_validation_time,
                mask_rotations,
                key_rotations,
                neural_checks_total,
                neural_checks_failed,
                dpi_attacks_detected,
            }
        }

        #[cfg(not(feature = "metrics"))]
        Self {}
    }

    /// Update session count
    pub fn update_session_count(&self, _total: usize, _active: usize) {
        #[cfg(feature = "metrics")]
        {
            self.sessions_total.set(_total as f64);
            self.sessions_active.set(_active as f64);
        }
    }

    /// Record packet received
    pub fn record_packet_received(&self, _bytes: usize) {
        #[cfg(feature = "metrics")]
        {
            self.packets_received.inc();
            self.bytes_received.inc_by(_bytes as f64);
        }
    }

    /// Record packet sent
    pub fn record_packet_sent(&self, _bytes: usize) {
        #[cfg(feature = "metrics")]
        {
            self.packets_sent.inc();
            self.bytes_sent.inc_by(_bytes as f64);
        }
    }

    /// Record successful handshake
    pub fn record_handshake_success(&self) {
        #[cfg(feature = "metrics")]
        {
            self.handshakes_success.inc();
        }
    }

    /// Record failed handshake
    pub fn record_handshake_failure(&self) {
        #[cfg(feature = "metrics")]
        {
            self.handshakes_failed.inc();
        }
    }

    /// Record PSK mismatch
    pub fn record_psk_mismatch(&self) {
        #[cfg(feature = "metrics")]
        {
            self.psk_mismatches.inc();
        }
    }

    /// Record decrypt failure
    pub fn record_decrypt_failure(&self) {
        #[cfg(feature = "metrics")]
        {
            self.decrypt_failures.inc();
        }
    }

    /// Record NAT forward failure
    pub fn record_nat_forward_failure(&self) {
        #[cfg(feature = "metrics")]
        {
            self.nat_forward_failures.inc();
        }
    }

    /// Record packet processing time
    pub fn record_processing_time(&self, _seconds: f64) {
        #[cfg(feature = "metrics")]
        {
            self.packet_processing_time.observe(_seconds);
        }
    }

    /// Record tag validation time
    pub fn record_tag_validation_time(&self, _seconds: f64) {
        #[cfg(feature = "metrics")]
        {
            self.tag_validation_time.observe(_seconds);
        }
    }

    /// Record mask rotation
    pub fn record_mask_rotation(&self) {
        #[cfg(feature = "metrics")]
        {
            self.mask_rotations.inc();
        }
    }

    /// Record key rotation
    pub fn record_key_rotation(&self) {
        #[cfg(feature = "metrics")]
        {
            self.key_rotations.inc();
        }
    }

    /// Record neural check
    pub fn record_neural_check(&self, _failed: bool) {
        #[cfg(feature = "metrics")]
        {
            self.neural_checks_total.inc();
            if _failed {
                self.neural_checks_failed.inc();
            }
        }
    }

    /// Record DPI attack detection
    pub fn record_dpi_attack(&self) {
        #[cfg(feature = "metrics")]
        {
            self.dpi_attacks_detected.inc();
            warn!("DPI attack detected!");
        }
    }

    /// Export metrics in Prometheus format
    pub fn gather(&self) -> String {
        #[cfg(feature = "metrics")]
        {
            let encoder = TextEncoder::new();
            let metric_families = self.registry.gather();
            let mut output = Vec::new();
            encoder.encode(&metric_families, &mut output).unwrap();
            String::from_utf8(output).unwrap_or_default()
        }

        #[cfg(not(feature = "metrics"))]
        {
            String::new()
        }
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// Serve Prometheus metrics over a small read-only HTTP endpoint.
#[cfg(feature = "metrics")]
pub async fn serve_metrics(addr: &str, collector: Arc<MetricsCollector>) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    info!("Metrics endpoint listening on http://{}/metrics", addr);

    loop {
        let (stream, _) = listener.accept().await?;
        let collector = collector.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_metrics_connection(stream, collector).await {
                warn!("Metrics HTTP request failed: {}", err);
            }
        });
    }
}

#[cfg(feature = "metrics")]
async fn handle_metrics_connection(
    mut stream: TcpStream,
    collector: Arc<MetricsCollector>,
) -> std::io::Result<()> {
    let mut buffer = [0u8; 1024];
    let bytes_read = stream.read(&mut buffer).await?;
    let request = String::from_utf8_lossy(&buffer[..bytes_read]);
    let first_line = request.lines().next().unwrap_or_default();

    if !first_line.starts_with("GET /metrics ") {
        let body = "not found\n";
        write_http_response(&mut stream, "404 Not Found", "text/plain", body).await?;
        return Ok(());
    }

    let body = collector.gather();
    write_http_response(&mut stream, "200 OK", "text/plain; version=0.0.4", &body).await
}

#[cfg(feature = "metrics")]
async fn write_http_response(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: &str,
) -> std::io::Result<()> {
    let response = format!(
        "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        status,
        content_type,
        body.len(),
        body
    );
    stream.write_all(response.as_bytes()).await
}

#[cfg(all(test, feature = "metrics"))]
mod tests {
    use super::*;

    #[test]
    fn gather_exports_prometheus_metrics() {
        let collector = MetricsCollector::new();
        collector.update_session_count(2, 1);
        collector.record_packet_received(128);
        collector.record_packet_sent(64);
        collector.record_handshake_success();
        collector.record_decrypt_failure();
        collector.record_mask_rotation();

        let metrics = collector.gather();

        assert!(metrics.contains("aivpn_sessions_active"));
        assert!(metrics.contains("aivpn_packets_received_total"));
        assert!(metrics.contains("aivpn_bytes_sent_total"));
        assert!(metrics.contains("aivpn_handshakes_success_total"));
        assert!(metrics.contains("aivpn_decrypt_failures_total"));
        assert!(metrics.contains("aivpn_mask_rotations_total"));
    }
}
