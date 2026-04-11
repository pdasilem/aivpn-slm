//! NAT Forwarder Module
//!
//! Handles:
//! - TUN device creation
//! - Packet forwarding to internet

use std::io;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::io::AsyncWriteExt;
use tracing::{info, debug};

use aivpn_common::error::{Error, Result};

const TUN_MTU: u16 = 1420;

/// NAT Forwarder for routing traffic to internet
/// Uses split reader/writer to avoid mutex starvation
pub struct NatForwarder {
    tun_name: String,
    tun_addr: String,
    tun_netmask: String,
    writer: Option<Arc<Mutex<tun::DeviceWriter>>>,
    reader: Option<Mutex<Option<tun::DeviceReader>>>,
}

impl NatForwarder {
    pub fn new(tun_name: &str, tun_addr: &str, tun_netmask: &str) -> Result<Self> {
        Ok(Self {
            tun_name: tun_name.to_string(),
            tun_addr: tun_addr.to_string(),
            tun_netmask: tun_netmask.to_string(),
            writer: None,
            reader: None,
        })
    }
    
    /// Create TUN device for NAT
    pub fn create(&mut self) -> Result<()> {
        let mut config = tun::Configuration::default();
        
        config
            .tun_name(&self.tun_name)
            .address(&self.tun_addr)
            .netmask(&self.tun_netmask)
            .mtu(TUN_MTU)
            .up();
        
        #[cfg(target_os = "linux")]
        config.platform_config(|config| {
            config.ensure_root_privileges(true);
        });
        
        let dev = tun::create_as_async(&config)
            .map_err(|e| Error::Io(io::Error::new(io::ErrorKind::Other, e.to_string())))?;
        
        let (writer, reader) = dev.split()
            .map_err(|e| Error::Io(io::Error::new(io::ErrorKind::Other, e.to_string())))?;
        self.writer = Some(Arc::new(Mutex::new(writer)));
        self.reader = Some(Mutex::new(Some(reader)));
        
        info!(
            "Created NAT TUN device: {} ({}/{})",
            self.tun_name,
            self.tun_addr,
            self.tun_netmask
        );
        
        Ok(())
    }
    
    /// Forward packet to TUN (write)
    pub async fn forward_packet(&self, packet: &[u8]) -> Result<()> {
        let writer = self.writer.as_ref()
            .ok_or_else(|| Error::Io(io::Error::new(
                io::ErrorKind::NotConnected,
                "TUN device not created",
            )))?;
        
        let mut w = writer.lock().await;
        
        // Linux TUN with IFF_NO_PI (default) expects raw IP packets
        w.write_all(packet).await?;
        w.flush().await?;
        
        debug!("Forwarded {} bytes to TUN", packet.len());
        Ok(())
    }
    
    /// Take ownership of the TUN reader (for use in a spawned task)
    pub async fn take_reader(&self) -> Option<tun::DeviceReader> {
        if let Some(reader_lock) = &self.reader {
            reader_lock.lock().await.take()
        } else {
            None
        }
    }
    
    /// Get TUN device name
    pub fn tun_name(&self) -> &str {
        &self.tun_name
    }
}

impl Drop for NatForwarder {
    fn drop(&mut self) {
        if self.writer.is_some() {
            info!("Closing NAT TUN device: {}", self.tun_name);
        }
    }
}
