use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::error::{Error, Result};

pub const FRAGMENT_HEADER_LEN: usize = 8;
pub const DEFAULT_FRAGMENT_REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug, Clone, Copy)]
pub struct FragmentHeader {
    pub fragment_id: u32,
    pub fragment_index: u16,
    pub fragment_count: u16,
}

impl FragmentHeader {
    pub fn encode(&self) -> [u8; FRAGMENT_HEADER_LEN] {
        let mut buf = [0u8; FRAGMENT_HEADER_LEN];
        buf[0..4].copy_from_slice(&self.fragment_id.to_le_bytes());
        buf[4..6].copy_from_slice(&self.fragment_index.to_le_bytes());
        buf[6..8].copy_from_slice(&self.fragment_count.to_le_bytes());
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < FRAGMENT_HEADER_LEN {
            return Err(Error::InvalidPacket("Fragment header too short"));
        }
        let fragment_id = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let fragment_index = u16::from_le_bytes(data[4..6].try_into().unwrap());
        let fragment_count = u16::from_le_bytes(data[6..8].try_into().unwrap());
        if fragment_count == 0 {
            return Err(Error::InvalidPacket("Fragment count must be non-zero"));
        }
        if fragment_index >= fragment_count {
            return Err(Error::InvalidPacket("Fragment index out of range"));
        }
        Ok(Self {
            fragment_id,
            fragment_index,
            fragment_count,
        })
    }
}

struct FragmentBuffer {
    created_at: Instant,
    parts: Vec<Option<Vec<u8>>>,
    received: usize,
}

pub struct FragmentAssembler {
    timeout: Duration,
    buffers: HashMap<u32, FragmentBuffer>,
}

impl Default for FragmentAssembler {
    fn default() -> Self {
        Self::new(DEFAULT_FRAGMENT_REASSEMBLY_TIMEOUT)
    }
}

impl FragmentAssembler {
    pub fn new(timeout: Duration) -> Self {
        Self {
            timeout,
            buffers: HashMap::new(),
        }
    }

    pub fn push(&mut self, header: FragmentHeader, payload: &[u8]) -> Result<Option<Vec<u8>>> {
        self.evict_expired();
        let entry = self
            .buffers
            .entry(header.fragment_id)
            .or_insert_with(|| FragmentBuffer {
                created_at: Instant::now(),
                parts: vec![None; header.fragment_count as usize],
                received: 0,
            });

        if entry.parts.len() != header.fragment_count as usize {
            self.buffers.remove(&header.fragment_id);
            return Err(Error::InvalidPacket("Fragment count changed mid-stream"));
        }

        let slot = &mut entry.parts[header.fragment_index as usize];
        if slot.is_none() {
            *slot = Some(payload.to_vec());
            entry.received += 1;
        }

        if entry.received == entry.parts.len() {
            let mut assembled = Vec::new();
            for part in entry.parts.iter() {
                let chunk = part.as_ref().ok_or(Error::InvalidPacket("Fragment set incomplete"))?;
                assembled.extend_from_slice(chunk);
            }
            self.buffers.remove(&header.fragment_id);
            return Ok(Some(assembled));
        }

        Ok(None)
    }

    pub fn evict_expired(&mut self) {
        let timeout = self.timeout;
        self.buffers.retain(|_, buf| buf.created_at.elapsed() < timeout);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reassembles_fragments_in_order() {
        let mut assembler = FragmentAssembler::default();
        let h1 = FragmentHeader { fragment_id: 7, fragment_index: 0, fragment_count: 2 };
        let h2 = FragmentHeader { fragment_id: 7, fragment_index: 1, fragment_count: 2 };
        assert!(assembler.push(h1, b"hello ").unwrap().is_none());
        let assembled = assembler.push(h2, b"world").unwrap();
        assert_eq!(assembled.as_deref(), Some(b"hello world".as_slice()));
    }

    #[test]
    fn reassembles_fragments_out_of_order() {
        let mut assembler = FragmentAssembler::default();
        let h1 = FragmentHeader { fragment_id: 11, fragment_index: 1, fragment_count: 2 };
        let h2 = FragmentHeader { fragment_id: 11, fragment_index: 0, fragment_count: 2 };
        assert!(assembler.push(h1, b"world").unwrap().is_none());
        let assembled = assembler.push(h2, b"hello ").unwrap();
        assert_eq!(assembled.as_deref(), Some(b"hello world".as_slice()));
    }

    #[test]
    fn rejects_fragment_count_change() {
        let mut assembler = FragmentAssembler::default();
        let h1 = FragmentHeader { fragment_id: 99, fragment_index: 0, fragment_count: 2 };
        let h2 = FragmentHeader { fragment_id: 99, fragment_index: 1, fragment_count: 3 };
        assert!(assembler.push(h1, b"a").unwrap().is_none());
        assert!(assembler.push(h2, b"b").is_err());
    }
}
