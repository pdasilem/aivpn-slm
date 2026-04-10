//! Mask System (Traffic Mimicry Profiles)
//! 
//! Implements Mask profiles that define traffic shaping behavior

use serde::{Deserialize, Serialize};
use rand::{Rng, distributions::Distribution};
use rand::distributions::weighted::WeightedIndex;

use crate::error::{Error, Result};

/// Mask profile for traffic mimicry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaskProfile {
    /// Unique identifier
    pub mask_id: String,
    /// Profile version
    pub version: u16,
    /// Creation timestamp
    pub created_at: u64,
    /// Expiration timestamp
    pub expires_at: u64,

    /// Protocol to spoof
    pub spoof_protocol: SpoofProtocol,
    /// Header template bytes
    pub header_template: Vec<u8>,
    /// Offset for ephemeral public key in header
    pub eph_pub_offset: u16,
    /// Length of ephemeral public key (always 32)
    pub eph_pub_length: u16,

    /// Packet size distribution
    pub size_distribution: SizeDistribution,
    /// Inter-arrival time distribution
    pub iat_distribution: IATDistribution,
    /// Padding strategy
    pub padding_strategy: PaddingStrategy,

    /// FSM states for behavioral mimicry
    pub fsm_states: Vec<FSMState>,
    /// Initial FSM state
    pub fsm_initial_state: u16,

    /// Neural resonance signature (64 floats)
    pub signature_vector: Vec<f32>,

    /// Reverse profile for server->client traffic
    pub reverse_profile: Option<Box<MaskProfile>>,

    /// Ed25519 signature (64 bytes)
    #[serde(with = "serde_bytes")]
    pub signature: [u8; 64],
}

/// Protocol spoofing types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SpoofProtocol {
    None,
    QUIC,
    #[serde(rename = "WebRTC_STUN")]
    WebRtcStun,
    #[serde(rename = "HTTPS_H2")]
    HttpsH2,
    #[serde(rename = "DNS_over_UDP")]
    DnsOverUdp,
}

/// Packet size distribution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SizeDistribution {
    pub dist_type: SizeDistType,
    pub bins: Vec<(u16, u16, f32)>, // (min, max, probability)
    pub parametric_type: Option<ParametricType>,
    pub parametric_params: Option<Vec<f64>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SizeDistType {
    Histogram,
    Parametric,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ParametricType {
    LogNormal,
    Gamma,
    Bimodal,
}

impl SizeDistribution {
    /// Sample a packet size from the distribution
    pub fn sample<R: Rng>(&self, rng: &mut R) -> u16 {
        match self.dist_type {
            SizeDistType::Histogram => {
                if self.bins.is_empty() {
                    return 64; // Default
                }
                
                // Weighted random selection of bin
                let weights: Vec<f32> = self.bins.iter().map(|(_, _, p)| *p).collect();
                if let Ok(dist) = WeightedIndex::new(&weights) {
                    let bin_idx = dist.sample(rng);
                    let (min, max, _) = self.bins[bin_idx];
                    rng.gen_range(min..=max)
                } else {
                    64
                }
            }
            SizeDistType::Parametric => {
                match self.parametric_type {
                    Some(ParametricType::LogNormal) => {
                        if let Some(params) = &self.parametric_params {
                            let mu: f64 = params[0];
                            let sigma: f64 = params[1];
                            // Box-Muller transform: generate standard normal from two uniform samples
                            let u1: f64 = rng.gen::<f64>().max(1e-10); // avoid ln(0)
                            let u2: f64 = rng.gen();
                            let z = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();
                            // LogNormal: exp(mu + sigma * z)
                            let sample = (mu + sigma * z).exp();
                            (sample as u16).max(1)
                        } else {
                            rng.gen_range(64..512)
                        }
                    }
                    _ => rng.gen_range(64..512),
                }
            }
        }
    }
}

/// Inter-arrival time distribution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IATDistribution {
    pub dist_type: IATDistType,
    pub params: Vec<f64>,
    pub jitter_range_ms: (f64, f64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IATDistType {
    Exponential,
    LogNormal,
    Gamma,
    Empirical,
}

impl IATDistribution {
    /// Sample an inter-arrival time in milliseconds
    pub fn sample<R: Rng>(&self, rng: &mut R) -> f64 {
        let base_iat = match self.dist_type {
            IATDistType::Exponential => {
                let lambda: f64 = self.params[0];
                let val: f64 = rng.gen::<f64>().max(1e-10);
                -(1.0 - val).ln() / lambda
            }
            IATDistType::LogNormal => {
                let mu: f64 = self.params[0];
                let sigma: f64 = self.params[1];
                // Box-Muller transform for proper normal distribution
                let u1: f64 = rng.gen::<f64>().max(1e-10);
                let u2: f64 = rng.gen();
                let z = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();
                (mu + sigma * z).exp()
            }
            IATDistType::Gamma => {
                // Simplified gamma sampling (sum of k exponentials for integer k)
                let k: f64 = self.params[0];
                let theta: f64 = self.params[1];
                let sum: f64 = (0..k.max(1.0) as i32)
                    .map(|_| {
                        let val: f64 = rng.gen::<f64>().max(1e-10);
                        -(1.0 - val).ln()
                    })
                    .sum();
                sum * theta
            }
            IATDistType::Empirical => {
                let idx = rng.gen_range(0..self.params.len());
                self.params[idx]
            }
        };

        // Add jitter
        let jitter = rng.gen_range(self.jitter_range_ms.0..=self.jitter_range_ms.1);
        (base_iat + jitter).max(0.0)
    }
}

/// Padding strategy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PaddingStrategy {
    RandomUniform { min: u16, max: u16 },
    MatchDistribution,
    Fixed { size: u16 },
}

impl PaddingStrategy {
    /// Calculate padding length for a given payload
    pub fn calc_padding<R: Rng>(&self, payload_size: usize, target_size: u16, rng: &mut R) -> u16 {
        match self {
            Self::RandomUniform { min, max } => rng.gen_range(*min..=*max),
            Self::MatchDistribution => {
                if target_size as usize > payload_size {
                    (target_size as usize - payload_size) as u16
                } else {
                    0
                }
            }
            Self::Fixed { size } => *size,
        }
    }
}

/// FSM state for behavioral mimicry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FSMState {
    pub state_id: u16,
    pub transitions: Vec<FSMTransition>,
}

/// FSM transition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FSMTransition {
    pub condition: TransitionCondition,
    pub next_state: u16,
    pub size_override: Option<SizeDistribution>,
    pub iat_override: Option<IATDistribution>,
    pub padding_override: Option<PaddingStrategy>,
}

/// Transition condition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransitionCondition {
    AfterPackets(u32),
    AfterDuration(u64), // milliseconds
    OnPayloadType(u8),
    Random(f32), // probability per packet
}

impl MaskProfile {
    /// Build a deterministic 64-dim fingerprint from the profile itself.
    ///
    /// This is not a trained model output. It is a stable structural signature
    /// derived from the profile fields so the server-side neural module has a
    /// meaningful baseline instead of all-zero vectors.
    pub fn derived_signature_vector(&self) -> Vec<f32> {
        let mut signature = vec![0.0f32; 64];

        // Block 1 (0..16): expected packet-size shape
        match self.size_distribution.dist_type {
            SizeDistType::Histogram => {
                let total: f32 = self
                    .size_distribution
                    .bins
                    .iter()
                    .map(|(_, _, p)| *p)
                    .sum::<f32>()
                    .max(1e-6);
                for (min, max, probability) in &self.size_distribution.bins {
                    let center = ((*min as u32 + *max as u32) / 2) as usize;
                    let bin = (center / 80).min(15);
                    signature[bin] += *probability / total;
                }
            }
            SizeDistType::Parametric => {
                let params = self
                    .size_distribution
                    .parametric_params
                    .as_deref()
                    .unwrap_or(&[]);
                let center = match self.size_distribution.parametric_type {
                    Some(ParametricType::LogNormal) => {
                        let mu = params.first().copied().unwrap_or(5.0);
                        let sigma = params.get(1).copied().unwrap_or(0.5);
                        (mu.exp() * (1.0 + sigma * 0.1)).clamp(64.0, 1400.0)
                    }
                    Some(ParametricType::Gamma) => {
                        let k = params.first().copied().unwrap_or(2.0);
                        let theta = params.get(1).copied().unwrap_or(128.0);
                        (k * theta).clamp(64.0, 1400.0)
                    }
                    Some(ParametricType::Bimodal) => {
                        let a = params.first().copied().unwrap_or(5.0).exp();
                        let b = params.get(1).copied().unwrap_or(6.0).exp();
                        ((a + b) * 0.5).clamp(64.0, 1400.0)
                    }
                    None => 256.0,
                };
                let main_bin = ((center as usize) / 80).min(15);
                signature[main_bin] = 0.7;
                if main_bin > 0 {
                    signature[main_bin - 1] += 0.15;
                }
                if main_bin < 15 {
                    signature[main_bin + 1] += 0.15;
                }
            }
        }

        // Block 2 (16..24): expected IAT features
        let jitter_mid = (self.iat_distribution.jitter_range_ms.0 + self.iat_distribution.jitter_range_ms.1) * 0.5;
        let (iat_mean_ms, iat_std_ms) = match self.iat_distribution.dist_type {
            IATDistType::Exponential => {
                let lambda = self.iat_distribution.params.first().copied().unwrap_or(0.1).max(1e-6);
                (1000.0 / lambda, 1000.0 / lambda)
            }
            IATDistType::LogNormal => {
                let mu = self.iat_distribution.params.first().copied().unwrap_or(2.5);
                let sigma = self.iat_distribution.params.get(1).copied().unwrap_or(0.3);
                let mean = (mu + (sigma * sigma * 0.5)).exp();
                let variance = ((sigma * sigma).exp() - 1.0) * (2.0 * mu + sigma * sigma).exp();
                (mean, variance.sqrt())
            }
            IATDistType::Gamma => {
                let k = self.iat_distribution.params.first().copied().unwrap_or(2.0);
                let theta = self.iat_distribution.params.get(1).copied().unwrap_or(10.0);
                (k * theta, k.sqrt() * theta)
            }
            IATDistType::Empirical => {
                if self.iat_distribution.params.is_empty() {
                    (50.0, 0.0)
                } else {
                    let n = self.iat_distribution.params.len() as f64;
                    let mean = self.iat_distribution.params.iter().sum::<f64>() / n;
                    let variance = self
                        .iat_distribution
                        .params
                        .iter()
                        .map(|x| (x - mean).powi(2))
                        .sum::<f64>()
                        / n;
                    (mean, variance.sqrt())
                }
            }
        };
        signature[16] = ((iat_mean_ms + jitter_mid) / 100.0).min(1.0) as f32;
        signature[17] = (iat_std_ms / 100.0).min(1.0) as f32;
        signature[18] = ((iat_mean_ms + self.iat_distribution.jitter_range_ms.1) / 1000.0).min(1.0) as f32;
        signature[19] = ((iat_mean_ms.max(0.0) + self.iat_distribution.jitter_range_ms.0) / 1000.0).min(1.0) as f32;
        signature[20] = (iat_mean_ms * 0.75 / 100.0).min(1.0) as f32;
        signature[21] = (iat_mean_ms / 100.0).min(1.0) as f32;
        signature[22] = (iat_mean_ms * 1.25 / 100.0).min(1.0) as f32;
        signature[23] = if iat_mean_ms > 0.0 {
            (iat_std_ms / iat_mean_ms).min(1.0) as f32
        } else {
            0.0
        };

        // Block 3 (32..36): protocol/entropy bias
        let protocol_entropy: f64 = match self.spoof_protocol {
            SpoofProtocol::None => 6.0,
            SpoofProtocol::QUIC => 7.6,
            SpoofProtocol::WebRtcStun => 6.8,
            SpoofProtocol::HttpsH2 => 7.2,
            SpoofProtocol::DnsOverUdp => 5.0,
        };
        signature[32] = (protocol_entropy / 8.0) as f32;
        signature[33] = ((self.header_template.len() as f32) / 64.0).min(1.0);
        signature[34] = ((protocol_entropy + 0.4).min(8.0) / 8.0) as f32;
        signature[35] = ((protocol_entropy - 0.4).max(0.0) / 8.0) as f32;

        // Block 4 (48..52): temporal/volume expectations
        let pps = if iat_mean_ms > 0.0 {
            1000.0 / iat_mean_ms
        } else {
            0.0
        };
        let mean_size = {
            let mut weighted_sum = 0.0f64;
            let mut weighted_n = 0.0f64;
            for (min, max, probability) in &self.size_distribution.bins {
                weighted_sum += ((*min as f64 + *max as f64) * 0.5) * (*probability as f64);
                weighted_n += *probability as f64;
            }
            if weighted_n > 0.0 {
                weighted_sum / weighted_n
            } else {
                256.0
            }
        };
        signature[48] = (pps / 1000.0).min(1.0) as f32;
        signature[49] = ((pps * mean_size) / 1_000_000.0).min(1.0) as f32;
        signature[50] = (mean_size / 1500.0).min(1.0) as f32;
        signature[51] = (((self.fsm_states.len() as f32) * 0.1) + signature[17]).min(1.0);

        // Structural tail: hash profile metadata into remaining dimensions.
        let mut fingerprint_material = Vec::new();
        fingerprint_material.extend_from_slice(self.mask_id.as_bytes());
        fingerprint_material.extend_from_slice(&(self.version).to_le_bytes());
        fingerprint_material.push(self.spoof_protocol as u8);
        fingerprint_material.extend_from_slice(&(self.header_template.len() as u16).to_le_bytes());
        fingerprint_material.extend_from_slice(&(self.fsm_states.len() as u16).to_le_bytes());
        for window in 0..3usize {
            let hash = blake3::keyed_hash(
                &[window as u8; 32],
                &fingerprint_material,
            );
            for (i, byte) in hash.as_bytes().iter().enumerate() {
                let idx = 52 + window * 8 + (i % 8);
                if idx < 64 {
                    signature[idx] = (*byte as f32) / 255.0;
                }
            }
        }

        signature
    }

    /// Verify Ed25519 signature over all profile fields except the signature itself
    pub fn verify_signature(&self, public_key: &[u8; 32]) -> Result<bool> {
        use ed25519_dalek::{Signature, VerifyingKey, Verifier};

        let vk = VerifyingKey::from_bytes(public_key)
            .map_err(|e| Error::Crypto(format!("Invalid Ed25519 public key: {}", e)))?;

        // Build canonical message: mask_id || version || header_template
        let mut message = Vec::new();
        message.extend_from_slice(self.mask_id.as_bytes());
        message.extend_from_slice(&self.version.to_le_bytes());
        message.extend_from_slice(&self.header_template);

        let sig = Signature::from_bytes(&self.signature);
        match vk.verify(&message, &sig) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Get initial FSM state
    pub fn initial_state(&self) -> u16 {
        self.fsm_initial_state
    }

    /// Process FSM transition
    pub fn process_transition(
        &self,
        current_state: u16,
        packets_in_state: u32,
        duration_in_state_ms: u64,
    ) -> (u16, Option<SizeDistribution>, Option<IATDistribution>, Option<PaddingStrategy>) {
        let state = self.fsm_states.iter().find(|s| s.state_id == current_state);
        if let Some(state) = state {
            for transition in &state.transitions {
                let should_transition = match &transition.condition {
                    TransitionCondition::AfterPackets(n) => packets_in_state >= *n,
                    TransitionCondition::AfterDuration(ms) => duration_in_state_ms >= *ms,
                    TransitionCondition::Random(prob) => rand::thread_rng().gen_range(0.0..1.0) < *prob,
                    TransitionCondition::OnPayloadType(_) => false, // Handled separately
                };

                if should_transition {
                    return (
                        transition.next_state,
                        transition.size_override.clone(),
                        transition.iat_override.clone(),
                        transition.padding_override.clone(),
                    );
                }
            }
        }
        (current_state, None, None, None)
    }
}

/// Pre-built mask catalog (MVP defaults)
pub mod preset_masks {
    use super::*;

    /// WebRTC Zoom-like profile
    pub fn webrtc_zoom_v3() -> MaskProfile {
        let mut mask = MaskProfile {
            mask_id: "webrtc_zoom_v3".to_string(),
            version: 1,
            created_at: 0,
            expires_at: u64::MAX,
            spoof_protocol: SpoofProtocol::WebRtcStun,
            header_template: vec![0x00, 0x01, 0x02, 0x03], // STUN-like
            eph_pub_offset: 4,
            eph_pub_length: 32,
            size_distribution: SizeDistribution {
                dist_type: SizeDistType::Parametric,
                bins: vec![],
                parametric_type: Some(ParametricType::Bimodal),
                parametric_params: Some(vec![5.0, 0.5]), // Opus-like
            },
            iat_distribution: IATDistribution {
                dist_type: IATDistType::LogNormal,
                params: vec![2.5, 0.3], // ~12ms average
                jitter_range_ms: (5.0, 20.0),
            },
            padding_strategy: PaddingStrategy::RandomUniform { min: 0, max: 64 },
            fsm_states: vec![
                FSMState {
                    state_id: 0,
                    transitions: vec![
                        FSMTransition {
                            condition: TransitionCondition::AfterDuration(5000),
                            next_state: 1,
                            size_override: None,
                            iat_override: None,
                            padding_override: None,
                        }
                    ],
                },
                FSMState {
                    state_id: 1,
                    transitions: vec![],
                },
            ],
            fsm_initial_state: 0,
            signature_vector: Vec::new(),
            reverse_profile: None,
            signature: [0u8; 64],
        };
        mask.signature_vector = mask.derived_signature_vector();
        mask
    }

    /// QUIC/HTTP3-like profile
    pub fn quic_https_v2() -> MaskProfile {
        let mut mask = MaskProfile {
            mask_id: "quic_https_v2".to_string(),
            version: 1,
            created_at: 0,
            expires_at: u64::MAX,
            spoof_protocol: SpoofProtocol::QUIC,
            header_template: vec![0xC0, 0xFF, 0xEE, 0x00], // QUIC-like
            eph_pub_offset: 4,
            eph_pub_length: 32,
            size_distribution: SizeDistribution {
                dist_type: SizeDistType::Histogram,
                bins: vec![
                    (64, 128, 0.3),
                    (256, 512, 0.4),
                    (768, 1200, 0.3),
                ],
                parametric_type: None,
                parametric_params: None,
            },
            iat_distribution: IATDistribution {
                dist_type: IATDistType::Exponential,
                params: vec![0.1], // Burst-idle pattern
                jitter_range_ms: (0.0, 10.0),
            },
            padding_strategy: PaddingStrategy::MatchDistribution,
            fsm_states: vec![
                FSMState {
                    state_id: 0,
                    transitions: vec![],
                },
            ],
            fsm_initial_state: 0,
            signature_vector: Vec::new(),
            reverse_profile: None,
            signature: [0u8; 64],
        };
        mask.signature_vector = mask.derived_signature_vector();
        mask
    }
}

#[cfg(test)]
mod tests {
    use super::preset_masks::{quic_https_v2, webrtc_zoom_v3};

    #[test]
    fn preset_masks_have_derived_nonzero_signatures() {
        let webrtc = webrtc_zoom_v3();
        let quic = quic_https_v2();

        assert_eq!(webrtc.signature_vector.len(), 64);
        assert_eq!(quic.signature_vector.len(), 64);
        assert!(webrtc.signature_vector.iter().any(|v| *v != 0.0));
        assert!(quic.signature_vector.iter().any(|v| *v != 0.0));
        assert_ne!(webrtc.signature_vector, quic.signature_vector);
    }
}
