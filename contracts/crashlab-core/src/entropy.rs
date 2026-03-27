//! High and low entropy byte-pattern generator for payload stress testing.
//!
//! Produces payloads at controlled entropy levels so the fuzzer can stress
//! host code paths sensitive to input randomness (compression, hashing,
//! caching, serialization).
//!
//! ## Entropy profiles
//!
//! | Profile | Description | Shannon entropy (bits/byte) |
//! |---------|-------------|-----------------------------|
//! | Low     | Repeating / structured bytes | ~0 – 3 |
//! | High    | Pseudo-random uniform bytes  | ~7 – 8 |
//!
//! ## Key components
//!
//! - [`EntropyProfile`]: Classification tag carried through to [`RunMetadata`].
//! - [`EntropyMutator`]: [`Mutator`] implementation that replaces the seed
//!   payload with a pattern matching the configured profile.
//! - [`shannon_entropy`]: Utility to measure actual byte-level entropy.
//! - [`generate_entropy_grid`]: Deterministic seed grid spanning both profiles.

use crate::prng::SeededPrng;
use crate::scheduler::Mutator;
use crate::CaseSeed;

/// Entropy classification for a generated payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum EntropyProfile {
    /// Low-entropy: repeating bytes, alternating pairs, sequential fills.
    Low,
    /// High-entropy: pseudo-random bytes with near-uniform distribution.
    High,
}

impl EntropyProfile {
    pub fn as_str(&self) -> &'static str {
        match self {
            EntropyProfile::Low => "low",
            EntropyProfile::High => "high",
        }
    }
}

/// Configuration for [`EntropyMutator`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntropyConfig {
    /// Target payload length in bytes.
    pub payload_len: usize,
    /// Which entropy profile to generate.
    pub profile: EntropyProfile,
}

impl Default for EntropyConfig {
    fn default() -> Self {
        Self {
            payload_len: 64,
            profile: EntropyProfile::High,
        }
    }
}

impl EntropyConfig {
    pub fn new(payload_len: usize, profile: EntropyProfile) -> Self {
        Self {
            payload_len: payload_len.max(1),
            profile,
        }
    }
}

/// Low-entropy pattern variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LowPattern {
    /// All zeros.
    Zeros,
    /// All `0xFF`.
    Ones,
    /// Repeating single byte chosen from seed.
    RepeatByte,
    /// Alternating two-byte pattern (e.g. `0xAA, 0x55`).
    Alternating,
    /// Sequential bytes `0, 1, 2, …`.
    Sequential,
}

const LOW_PATTERN_COUNT: usize = 5;

fn pick_low_pattern(rng_state: &mut u64) -> LowPattern {
    advance_rng(rng_state);
    match (*rng_state as usize) % LOW_PATTERN_COUNT {
        0 => LowPattern::Zeros,
        1 => LowPattern::Ones,
        2 => LowPattern::RepeatByte,
        3 => LowPattern::Alternating,
        _ => LowPattern::Sequential,
    }
}

/// Generates a low-entropy byte payload.
fn generate_low_entropy(len: usize, seed: &CaseSeed, rng_state: &mut u64) -> Vec<u8> {
    let pattern = pick_low_pattern(rng_state);
    match pattern {
        LowPattern::Zeros => vec![0x00; len],
        LowPattern::Ones => vec![0xFF; len],
        LowPattern::RepeatByte => {
            advance_rng(rng_state);
            let byte = (*rng_state ^ seed.id) as u8;
            vec![byte; len]
        }
        LowPattern::Alternating => {
            advance_rng(rng_state);
            let a = (*rng_state ^ seed.id) as u8;
            let b = a.wrapping_add(0x55);
            (0..len).map(|i| if i % 2 == 0 { a } else { b }).collect()
        }
        LowPattern::Sequential => (0..len).map(|i| (i % 8) as u8).collect(),
    }
}

/// Generates a high-entropy byte payload using the PRNG mutation stream.
fn generate_high_entropy(len: usize, seed: &CaseSeed) -> Vec<u8> {
    let mut prng = SeededPrng::new(seed.id);
    prng.mutation_stream(len)
}

/// Computes the Shannon entropy (in bits per byte) of a byte slice.
///
/// Returns a value in `[0.0, 8.0]`.  An empty slice yields `0.0`.
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut freq = [0u64; 256];
    for &b in data {
        freq[b as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Mutator that replaces the seed payload with a controlled-entropy pattern.
///
/// # Integration
///
/// ```rust
/// # use crashlab_core::scheduler::{WeightedScheduler, Mutator};
/// # use crashlab_core::entropy::{EntropyMutator, EntropyConfig, EntropyProfile};
/// # fn main() {
/// let mutators: Vec<(Box<dyn Mutator>, f64)> = vec![
///     (Box::new(EntropyMutator::new(EntropyConfig::new(64, EntropyProfile::High))), 3.0),
///     (Box::new(EntropyMutator::new(EntropyConfig::new(64, EntropyProfile::Low))), 2.0),
/// ];
/// let scheduler = WeightedScheduler::new(mutators).unwrap();
/// # }
/// ```
pub struct EntropyMutator {
    config: EntropyConfig,
}

impl EntropyMutator {
    pub fn new(config: EntropyConfig) -> Self {
        Self { config }
    }

    pub fn high(len: usize) -> Self {
        Self::new(EntropyConfig::new(len, EntropyProfile::High))
    }

    pub fn low(len: usize) -> Self {
        Self::new(EntropyConfig::new(len, EntropyProfile::Low))
    }

    pub fn profile(&self) -> EntropyProfile {
        self.config.profile
    }
}

impl Mutator for EntropyMutator {
    fn name(&self) -> &'static str {
        match self.config.profile {
            EntropyProfile::High => "entropy-high",
            EntropyProfile::Low => "entropy-low",
        }
    }

    fn mutate(&self, seed: &CaseSeed, rng_state: &mut u64) -> CaseSeed {
        let payload = match self.config.profile {
            EntropyProfile::High => generate_high_entropy(self.config.payload_len, seed),
            EntropyProfile::Low => generate_low_entropy(self.config.payload_len, seed, rng_state),
        };

        CaseSeed {
            id: seed.id,
            payload,
        }
    }
}

/// Deterministic [`CaseSeed`] grid covering both entropy profiles.
///
/// Produces seeds for each profile at several payload lengths, useful for
/// building a corpus that exercises entropy-sensitive code paths.
pub fn generate_entropy_grid(base_id: u64, lengths: &[usize]) -> Vec<CaseSeed> {
    let mut out = Vec::new();
    let mut id = base_id;

    for &len in lengths {
        for profile in [EntropyProfile::Low, EntropyProfile::High] {
            let config = EntropyConfig::new(len, profile);
            let mutator = EntropyMutator::new(config);
            let seed = CaseSeed {
                id,
                payload: vec![],
            };
            let mut rng = id;
            out.push(mutator.mutate(&seed, &mut rng));
            id += 1;
        }
    }

    out
}

fn advance_rng(state: &mut u64) {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    *state = z ^ (z >> 31);
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Shannon entropy utility ──────────────────────────────────────────────

    #[test]
    fn shannon_entropy_empty_is_zero() {
        assert_eq!(shannon_entropy(&[]), 0.0);
    }

    #[test]
    fn shannon_entropy_single_byte_is_zero() {
        assert_eq!(shannon_entropy(&[42]), 0.0);
    }

    #[test]
    fn shannon_entropy_all_same_is_zero() {
        assert_eq!(shannon_entropy(&vec![0xFF; 256]), 0.0);
    }

    #[test]
    fn shannon_entropy_uniform_256_values_is_eight() {
        let data: Vec<u8> = (0..=255u16).flat_map(|v| vec![v as u8; 10]).collect();
        let h = shannon_entropy(&data);
        assert!(
            (h - 8.0).abs() < 0.01,
            "expected ~8.0 bits/byte for uniform distribution, got {}",
            h
        );
    }

    #[test]
    fn shannon_entropy_two_equal_values_is_one_bit() {
        // Half 0x00, half 0xFF → entropy = 1.0 bit/byte.
        let mut data = vec![0x00; 128];
        data.extend(vec![0xFF; 128]);
        let h = shannon_entropy(&data);
        assert!((h - 1.0).abs() < 0.01, "expected ~1.0 bits/byte, got {}", h);
    }

    #[test]
    fn shannon_entropy_is_bounded() {
        let data: Vec<u8> = (0..1000).map(|i| (i % 17) as u8).collect();
        let h = shannon_entropy(&data);
        assert!(h >= 0.0 && h <= 8.0, "entropy {} out of range", h);
    }

    // ── Low entropy generation ───────────────────────────────────────────────

    #[test]
    fn low_entropy_payload_has_low_shannon_entropy() {
        let len = 256;
        // Test many seeds to cover all low-pattern variants.
        for id in 0..50u64 {
            let s = CaseSeed {
                id,
                payload: vec![],
            };
            let mut rng = id;
            let payload = generate_low_entropy(len, &s, &mut rng);
            let h = shannon_entropy(&payload);
            assert!(
                h <= 3.0,
                "seed {}: low entropy payload has shannon entropy {} > 3.0",
                id,
                h
            );
        }
    }

    #[test]
    fn low_entropy_zeros_pattern() {
        let seed = CaseSeed {
            id: 0,
            payload: vec![],
        };
        // Force Zeros pattern by seeding rng to produce it.
        // We test indirectly: generate many and check that some are all-zeros.
        let len = 64;
        let mut found_zeros = false;
        for r in 0..100u64 {
            let mut rng = r;
            let payload = generate_low_entropy(len, &seed, &mut rng);
            if payload.iter().all(|&b| b == 0) {
                found_zeros = true;
                break;
            }
        }
        assert!(
            found_zeros,
            "expected to find all-zeros low-entropy pattern"
        );
    }

    #[test]
    fn low_entropy_ones_pattern() {
        let seed = CaseSeed {
            id: 0,
            payload: vec![],
        };
        let len = 64;
        let mut found_ones = false;
        for r in 0..100u64 {
            let mut rng = r;
            let payload = generate_low_entropy(len, &seed, &mut rng);
            if payload.iter().all(|&b| b == 0xFF) {
                found_ones = true;
                break;
            }
        }
        assert!(found_ones, "expected to find all-0xFF low-entropy pattern");
    }

    // Update sequential test for new mod range
    #[test]
    fn low_entropy_sequential_pattern() {
        let seed = CaseSeed {
            id: 0,
            payload: vec![],
        };
        let len = 256;
        let mut found_seq = false;
        for r in 0..100u64 {
            let mut rng = r;
            let payload = generate_low_entropy(len, &seed, &mut rng);
            // Sequential pattern cycles through 0..7 (mod 8).
            if payload.len() >= 8 && payload[0] == 0 && payload[7] == 7 && payload[8] == 0 {
                found_seq = true;
                break;
            }
        }
        assert!(found_seq, "expected to find sequential low-entropy pattern");
    }

    #[test]
    fn low_entropy_alternating_pattern() {
        let seed = CaseSeed {
            id: 0,
            payload: vec![],
        };
        let len = 64;
        let mut found_alt = false;
        for r in 0..100u64 {
            let mut rng = r;
            let payload = generate_low_entropy(len, &seed, &mut rng);
            if payload.len() >= 4
                && payload[0] == payload[2]
                && payload[1] == payload[3]
                && payload[0] != payload[1]
            {
                found_alt = true;
                break;
            }
        }
        assert!(
            found_alt,
            "expected to find alternating low-entropy pattern"
        );
    }

    #[test]
    fn low_entropy_payload_length_matches_config() {
        let config = EntropyConfig::new(17, EntropyProfile::Low);
        let mutator = EntropyMutator::new(config);
        let seed = CaseSeed {
            id: 5,
            payload: vec![0; 100],
        };
        let result = mutator.mutate(&seed, &mut 42);
        assert_eq!(result.payload.len(), 17);
    }

    // ── High entropy generation ──────────────────────────────────────────────

    #[test]
    fn high_entropy_payload_has_high_shannon_entropy() {
        let len = 256;
        for id in 0..20u64 {
            let seed = CaseSeed {
                id,
                payload: vec![],
            };
            let payload = generate_high_entropy(len, &seed);
            let h = shannon_entropy(&payload);
            assert!(
                h >= 7.0,
                "seed {}: high entropy payload has shannon entropy {} < 7.0",
                id,
                h
            );
        }
    }

    #[test]
    fn high_entropy_payload_length_matches_config() {
        let config = EntropyConfig::new(33, EntropyProfile::High);
        let mutator = EntropyMutator::new(config);
        let seed = CaseSeed {
            id: 1,
            payload: vec![0; 200],
        };
        let result = mutator.mutate(&seed, &mut 99);
        assert_eq!(result.payload.len(), 33);
    }

    #[test]
    fn high_entropy_is_deterministic_for_same_seed() {
        let a = generate_high_entropy(
            128,
            &CaseSeed {
                id: 42,
                payload: vec![],
            },
        );
        let b = generate_high_entropy(
            128,
            &CaseSeed {
                id: 42,
                payload: vec![],
            },
        );
        assert_eq!(a, b);
    }

    #[test]
    fn high_entropy_differs_across_seeds() {
        let a = generate_high_entropy(
            128,
            &CaseSeed {
                id: 1,
                payload: vec![],
            },
        );
        let b = generate_high_entropy(
            128,
            &CaseSeed {
                id: 2,
                payload: vec![],
            },
        );
        assert_ne!(a, b);
    }

    #[test]
    fn high_entropy_byte_diversity() {
        let payload = generate_high_entropy(
            1024,
            &CaseSeed {
                id: 7,
                payload: vec![],
            },
        );
        let unique: std::collections::HashSet<u8> = payload.iter().copied().collect();
        assert!(
            unique.len() > 200,
            "expected high byte diversity, got {} unique values",
            unique.len()
        );
    }

    // ── Entropy gap (high vs low) ────────────────────────────────────────────

    #[test]
    fn high_entropy_exceeds_low_entropy_by_large_margin() {
        let seed = CaseSeed {
            id: 10,
            payload: vec![],
        };
        let len = 512;

        let high = generate_high_entropy(len, &seed);
        let h_high = shannon_entropy(&high);

        // Sample multiple low-entropy variants and take the max.
        let mut max_low = 0.0_f64;
        for r in 0..50u64 {
            let mut rng = r;
            let low = generate_low_entropy(len, &seed, &mut rng);
            let h = shannon_entropy(&low);
            max_low = max_low.max(h);
        }

        assert!(
            h_high - max_low >= 4.0,
            "expected entropy gap >= 4.0 bits/byte, got high={} low={}",
            h_high,
            max_low
        );
    }

    // ── EntropyMutator trait compliance ──────────────────────────────────────

    #[test]
    fn mutator_names_are_correct() {
        assert_eq!(EntropyMutator::high(64).name(), "entropy-high");
        assert_eq!(EntropyMutator::low(64).name(), "entropy-low");
    }

    #[test]
    fn mutator_preserves_seed_id() {
        let seed = CaseSeed {
            id: 777,
            payload: vec![0xAA; 30],
        };
        let result = EntropyMutator::high(16).mutate(&seed, &mut 0);
        assert_eq!(result.id, 777);

        let result = EntropyMutator::low(16).mutate(&seed, &mut 0);
        assert_eq!(result.id, 777);
    }

    #[test]
    fn mutator_is_deterministic_for_same_inputs() {
        let seed = CaseSeed {
            id: 42,
            payload: vec![],
        };
        let m = EntropyMutator::high(32);
        let a = m.mutate(&seed, &mut 10);
        let b = m.mutate(&seed, &mut 10);
        assert_eq!(a, b);
    }

    #[test]
    fn mutator_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<EntropyMutator>();
    }

    #[test]
    fn minimum_payload_length_is_one() {
        let config = EntropyConfig::new(0, EntropyProfile::High);
        assert_eq!(config.payload_len, 1);
    }

    // ── Profile string conversion ────────────────────────────────────────────

    #[test]
    fn profile_as_str() {
        assert_eq!(EntropyProfile::High.as_str(), "high");
        assert_eq!(EntropyProfile::Low.as_str(), "low");
    }

    // ── generate_entropy_grid ────────────────────────────────────────────────

    #[test]
    fn grid_is_deterministic() {
        let a = generate_entropy_grid(0, &[8, 16, 64]);
        let b = generate_entropy_grid(0, &[8, 16, 64]);
        assert_eq!(a, b);
    }

    #[test]
    fn grid_covers_both_profiles() {
        let grid = generate_entropy_grid(0, &[256]);
        assert_eq!(grid.len(), 2);

        // First should be low, second high (based on iteration order).
        let h_low = shannon_entropy(&grid[0].payload);
        let h_high = shannon_entropy(&grid[1].payload);
        assert!(h_low <= 3.0, "grid[0] should be low entropy, got {}", h_low);
        assert!(
            h_high >= 7.0,
            "grid[1] should be high entropy, got {}",
            h_high
        );
    }

    #[test]
    fn grid_payloads_match_requested_lengths() {
        let lengths = [1, 8, 64, 256];
        let grid = generate_entropy_grid(0, &lengths);
        for (i, seed) in grid.iter().enumerate() {
            let expected_len = lengths[i / 2];
            assert_eq!(
                seed.payload.len(),
                expected_len,
                "grid[{}] should have length {}",
                i,
                expected_len
            );
        }
    }

    #[test]
    fn grid_sequential_ids() {
        let grid = generate_entropy_grid(100, &[16, 32]);
        // 2 lengths * 2 profiles = 4 seeds
        assert_eq!(grid.len(), 4);
        for (i, seed) in grid.iter().enumerate() {
            assert_eq!(seed.id, 100 + i as u64);
        }
    }

    // ── Edge cases ───────────────────────────────────────────────────────────

    #[test]
    fn single_byte_payload_low_entropy() {
        let payload = generate_low_entropy(
            1,
            &CaseSeed {
                id: 0,
                payload: vec![],
            },
            &mut 0,
        );
        assert_eq!(payload.len(), 1);
        assert_eq!(shannon_entropy(&payload), 0.0);
    }

    #[test]
    fn single_byte_payload_high_entropy() {
        let payload = generate_high_entropy(
            1,
            &CaseSeed {
                id: 0,
                payload: vec![],
            },
        );
        assert_eq!(payload.len(), 1);
        assert_eq!(shannon_entropy(&payload), 0.0);
    }

    #[test]
    fn very_large_payload_low_entropy() {
        let len = 4096;
        let payload = generate_low_entropy(
            len,
            &CaseSeed {
                id: 0,
                payload: vec![],
            },
            &mut 0,
        );
        assert_eq!(payload.len(), len);
        assert!(shannon_entropy(&payload) <= 3.0);
    }

    #[test]
    fn very_large_payload_high_entropy() {
        let len = 4096;
        let payload = generate_high_entropy(
            len,
            &CaseSeed {
                id: 0,
                payload: vec![],
            },
        );
        assert_eq!(payload.len(), len);
        assert!(shannon_entropy(&payload) >= 7.0);
    }
}
