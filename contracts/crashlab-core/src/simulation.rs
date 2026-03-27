//! Bounded simulation runs with configurable wall-clock timeouts.
//!
//! When a user-supplied simulator exceeds the configured limit, the result is a
//! [`CrashSignature`](crate::CrashSignature) with category `"timeout"` so runs
//! can be triaged like other failure classes.

use crate::entropy::EntropyProfile;
use crate::{compute_signature_hash, CaseSeed, CrashSignature};
use serde::{Deserialize, Serialize};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

/// Wall-clock limit for a single simulation invocation (milliseconds).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SimulationTimeoutConfig {
    pub timeout_ms: u64,
}

impl SimulationTimeoutConfig {
    pub const fn new(timeout_ms: u64) -> Self {
        Self { timeout_ms }
    }
}

/// Metadata surfaced alongside a fuzzing run (e.g. for dashboards and CI logs).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunMetadata {
    /// Active simulation timeout used for this run (milliseconds).
    pub simulation_timeout_ms: u64,
    /// Entropy profile used for payload generation, if configured.
    pub entropy_profile: Option<EntropyProfile>,
}

impl RunMetadata {
    pub fn from_timeout_config(cfg: &SimulationTimeoutConfig) -> Self {
        Self {
            simulation_timeout_ms: cfg.timeout_ms,
            entropy_profile: None,
        }
    }

    pub fn with_entropy_profile(mut self, profile: EntropyProfile) -> Self {
        self.entropy_profile = Some(profile);
        self
    }
}

/// Builds the crash signature used when a simulation hits the timeout wall.
pub fn timeout_crash_signature(seed: &CaseSeed) -> CrashSignature {
    let category = "timeout";
    let digest = seed.payload.iter().fold(seed.id, |acc, b| {
        acc.wrapping_mul(1099511628211).wrapping_add(*b as u64)
    }) ^ 0x7F4A_7C15_4E3F_4E3Fu64;
    let signature_hash = compute_signature_hash(category, &seed.payload);
    CrashSignature {
        category: category.to_string(),
        digest,
        signature_hash,
    }
}

/// Runs `simulator` on a worker thread; if it does not finish within `config`,
/// returns [`timeout_crash_signature`] instead.
///
/// If the timeout fires, the worker thread is not forcibly stopped (host code
/// may still run to completion in the background).
pub fn run_simulation_with_timeout<F>(
    seed: &CaseSeed,
    config: &SimulationTimeoutConfig,
    simulator: F,
) -> CrashSignature
where
    F: FnOnce(&CaseSeed) -> CrashSignature + Send + 'static,
{
    if config.timeout_ms == 0 {
        return timeout_crash_signature(seed);
    }

    let seed_clone = seed.clone();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let sig = simulator(&seed_clone);
        let _ = tx.send(sig);
    });

    match rx.recv_timeout(Duration::from_millis(config.timeout_ms)) {
        Ok(sig) => sig,
        Err(_) => timeout_crash_signature(seed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classify;
    use std::thread;
    use std::time::Duration as StdDuration;

    #[test]
    fn fast_simulator_returns_normally() {
        let seed = CaseSeed {
            id: 1,
            payload: vec![0x50],
        };
        let cfg = SimulationTimeoutConfig::new(500);
        let sig = run_simulation_with_timeout(&seed, &cfg, |s| classify(s));
        assert_ne!(sig.category, "timeout");
    }

    #[test]
    fn slow_simulator_marks_timeout() {
        let seed = CaseSeed {
            id: 2,
            payload: vec![0x40, 0x41],
        };
        let cfg = SimulationTimeoutConfig::new(30);
        let sig = run_simulation_with_timeout(&seed, &cfg, |_| {
            thread::sleep(StdDuration::from_millis(200));
            classify(&CaseSeed {
                id: 2,
                payload: vec![0x40, 0x41],
            })
        });
        assert_eq!(sig.category, "timeout");
    }

    #[test]
    fn zero_timeout_immediately_times_out() {
        let seed = CaseSeed {
            id: 3,
            payload: vec![1],
        };
        let cfg = SimulationTimeoutConfig::new(0);
        let sig = run_simulation_with_timeout(&seed, &cfg, |s| classify(s));
        assert_eq!(sig.category, "timeout");
    }

    #[test]
    fn run_metadata_surfaces_timeout() {
        let cfg = SimulationTimeoutConfig::new(1234);
        let meta = RunMetadata::from_timeout_config(&cfg);
        assert_eq!(meta.simulation_timeout_ms, 1234);
        assert!(meta.entropy_profile.is_none());
    }

    #[test]
    fn run_metadata_carries_entropy_profile() {
        let cfg = SimulationTimeoutConfig::new(500);
        let meta =
            RunMetadata::from_timeout_config(&cfg).with_entropy_profile(EntropyProfile::High);
        assert_eq!(meta.entropy_profile, Some(EntropyProfile::High));
    }
}
