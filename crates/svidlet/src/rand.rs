//! A SplitMix64 seeded from the operating system.
//!
//! Renewal jitter needs to be unpredictable enough to spread a fleet, not
//! cryptographically strong — the certificate keys come from `ring`, not from
//! here. Keeping this at ~30 lines avoids a dependency in the DaemonSet.

use std::sync::atomic::{AtomicU64, Ordering};

static STATE: AtomicU64 = AtomicU64::new(0);

/// Seed from `/dev/urandom`, falling back to the clock and the PID.
///
/// The fallback matters: a fleet where every node seeded identically would
/// renew in lockstep, which is exactly what the jitter exists to prevent.
pub fn seed() {
    let mut buf = [0u8; 8];
    let seed = match std::fs::File::open("/dev/urandom") {
        Ok(mut f) => {
            use std::io::Read as _;
            f.read_exact(&mut buf)
                .ok()
                .map(|()| u64::from_ne_bytes(buf))
        }
        Err(_) => None,
    }
    .unwrap_or_else(|| {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        nanos ^ ((std::process::id() as u64) << 32)
    });
    STATE.store(seed | 1, Ordering::Relaxed);
}

pub fn next_u64() -> u64 {
    let mut z = STATE.fetch_add(0x9E37_79B9_7F4A_7C15, Ordering::Relaxed);
    z = z.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Uniform in `[0, 1)`.
pub fn unit() -> f64 {
    (next_u64() >> 11) as f64 / (1u64 << 53) as f64
}

/// Uniform in `[low, high]`, inclusive; returns `low` if the range is empty.
pub fn range_i64(low: i64, high: i64) -> i64 {
    if high <= low {
        return low;
    }
    let span = (high - low) as u64 + 1;
    low + (next_u64() % span) as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_stays_in_range_and_varies() {
        seed();
        let samples: Vec<f64> = (0..1000).map(|_| unit()).collect();
        assert!(samples.iter().all(|v| (0.0..1.0).contains(v)));
        let distinct = samples
            .iter()
            .map(|v| (v * 1000.0) as u64)
            .collect::<std::collections::HashSet<_>>();
        assert!(
            distinct.len() > 500,
            "only {} distinct buckets",
            distinct.len()
        );
    }

    #[test]
    fn range_is_inclusive_and_bounded() {
        seed();
        for _ in 0..1000 {
            let v = range_i64(10, 12);
            assert!((10..=12).contains(&v));
        }
        assert_eq!(range_i64(5, 5), 5);
        assert_eq!(range_i64(5, 1), 5);
    }
}
