//! Probe rate limiting and adaptive timeout estimation.
//!
//! Both are pure arithmetic over an injected clock, so the pacing behaviour is
//! tested deterministically rather than by sleeping and hoping.

use std::time::Duration;

/// A token bucket.
///
/// Rate limiting a scan is not politeness alone: an unpaced sweep of a /16 will
/// overflow the ARP table of the first switch it crosses, and many access
/// points treat a burst of ARP requests as an attack and start dropping them,
/// which makes the scan report fewer hosts the faster it runs.
///
/// The bucket holds fractional tokens so that rates below one per second still
/// work, and it is driven by an explicit monotonic timestamp so tests do not
/// need to sleep.
#[derive(Debug, Clone)]
pub struct TokenBucket {
    /// Tokens added per second.
    rate: f64,
    /// Maximum tokens that can accumulate, which bounds burst size.
    capacity: f64,
    tokens: f64,
    last_update: Duration,
}

impl TokenBucket {
    /// Creates a bucket that refills at `rate` tokens per second.
    ///
    /// The bucket starts full, so the first `burst` probes go out immediately.
    pub fn new(rate: f64, burst: f64) -> Self {
        let capacity = burst.max(1.0);
        Self {
            rate: rate.max(0.0),
            capacity,
            tokens: capacity,
            last_update: Duration::ZERO,
        }
    }

    /// A bucket with a burst allowance of one second's worth of probes.
    pub fn per_second(rate: f64) -> Self {
        Self::new(rate, rate.max(1.0))
    }

    /// Adds tokens for the time elapsed since the last update.
    fn refill(&mut self, now: Duration) {
        // A clock that appears to move backwards must not remove tokens.
        if now <= self.last_update {
            self.last_update = now;
            return;
        }
        let elapsed = (now - self.last_update).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.rate).min(self.capacity);
        self.last_update = now;
    }

    /// Tolerance applied when comparing the token count against one.
    ///
    /// Refills accumulate in floating point, so a bucket topped up in several
    /// steps lands on 0.9999999999999999 rather than 1.0 and would refuse a
    /// probe that is genuinely due. Left uncorrected this compounds: the bucket
    /// runs a little slower than configured, and at low rates it can stall
    /// outright. The tolerance is far below one probe, so it cannot let the
    /// long-run rate exceed the configured one.
    const EPSILON: f64 = 1e-9;

    /// Takes one token if available.
    pub fn try_acquire(&mut self, now: Duration) -> bool {
        self.refill(now);
        if self.tokens >= 1.0 - Self::EPSILON {
            // Never go negative, which the tolerance would otherwise allow.
            self.tokens = (self.tokens - 1.0).max(0.0);
            true
        } else {
            false
        }
    }

    /// How long to wait before a token will be available.
    ///
    /// Returns `Duration::ZERO` when one is available now, and `None` when the
    /// rate is zero and no amount of waiting will produce one.
    pub fn time_until_available(&mut self, now: Duration) -> Option<Duration> {
        self.refill(now);
        if self.tokens >= 1.0 - Self::EPSILON {
            return Some(Duration::ZERO);
        }
        if self.rate <= 0.0 {
            return None;
        }
        Some(Duration::from_secs_f64((1.0 - self.tokens) / self.rate))
    }

    /// Tokens currently held, for tests and diagnostics.
    pub fn available(&self) -> f64 {
        self.tokens
    }
}

/// Round-trip time estimator following RFC 6298.
///
/// A fixed probe timeout is wrong in both directions: too short and a busy or
/// distant host is recorded as down, too long and a sweep of a quiet /24 spends
/// most of its time waiting on addresses where nothing exists. This tracks the
/// smoothed RTT and its variation and derives a timeout from both, so the scan
/// adapts to the network it is actually on.
#[derive(Debug, Clone)]
pub struct RttEstimator {
    /// Smoothed round-trip time.
    srtt: Option<Duration>,
    /// Round-trip time variation.
    rttvar: Duration,
    min_timeout: Duration,
    max_timeout: Duration,
}

impl RttEstimator {
    /// RFC 6298 alpha: weight given to each new measurement in the smoothed RTT.
    const ALPHA: f64 = 0.125;
    /// RFC 6298 beta: weight given to each new deviation in the variation.
    const BETA: f64 = 0.25;
    /// RFC 6298 K: how many deviations of headroom the timeout allows.
    const K: u32 = 4;

    pub fn new(min_timeout: Duration, max_timeout: Duration) -> Self {
        Self {
            srtt: None,
            rttvar: Duration::ZERO,
            min_timeout,
            max_timeout: max_timeout.max(min_timeout),
        }
    }

    /// Folds a new measurement into the estimate.
    pub fn observe(&mut self, rtt: Duration) {
        match self.srtt {
            // First measurement: RFC 6298 seeds the variation at half the RTT.
            None => {
                self.srtt = Some(rtt);
                self.rttvar = rtt / 2;
            }
            Some(srtt) => {
                // Duration cannot be negative, so the deviation is computed as
                // an absolute difference rather than by subtraction.
                let delta = if rtt > srtt { rtt - srtt } else { srtt - rtt };
                self.rttvar = self.rttvar.mul_f64(1.0 - Self::BETA) + delta.mul_f64(Self::BETA);
                self.srtt = Some(srtt.mul_f64(1.0 - Self::ALPHA) + rtt.mul_f64(Self::ALPHA));
            }
        }
    }

    /// The timeout to use for the next probe: `SRTT + K * RTTVAR`, clamped.
    pub fn timeout(&self) -> Duration {
        match self.srtt {
            // With no measurements yet, be pessimistic rather than fast.
            None => self.max_timeout,
            Some(srtt) => (srtt + Self::K * self.rttvar)
                .clamp(self.min_timeout, self.max_timeout),
        }
    }

    pub fn smoothed_rtt(&self) -> Option<Duration> {
        self.srtt
    }

    pub fn has_samples(&self) -> bool {
        self.srtt.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS: Duration = Duration::from_millis(1);

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    // ---- token bucket ------------------------------------------------------

    #[test]
    fn a_new_bucket_starts_full_so_the_first_burst_is_immediate() {
        let mut b = TokenBucket::new(10.0, 5.0);
        for i in 0..5 {
            assert!(b.try_acquire(Duration::ZERO), "token {i} should be free");
        }
        assert!(!b.try_acquire(Duration::ZERO), "burst should be exhausted");
    }

    #[test]
    fn tokens_refill_at_the_configured_rate() {
        let mut b = TokenBucket::new(100.0, 1.0);
        assert!(b.try_acquire(Duration::ZERO));
        assert!(!b.try_acquire(Duration::ZERO));
        // At 100/s one token takes 10ms.
        assert!(!b.try_acquire(ms(9)));
        assert!(b.try_acquire(ms(10)));
    }

    #[test]
    fn accumulated_tokens_are_capped_at_the_burst_size() {
        // Idling for an hour must not permit an hour's worth of probes at once.
        let mut b = TokenBucket::new(10.0, 5.0);
        for _ in 0..5 {
            assert!(b.try_acquire(Duration::ZERO));
        }
        b.refill(Duration::from_secs(3600));
        assert_eq!(b.available(), 5.0);
        for _ in 0..5 {
            assert!(b.try_acquire(Duration::from_secs(3600)));
        }
        assert!(!b.try_acquire(Duration::from_secs(3600)));
    }

    #[test]
    fn the_long_run_rate_matches_the_configured_rate() {
        // Drive a bucket for 10 simulated seconds and count what it allows.
        let rate = 50.0;
        let mut b = TokenBucket::new(rate, 1.0);
        let mut allowed = 0;
        // Poll every millisecond for 10 seconds.
        for tick in 0..10_000u64 {
            if b.try_acquire(ms(tick)) {
                allowed += 1;
            }
        }
        let expected = (rate * 10.0) as i64;
        // Allow the initial burst token and rounding.
        assert!(
            (allowed as i64 - expected).abs() <= 2,
            "allowed {allowed}, expected about {expected}"
        );
    }

    #[test]
    fn incremental_refills_do_not_stall_the_bucket() {
        // Refilling in many small steps accumulates floating-point error, so
        // the token count lands just under 1.0 exactly when a probe is due.
        // Without a tolerance the bucket runs slow and can stall at low rates.
        let mut b = TokenBucket::new(100.0, 1.0);
        assert!(b.try_acquire(Duration::ZERO));
        // Poll every millisecond; at 100/s the tenth poll must succeed.
        let mut acquired_at = None;
        for tick in 1..=10u64 {
            if b.try_acquire(ms(tick)) {
                acquired_at = Some(tick);
                break;
            }
        }
        assert_eq!(acquired_at, Some(10), "token should be due at exactly 10ms");
    }

    #[test]
    fn the_token_count_never_goes_negative() {
        // The acquire tolerance must not let the bucket borrow against itself.
        let mut b = TokenBucket::new(1.0, 1.0);
        for tick in 0..100u64 {
            b.try_acquire(ms(tick));
            assert!(b.available() >= 0.0, "negative tokens at tick {tick}");
        }
    }

    #[test]
    fn fractional_rates_below_one_per_second_still_work() {
        // 0.5/s: one probe every two seconds.
        let mut b = TokenBucket::new(0.5, 1.0);
        assert!(b.try_acquire(Duration::ZERO));
        assert!(!b.try_acquire(Duration::from_secs(1)));
        assert!(b.try_acquire(Duration::from_secs(2)));
    }

    #[test]
    fn wait_time_is_reported_accurately() {
        let mut b = TokenBucket::new(100.0, 1.0);
        assert_eq!(b.time_until_available(Duration::ZERO), Some(Duration::ZERO));
        assert!(b.try_acquire(Duration::ZERO));
        let wait = b.time_until_available(Duration::ZERO).unwrap();
        // One token at 100/s is 10ms.
        assert!(
            wait >= ms(9) && wait <= ms(11),
            "expected about 10ms, got {wait:?}"
        );
    }

    #[test]
    fn a_zero_rate_bucket_reports_no_wait_that_would_help() {
        let mut b = TokenBucket::new(0.0, 1.0);
        assert!(b.try_acquire(Duration::ZERO));
        assert_eq!(b.time_until_available(Duration::from_secs(1000)), None);
    }

    #[test]
    fn a_clock_moving_backwards_does_not_remove_tokens() {
        // Monotonic clocks can report equal or slightly earlier values across
        // threads; that must not make the bucket lose capacity.
        let mut b = TokenBucket::new(10.0, 5.0);
        b.refill(Duration::from_secs(10));
        let before = b.available();
        b.refill(Duration::from_secs(5));
        assert_eq!(b.available(), before);
    }

    // ---- RTT estimator -----------------------------------------------------

    #[test]
    fn the_first_measurement_seeds_srtt_and_variation() {
        // RFC 6298: SRTT = R, RTTVAR = R/2, so RTO = R + 4*(R/2) = 3R.
        let mut e = RttEstimator::new(ms(10), ms(5000));
        e.observe(ms(100));
        assert_eq!(e.smoothed_rtt(), Some(ms(100)));
        assert_eq!(e.timeout(), ms(300));
    }

    #[test]
    fn a_stable_rtt_converges_and_narrows_the_timeout() {
        let mut e = RttEstimator::new(ms(1), ms(5000));
        for _ in 0..100 {
            e.observe(ms(50));
        }
        let srtt = e.smoothed_rtt().unwrap();
        assert!(
            srtt >= ms(49) && srtt <= ms(51),
            "SRTT should converge to 50ms, got {srtt:?}"
        );
        // With no variation the timeout collapses towards the RTT itself.
        assert!(
            e.timeout() < ms(60),
            "timeout should tighten on a stable link, got {:?}",
            e.timeout()
        );
    }

    #[test]
    fn a_variable_rtt_widens_the_timeout() {
        let mut stable = RttEstimator::new(ms(1), ms(5000));
        let mut jittery = RttEstimator::new(ms(1), ms(5000));
        for i in 0..50 {
            stable.observe(ms(50));
            // Alternating 10ms and 90ms: same mean, much higher variation.
            jittery.observe(if i % 2 == 0 { ms(10) } else { ms(90) });
        }
        assert!(
            jittery.timeout() > stable.timeout(),
            "a jittery link must get more headroom: {:?} vs {:?}",
            jittery.timeout(),
            stable.timeout()
        );
    }

    #[test]
    fn the_timeout_is_clamped_to_the_configured_bounds() {
        // Far below the minimum.
        let mut fast = RttEstimator::new(ms(100), ms(5000));
        for _ in 0..50 {
            fast.observe(Duration::from_micros(50));
        }
        assert_eq!(fast.timeout(), ms(100));

        // Far above the maximum.
        let mut slow = RttEstimator::new(ms(10), ms(500));
        for _ in 0..50 {
            slow.observe(Duration::from_secs(10));
        }
        assert_eq!(slow.timeout(), ms(500));
    }

    #[test]
    fn with_no_samples_the_timeout_is_pessimistic() {
        // Starting fast would record every slow host as down.
        let e = RttEstimator::new(ms(10), ms(2000));
        assert!(!e.has_samples());
        assert_eq!(e.timeout(), ms(2000));
    }

    #[test]
    fn a_sudden_latency_spike_is_absorbed_gradually() {
        // Alpha is 1/8, so one outlier moves SRTT by an eighth of the gap
        // rather than dragging the whole estimate with it.
        let mut e = RttEstimator::new(MS, ms(5000));
        for _ in 0..50 {
            e.observe(ms(20));
        }
        let before = e.smoothed_rtt().unwrap();
        e.observe(ms(500));
        let after = e.smoothed_rtt().unwrap();
        assert!(after > before);
        assert!(
            after < ms(100),
            "one outlier should not dominate: {after:?}"
        );
    }

    #[test]
    fn a_downward_step_is_tracked_without_underflow() {
        // The deviation is an absolute difference; subtracting Durations the
        // other way round would panic.
        let mut e = RttEstimator::new(MS, ms(5000));
        for _ in 0..30 {
            e.observe(ms(200));
        }
        for _ in 0..200 {
            e.observe(ms(5));
        }
        let srtt = e.smoothed_rtt().unwrap();
        assert!(srtt < ms(20), "should track downward, got {srtt:?}");
    }

    #[test]
    fn zero_rtt_measurements_are_handled() {
        // Loopback probes routinely complete inside the clock's resolution.
        let mut e = RttEstimator::new(MS, ms(1000));
        e.observe(Duration::ZERO);
        e.observe(Duration::ZERO);
        assert_eq!(e.smoothed_rtt(), Some(Duration::ZERO));
        assert_eq!(e.timeout(), MS, "clamped to the minimum");
    }
}
