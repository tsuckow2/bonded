//! Transport overhead measurement for a fixed-payload transfer.
//!
//! Definitions (these are the contract the diagnostic UI reports):
//! - `payload_bytes`: application payload, known and fixed (the
//!   diagnostic chooses it: 256 KiB, 1 MiB, or 10 MiB).
//! - `inside_*_bytes`: TUN IP packet bytes over the transfer window
//!   (the session snapshot's outbound/inbound counters, which count
//!   TUN packet lengths — IP header + TCP header + payload — in each
//!   direction). Session frame headers are NOT inside bytes; they are
//!   wire overhead.
//! - `wire_*_bytes`: socket bytes over the same window, from the
//!   transport's [`crate::transport::WireStats`] (session framing +
//!   transport framing + encryption; excludes IP/UDP/TCP headers below
//!   the socket). `None` when the transport cannot observe socket
//!   bytes (WebSocketTls today).
//! - `overhead_*_bytes`: `wire - inside` (saturating: counter windows
//!   can skew by a packet when the two snapshots are not simultaneous).
//! - Bandwidths are bytes × 8 / elapsed seconds. An elapsed time of
//!   zero yields 0 bps rather than infinity.

use std::time::Duration;

/// One transfer's measured inputs. Byte counts are deltas over the
/// transfer window (counter after minus counter before).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OverheadInput {
    pub payload_bytes: u64,
    pub inside_tx_bytes: u64,
    pub inside_rx_bytes: u64,
    pub wire_tx_bytes: Option<u64>,
    pub wire_rx_bytes: Option<u64>,
    pub elapsed: Duration,
}

/// A transfer's overhead report. `None` fields mean the transport
/// could not measure wire bytes (see [`crate::transport::WireStats`]).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct OverheadReport {
    pub payload_bytes: u64,
    pub inside_tx_bytes: u64,
    pub inside_rx_bytes: u64,
    pub wire_tx_bytes: Option<u64>,
    pub wire_rx_bytes: Option<u64>,
    pub overhead_tx_bytes: Option<u64>,
    pub overhead_rx_bytes: Option<u64>,
    pub overhead_tx_ratio: Option<f64>,
    pub overhead_rx_ratio: Option<f64>,
    pub elapsed: Duration,
    /// Application payload throughput.
    pub payload_bandwidth_bps: f64,
    /// TUN-byte throughput in each direction.
    pub inside_tx_bandwidth_bps: f64,
    pub inside_rx_bandwidth_bps: f64,
    /// Socket-byte throughput in each direction.
    pub wire_tx_bandwidth_bps: Option<f64>,
    pub wire_rx_bandwidth_bps: Option<f64>,
}

fn bandwidth_bps(bytes: u64, elapsed: Duration) -> f64 {
    let secs = elapsed.as_secs_f64();
    if secs <= 0.0 {
        0.0
    } else {
        bytes as f64 * 8.0 / secs
    }
}

fn overhead_ratio(overhead: u64, inside: u64) -> Option<f64> {
    if inside == 0 {
        None
    } else {
        Some(overhead as f64 / inside as f64)
    }
}

pub fn compute_overhead(input: OverheadInput) -> OverheadReport {
    let overhead_tx_bytes = input
        .wire_tx_bytes
        .map(|wire| wire.saturating_sub(input.inside_tx_bytes));
    let overhead_rx_bytes = input
        .wire_rx_bytes
        .map(|wire| wire.saturating_sub(input.inside_rx_bytes));
    OverheadReport {
        payload_bytes: input.payload_bytes,
        inside_tx_bytes: input.inside_tx_bytes,
        inside_rx_bytes: input.inside_rx_bytes,
        wire_tx_bytes: input.wire_tx_bytes,
        wire_rx_bytes: input.wire_rx_bytes,
        overhead_tx_bytes,
        overhead_rx_bytes,
        overhead_tx_ratio: overhead_tx_bytes
            .and_then(|overhead| overhead_ratio(overhead, input.inside_tx_bytes)),
        overhead_rx_ratio: overhead_rx_bytes
            .and_then(|overhead| overhead_ratio(overhead, input.inside_rx_bytes)),
        elapsed: input.elapsed,
        payload_bandwidth_bps: bandwidth_bps(input.payload_bytes, input.elapsed),
        inside_tx_bandwidth_bps: bandwidth_bps(input.inside_tx_bytes, input.elapsed),
        inside_rx_bandwidth_bps: bandwidth_bps(input.inside_rx_bytes, input.elapsed),
        wire_tx_bandwidth_bps: input
            .wire_tx_bytes
            .map(|wire| bandwidth_bps(wire, input.elapsed)),
        wire_rx_bandwidth_bps: input
            .wire_rx_bytes
            .map(|wire| bandwidth_bps(wire, input.elapsed)),
    }
}

#[cfg(test)]
mod tests {
    use super::{compute_overhead, OverheadInput};
    use std::time::Duration;

    fn input() -> OverheadInput {
        OverheadInput {
            payload_bytes: 1_048_576,
            inside_tx_bytes: 1_060_000,
            inside_rx_bytes: 1_060_000,
            wire_tx_bytes: Some(1_075_000),
            wire_rx_bytes: Some(1_075_000),
            elapsed: Duration::from_secs(2),
        }
    }

    #[test]
    fn overhead_is_wire_minus_inside_with_ratio_and_bandwidths() {
        let report = compute_overhead(input());
        assert_eq!(report.overhead_tx_bytes, Some(15_000));
        assert_eq!(report.overhead_rx_bytes, Some(15_000));
        let ratio = report.overhead_tx_ratio.expect("ratio should exist");
        assert!((ratio - 15_000.0 / 1_060_000.0).abs() < 1e-12);
        assert_eq!(report.payload_bandwidth_bps, 1_048_576.0 * 8.0 / 2.0);
        assert_eq!(report.inside_tx_bandwidth_bps, 1_060_000.0 * 8.0 / 2.0);
        assert_eq!(report.wire_tx_bandwidth_bps, Some(1_075_000.0 * 8.0 / 2.0));
    }

    #[test]
    fn unmeasured_wire_yields_no_overhead_fields() {
        let mut missing = input();
        missing.wire_tx_bytes = None;
        missing.wire_rx_bytes = None;
        let report = compute_overhead(missing);
        assert_eq!(report.overhead_tx_bytes, None);
        assert_eq!(report.overhead_tx_ratio, None);
        assert_eq!(report.wire_tx_bandwidth_bps, None);
        // Payload and inside bandwidths are still computable.
        assert!(report.payload_bandwidth_bps > 0.0);
        assert!(report.inside_tx_bandwidth_bps > 0.0);
    }

    #[test]
    fn zero_elapsed_yields_zero_bandwidths_not_infinity() {
        let mut zero = input();
        zero.elapsed = Duration::ZERO;
        let report = compute_overhead(zero);
        assert_eq!(report.payload_bandwidth_bps, 0.0);
        assert_eq!(report.inside_tx_bandwidth_bps, 0.0);
        assert_eq!(report.wire_tx_bandwidth_bps, Some(0.0));
    }

    #[test]
    fn wire_below_inside_saturates_at_zero() {
        let mut skewed = input();
        skewed.wire_tx_bytes = Some(1_000_000);
        let report = compute_overhead(skewed);
        assert_eq!(report.overhead_tx_bytes, Some(0));
        assert_eq!(report.overhead_tx_ratio, Some(0.0));
    }
}
