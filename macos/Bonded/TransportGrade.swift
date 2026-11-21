// TransportGrade.swift — per-transport grades (plan 4.50), ported
// from android/lib/models/transport_grade.dart +
// grade_scoring.dart (slice 4.98).
//
// The port is faithful: same weights, thresholds, sampling rules,
// and scoring functions, so a macOS grade means the same thing as
// an Android grade. The grade is explainable — every component
// carries its measurement, and a component with no data yet scores
// nothing (the total rebalances over the components that do have
// data).
//
// Weights: latency 30 / stability 30 / loss 20 / bandwidth 20.
//   * Latency (30): median active-path RTT from a histogram
//     (buckets [50, 100, 200, 350, 500] ms; the median is the
//     bucket midpoint). 100 at ≤ 50 ms, 0 at ≥ 500 ms.
//   * Stability (30): flaps per hour (a re-dial, or a rejoin
//     after being inactive, counts once per sample at most).
//     100 at 0, 0 at ≥ 12. Only scored after ≥ 60 s sampled.
//   * Loss (20): this path's QUIC loss rate (lost / sent).
//     100 at 0%, 0 at ≥ 10%. Only scored after ≥ 100 packets
//     sent. Non-QUIC paths never observe loss and never get a
//     loss score — never a fabricated 0.
//   * Bandwidth (20): share of active windows (bytes moved) that
//     were saturated — RTT inflated ≥ 1.5× and ≥ +100 ms against
//     the path's low-water mark, or the interval loss rate spiked
//     (≥ 20 packets, ≥ 5% lost). 100 when no window saturated.
//     Only scored after ≥ 10 active windows.
// Exploration prior (plan 4.86): a transport with insufficient
// data (sent < 100 packets AND active windows < 10) grades 99,
// just below a known-perfect 100, so it gets tried and gathers
// data. Once either threshold is met the grade becomes the
// measured total.

import Foundation

// MARK: - Scoring primitives (grade_scoring.dart)

/// Median active-path RTT in ms: 100 at ≤ 50 ms, 0 at ≥ 500 ms.
func latencyScoreFromMedianRtt(_ medianMs: Double) -> Double {
    clamp01((500 - medianMs) / 450) * 100
}

/// Flaps per hour: 100 at 0, 0 at ≥ 12.
func stabilityScoreFromFlapsPerHour(_ flapsPerHour: Double) -> Double {
    clamp01((12 - flapsPerHour) / 12) * 100
}

/// Loss rate 0–1: 100 at 0%, 0 at ≥ 10%.
func lossScoreFromRate(_ rate: Double) -> Double {
    clamp01((0.10 - rate) / 0.099) * 100
}

/// Share of active windows that were saturated, 0–1: 100 when
/// none saturated.
func bandwidthScoreFromSaturatedShare(_ share: Double) -> Double {
    (1 - min(max(share, 0), 1)) * 100
}

/// Letter bands: 90+ A, 80+ B, 70+ C, 60+ D, below 60 F.
func letterForScore(_ total: Int) -> String {
    if total >= 90 { return "A" }
    if total >= 80 { return "B" }
    if total >= 70 { return "C" }
    if total >= 60 { return "D" }
    return "F"
}

/// One graded component's weight and score, for the rebalancing
/// total. A nil score means the component has no data yet and is
/// excluded (weights rebalance over the rest).
struct WeightedComponent {
    let weight: Double
    let score: Double?
}

/// Weighted total over the components that have data, rebalanced
/// proportionally. Nil when no component has data yet.
func totalScore(_ components: [WeightedComponent]) -> Int? {
    var weightSum = 0.0
    var scoreSum = 0.0
    for component in components {
        guard let score = component.score else { continue }
        weightSum += component.weight
        scoreSum += component.weight * score
    }
    guard weightSum > 0 else { return nil }
    return Int((scoreSum / weightSum).rounded())
}

func clamp01(_ value: Double) -> Double {
    min(max(value, 0), 1)
}

/// RTT histogram buckets (ms). Upper bounds [50, 100, 200, 350,
/// 500, ∞]; midpoints used for the score interpolation (the open
/// top bucket counts as 750 ms).
let rttBounds = [50, 100, 200, 350, 500]
let rttMidpoints = [25.0, 75.0, 150.0, 275.0, 425.0, 750.0]

func rttBandLabel(_ bucket: Int) -> String {
    if bucket == 0 { return "median ≤ 50 ms" }
    if bucket >= rttBounds.count { return "median > 500 ms" }
    return "median \(rttBounds[bucket - 1])–\(rttBounds[bucket]) ms"
}

/// Median bucket of a histogram: the bucket holding the 50th
/// percentile. Bounded memory (one counter per bucket) at the
/// cost of an approximate median — the bands are the point, not
/// the exact value, so the grade shows the band, never a
/// fake-precise number. Scores interpolate from the bucket
/// midpoint (a documented convention).
func medianBucketIndex(_ counts: [Int]) -> Int {
    let total = counts.reduce(0, +)
    guard total > 0 else { return 0 }
    var seen = 0
    let target = (total + 1) / 2
    for (index, count) in counts.enumerated() {
        seen += count
        if seen >= target { return index }
    }
    return counts.count - 1
}

/// Bucket index for a value against ascending bounds; the open top
/// bucket is bounds.count.
func bucketIndex(_ value: Int, _ bounds: [Int]) -> Int {
    for (index, bound) in bounds.enumerated() {
        if value <= bound { return index }
    }
    return bounds.count
}

/// "3m 12s" style duration for the grade's sample line.
func formatSampledFor(_ milliseconds: Int) -> String {
    let totalSeconds = milliseconds / 1000
    let hours = totalSeconds / 3600
    let minutes = (totalSeconds % 3600) / 60
    let seconds = totalSeconds % 60
    if hours > 0 { return "\(hours)h \(minutes)m" }
    if minutes > 0 { return "\(minutes)m \(seconds)s" }
    return "\(seconds)s"
}

// MARK: - Grade value

/// One transport's grade: the total, the letter, and the
/// sub-scores with their measurements, so the grade is
/// explainable. Sub-scores are nil alongside a nil detail when
/// the component has no data yet.
struct TransportGrade: Equatable {
    let total: Int
    let letter: String
    let latencyScore: Double?
    let stabilityScore: Double?
    let lossScore: Double?
    let bandwidthScore: Double?
    let latencyDetail: String?
    let stabilityDetail: String?
    let lossDetail: String?
    let bandwidthDetail: String?
    /// Milliseconds of sampled time behind this grade.
    let sampledForMs: Int
    let sampleCount: Int
    /// True when the total is the exploration prior (99), not a
    /// measured total.
    let isPrior: Bool
}

// MARK: - Tracker (transport_grade.dart)

/// Per-transport grade tracker. Call record() on the UI poll tick
/// while connected; samples outside a session are ignored.
final class TransportGradeTracker {
    static let weights: [String: Double] = [
        "latency": 30,
        "stability": 30,
        "loss": 20,
        "bandwidth": 20,
    ]

    /// Stability needs this much sampled time before it scores.
    static let minStabilityMs = 60_000
    /// Loss needs this many packets sent before it scores.
    static let minLossSentPackets = 100
    /// Bandwidth needs this many active windows before it scores.
    static let minBandwidthActiveIntervals = 10
    /// Intervals longer than this are unknown time (app
    /// backgrounded, window left): skipped, not counted up or
    /// down. 35 s admits the 30 s background cadence.
    static let maxIntervalMs = 35_000
    /// Flaps/h at which Stability hits zero.
    static let maxFlapsPerHour = 12.0
    /// Saturation signals: RTT inflation vs the path's low-water
    /// mark, and an interval loss spike under load.
    static let minRttInflationMs = 100
    static let minRttInflationFactor = 1.5
    static let minLossSpikePackets = 20
    static let lossSpikeRate = 0.05
    /// Exploration prior (plan 4.86): a transport with
    /// insufficient data grades this, not its thin measured
    /// total. 99 is just below a known-perfect 100 and above most
    /// known-worse transports, so BestTransport tries it and it
    /// gathers data.
    static let priorGradeTotal = 99

    private struct PathState {
        var sampledMs = 0
        var samples = 0
        var rttBuckets = [Int](repeating: 0, count: rttBounds.count + 1)
        var rttSamples = 0
        var flapEvents = 0
        var lostTotal = 0
        var sentTotal = 0
        var activeIntervals = 0
        var saturatedIntervals = 0
        var lowWaterRttMs: Int?
        var prevActive: Bool?
        var prevPingFrames: Int?
        var prevInBytes: Int?
        var prevOutBytes: Int?
        var prevLostPackets: Int?
        var prevSentPackets: Int?
        var hasBaseline = false
    }

    private var sessionId = 0
    private var lastSampleAt: Date?
    private var paths: [String: PathState] = [:]

    /// The grade for one path by its gradeKey, or nil when the
    /// path has no data yet.
    func gradeFor(_ key: String) -> TransportGrade? {
        guard let state = paths[key] else { return nil }
        return grade(state)
    }

    /// Grades for every path with data, keyed by gradeKey.
    var grades: [String: TransportGrade] {
        var out: [String: TransportGrade] = [:]
        for (key, state) in paths {
            if let grade = grade(state) { out[key] = grade }
        }
        return out
    }

    private func grade(_ state: PathState) -> TransportGrade? {
        var latencyScore: Double?
        var latencyDetail: String?
        if state.rttSamples > 0 {
            let bucket = medianBucketIndex(state.rttBuckets)
            latencyScore = latencyScoreFromMedianRtt(rttMidpoints[bucket])
            latencyDetail = rttBandLabel(bucket)
        }

        var stabilityScore: Double?
        var stabilityDetail: String?
        if state.sampledMs >= Self.minStabilityMs {
            let hours = Double(state.sampledMs) / 3_600_000
            let rate = Double(state.flapEvents) / hours
            stabilityScore = stabilityScoreFromFlapsPerHour(rate)
            stabilityDetail = "\(state.flapEvents) flap" +
                (state.flapEvents == 1 ? "" : "s") +
                " · \(String(format: "%.1f", rate))/h"
        }

        var lossScore: Double?
        var lossDetail: String?
        if state.sentTotal >= Self.minLossSentPackets {
            let rate = Double(state.lostTotal) / Double(state.sentTotal)
            lossScore = lossScoreFromRate(rate)
            lossDetail = String(format: "%.1f%% lost · %d/%d packets",
                rate * 100, state.lostTotal, state.sentTotal)
        }

        var bandwidthScore: Double?
        var bandwidthDetail: String?
        if state.activeIntervals >= Self.minBandwidthActiveIntervals {
            let share = Double(state.saturatedIntervals)
                / Double(state.activeIntervals)
            bandwidthScore = bandwidthScoreFromSaturatedShare(share)
            if state.saturatedIntervals > 0 {
                bandwidthDetail = "\(state.saturatedIntervals) of " +
                    "\(state.activeIntervals) active windows saturated"
            } else {
                bandwidthDetail = "no saturation in " +
                    "\(state.activeIntervals) active windows"
            }
        }

        // Exploration prior (4.86): insufficient data — not enough
        // traffic to measure loss or bandwidth — grades 99 so this
        // transport gets tried and gathers data. The sub-scores
        // stay the honest measurements (they may show what little
        // data exists); only the total is the prior.
        let insufficientData = state.sentTotal < Self.minLossSentPackets
            && state.activeIntervals < Self.minBandwidthActiveIntervals
        if insufficientData {
            return TransportGrade(
                total: Self.priorGradeTotal,
                letter: letterForScore(Self.priorGradeTotal),
                latencyScore: latencyScore,
                stabilityScore: stabilityScore,
                lossScore: lossScore,
                bandwidthScore: bandwidthScore,
                latencyDetail: latencyDetail,
                stabilityDetail: stabilityDetail,
                lossDetail: lossDetail,
                bandwidthDetail: bandwidthDetail,
                sampledForMs: state.sampledMs,
                sampleCount: state.samples,
                isPrior: true)
        }

        guard let total = totalScore([
            WeightedComponent(
                weight: Self.weights["latency"] ?? 0, score: latencyScore),
            WeightedComponent(
                weight: Self.weights["stability"] ?? 0, score: stabilityScore),
            WeightedComponent(
                weight: Self.weights["loss"] ?? 0, score: lossScore),
            WeightedComponent(
                weight: Self.weights["bandwidth"] ?? 0,
                score: bandwidthScore),
        ]) else { return nil }
        return TransportGrade(
            total: total,
            letter: letterForScore(total),
            latencyScore: latencyScore,
            stabilityScore: stabilityScore,
            lossScore: lossScore,
            bandwidthScore: bandwidthScore,
            latencyDetail: latencyDetail,
            stabilityDetail: stabilityDetail,
            lossDetail: lossDetail,
            bandwidthDetail: bandwidthDetail,
            sampledForMs: state.sampledMs,
            sampleCount: state.samples,
            isPrior: false)
    }

    /// Starts a new session (connectedAtMs as the id). Resets all
    /// per-path accumulation: path keys and counters do not carry
    /// across sessions.
    func beginSession(_ connectedAtMs: Int) {
        reset()
        sessionId = connectedAtMs
    }

    /// One snapshot sample. Call on the existing poll tick while
    /// connected; samples outside a session are ignored. A session
    /// id change re-baselines without counting (the caller normally
    /// calls beginSession first).
    func record(_ status: SessionSnapshot, now: Date) {
        guard status.isConnected else { return }
        if status.connectedAtMs != sessionId {
            reset()
            sessionId = status.connectedAtMs
        }
        let prevAt = lastSampleAt
        let dtMs: Int
        if let prev = prevAt {
            dtMs = Int(now.timeIntervalSince(prev) * 1000)
        } else {
            dtMs = 0
        }
        if prevAt == nil || dtMs <= 0 || dtMs > Self.maxIntervalMs {
            // First sample, clock oddity, or a gap the stream did
            // not observe (backgrounded): re-baseline every path
            // present, count nothing. Paths absent from this
            // sample lose their baseline too, so their deltas
            // never span the gap when they return.
            lastSampleAt = now
            for key in paths.keys {
                paths[key]?.hasBaseline = false
            }
            for path in status.paths {
                var state = paths[path.gradeKey] ?? PathState()
                rebaseline(&state, path)
                paths[path.gradeKey] = state
            }
            return
        }

        for path in status.paths {
            var state = paths[path.gradeKey] ?? PathState()
            if !state.hasBaseline {
                rebaseline(&state, path)
                paths[path.gradeKey] = state
                continue
            }
            state.sampledMs += dtMs
            state.samples += 1

            let rtt = path.lastRttMs
            if rtt > 0 {
                state.rttBuckets[bucketIndex(rtt, rttBounds)] += 1
                state.rttSamples += 1
            }

            // Stability: a re-dial (PING counter restarts from
            // zero) or a rejoin after being inactive. At most one
            // flap per sample per path.
            var flapped = false
            if let prevPing = state.prevPingFrames,
               let ping = path.quicPingFrames,
               ping < prevPing
            {
                flapped = true
            }
            if state.prevActive == false && path.active {
                flapped = true
            }
            if flapped { state.flapEvents += 1 }

            // Loss deltas from the cumulative counters. A negative
            // delta is a counter reset (re-dial), not negative loss.
            let lostDelta = delta(path.quicLostPackets, state.prevLostPackets)
            let sentDelta = delta(path.quicSentPackets, state.prevSentPackets)
            if let lost = lostDelta, let sent = sentDelta {
                state.lostTotal += lost
                state.sentTotal += sent
            }

            // Bandwidth: an active window moved bytes. It is
            // saturated when RTT inflates against this path's
            // low-water mark under that load, or the interval loss
            // rate spikes. The low-water mark is from earlier
            // samples only — the current sample cannot inflate
            // against itself.
            let inDelta = delta(path.inboundBytes, state.prevInBytes) ?? 0
            let outDelta = delta(path.outboundBytes, state.prevOutBytes) ?? 0
            let moved = inDelta + outDelta
            if moved > 0 {
                state.activeIntervals += 1
                let lowWater = state.lowWaterRttMs
                let rttInflated = lowWater != nil
                    && rtt > 0
                    && Double(rtt) >= Double(lowWater!) * Self.minRttInflationFactor
                    && rtt - lowWater! >= Self.minRttInflationMs
                let lossSpike = sentDelta != nil
                    && sentDelta! >= Self.minLossSpikePackets
                    && lostDelta != nil
                    && Double(lostDelta!) / Double(sentDelta!) >= Self.lossSpikeRate
                if rttInflated || lossSpike {
                    state.saturatedIntervals += 1
                }
            }

            if rtt > 0 {
                if let lowWater = state.lowWaterRttMs {
                    state.lowWaterRttMs = min(lowWater, rtt)
                } else {
                    state.lowWaterRttMs = rtt
                }
            }

            state.prevActive = path.active
            state.prevPingFrames = path.quicPingFrames
            state.prevInBytes = path.inboundBytes
            state.prevOutBytes = path.outboundBytes
            state.prevLostPackets = path.quicLostPackets
            state.prevSentPackets = path.quicSentPackets
            state.hasBaseline = true
            paths[path.gradeKey] = state
        }
        lastSampleAt = now
    }

    /// Non-negative delta between cumulative counters, or nil when
    /// either side is unmeasured. A drop (counter reset) counts as
    /// zero and re-baselines on the next sample via the stored prev.
    private func delta(_ current: Int?, _ prev: Int?) -> Int? {
        guard let current = current, let prev = prev else { return nil }
        let diff = current - prev
        return diff < 0 ? 0 : diff
    }

    private func rebaseline(_ state: inout PathState, _ path: PathStat) {
        state.prevActive = path.active
        state.prevPingFrames = path.quicPingFrames
        state.prevInBytes = path.inboundBytes
        state.prevOutBytes = path.outboundBytes
        state.prevLostPackets = path.quicLostPackets
        state.prevSentPackets = path.quicSentPackets
        state.hasBaseline = true
    }

    private func reset() {
        sessionId = 0
        lastSampleAt = nil
        paths.removeAll()
    }
}
