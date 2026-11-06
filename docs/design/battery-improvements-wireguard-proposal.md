# Battery improvements: WireGuard inspiration + in-app profiling

Research + proposal only (2026-11-05). No code was changed for this document.
Sources read: `wireguard-android` (github.com/WireGuard/wireguard-android,
cloned shallow to `~/workspace/wireguard-android-src`, commit at clone time
2026-11-05), WireGuard protocol docs (wireguard.com — persistent keepalive
off by default, 25 s recommended when needed; rekey 120 s; silent when idle),
and the Bonded code cited inline. Plan rows 4.35–4.41 are the baseline; this
document does not re-propose them.

## 1. What Bonded already does (brief)

Shipped in v242/v245 (plan 4.35–4.41):

- **4.35** Adaptive idle heartbeats: 10 s active / 25 s idle, active path
  only when idle; standby paths silent while idle (server reaps them after
  30 s). QUIC keepalive 10 s → 25 s. Documented slack problem: 25 s leaves
  only 5 s vs the server's 30 s reap, so a Doze stall can kill even the
  active path.
- **4.36** Session-monitor snapshot poll: 1 s only while the UI is asking,
  30 s backoff otherwise; home poll skips when not resumed.
- **4.37** Multicast lock only when peer sharing is on.
- **4.38** Windowed peer discovery: 10 s lock at the top of each UTC minute,
  bursts on start/path change, 60 s sweep every 30 min.
- **4.39** Battery-saver (default off): WireGuard-first protocol order,
  cellular paths auto-parked while idle with Wi-Fi live. Honest limit:
  parked cellular still sends QUIC PINGs every 25 s (quinn 0.11 fixes
  keepalive at connect time; no runtime toggle). Full radio sleep needs
  tearing the transport down, deliberately deferred.
- **4.40** Packet-path batching: removed the per-packet JVM copy on the
  outbound fast path and the no-op inbound flush; the drain thread exits
  once the native fd handoff is active.
- **4.41** Transport overhead diagnostic (Network Tests screen): per-transport
  wire-vs-inside byte counters, live 10 s window.

Steady-state cost inventory today (what is still waking the radio/CPU when
the session is idle): QUIC keepalive PING every 25 s on every live transport
(2–3 transports in multipath); session heartbeats 25 s idle on the active
path; the 5 s advertise-IP poll (`run_advertise_watcher`, 4.17); the FFI
worker tick and snapshot serialization; the foreground service itself
(`FOREGROUND_SERVICE_SPECIAL_USE`, persistent notification — no WakeLock is
held anywhere, and no battery-optimizations exemption is requested). The
service also holds `NetworkCallback`s (path monitoring) and, when peer
sharing is on, the relay pump + mDNS windows.

## 2. What WireGuard does, and what transfers

The core of the WireGuard Android app's battery story is how little it does.
`GoBackend` (`tunnel/.../backend/GoBackend.java`) holds the whole tunnel in
one `wireguard-go` userspace instance: a single UDP socket per address
family, `setBlocking(true)` on the builder, `setUnderlyingNetworks(null)`.
The Java/Kotlin layer does **zero steady-state work**: no polling loop, no
timers, no WakeLock, no AlarmManager, no JobScheduler, no multicast, no
discovery, no foreground service (the `VpnService` in
`tunnel/src/main/AndroidManifest.xml` is declared with only
`BIND_VPN_SERVICE` — no `foregroundServiceType`, no `startForeground` call
anywhere), no battery-optimizations exemption request. DNS is resolved at
bring-up only (10 retries × 1 s), then never again. Statistics are strictly
pull-based: `getStatistics()` parses a `wgGetConfig` dump (rx/tx bytes +
last handshake per peer), `Statistics.isStale()` is 900 ms, and the UI
refreshes at 1 s **only while the tunnel detail screen is visible**
(`TunnelDetailFragment.kt`, `TvMainActivity.kt`) — nothing polls in the
background. Persistent keepalive is opt-in per peer and absent by default
(`PeerProxy.kt` defaults it to `""`; the config model holds
`Optional.empty()`), and the protocol itself is silent when idle
(wireguard.com: "it only transmits data when a peer wishes to send
packets"; rekey is 120 s and only on send; the 10 s keepalive-timeout fires
only if data arrived and nothing went back).

Ranked by expected saving vs implementation cost. "Transfers" means the idea
fits Bonded's architecture; the last section lists what does not.

### Rank 1 — Go silent when idle (highest saving, medium-large cost)

**Idea.** WG's defining property: no keepalive by default, so an idle tunnel
sends nothing. Bonded's idle cadence is 25 s (QUIC PING + heartbeat). On
cellular that matters more than the packet count suggests: a cellular radio
stays in a high-power tail for ~10–20 s after each transmission, so a 25 s
wakeup cadence can keep the radio from ever sleeping — the idle cost is
dominated by the *cadence*, not the bytes. Going silent (no PING, no
heartbeat) while idle, and re-dialing on the next traffic burst, attacks
that directly.

**Cost / risk.** Medium-large. It needs a runtime keepalive toggle quinn
0.11 does not offer (keepalive is fixed at connect time), so the idle path
is either transport teardown + re-dial on demand, or a quinn upgrade. It
also collides with two hard limits: the server reaps transports after 30 s
of silence, and NAT mappings expire, so a silent session must re-establish
(handshake + latency) on wake instead of resuming instantly. That is a real
UX tradeoff (first-packet latency after idle), and it needs the profiling
in §3 to prove the saving is real before shipping. A cheap halfway step is
stretching idle to 60 s, but that already breaks the 30 s server reap, so
it needs a server-side reap change too — do not do it alone.

### Rank 2 — Make battery-saver's cellular park real (high saving, medium cost)

**Idea.** 4.39's honest limit: parked cellular still sends QUIC PINGs every
25 s. Tear the cellular transport down while parked (idle + Wi-Fi live) and
re-dial on demand, instead of parking it in send order. Same radio-tail
argument as Rank 1, scoped to the cellular path only, and only when the user
opts into battery-saver.

**Cost.** Medium — the supervisor change 4.39 deliberately deferred
(teardown + re-dial, with the same resume-latency tradeoff as Rank 1, plus
the existing auto-park clear conditions: traffic burst, Wi-Fi gone). Smaller
blast radius than Rank 1 because it is opt-in and cellular-only.

### Rank 3 — Replace the 5 s advertise-IP poll with event-driven checks (medium saving, low cost)

**Idea.** `run_advertise_watcher` (4.17) re-resolves the advertise IP every
5 s all session long. WG has no equivalent at all (no discovery, no
re-advertise). Bonded already has `NetworkCallback`s watching path changes
(`AndroidNetworkPathManager.kt`) — re-resolve on path-change callbacks plus
a slow sanity poll (e.g. 60 s), and drop the 5 s loop.

**Cost.** Low. The 5 s loop is a small timer, but it is also a permanent
wakeup source; removing it is cheap and safe (a missed re-advertise only
delays peer discovery, which already tolerates minute-scale windows).

### Rank 4 — Coalesce per-transport keepalives (small-medium saving, low-medium cost)

**Idea.** With 2–3 live transports each PINGing every 25 s on independent
timers, wakeups are spread across the whole minute. Stagger/align them so
all transports PING in the same short window, letting the radio sleep
between bursts. WG never faces this (one socket).

**Cost.** Low-medium: needs a shared phase for the per-transport keepalive
timers (quinn exposes the interval, not the phase — this may need the same
teardown/rebuild hook as Rank 1, or a supervisor-side tick that drives
PINGs). Do only if profiling (§3) shows the wakeups are actually spread
rather than already clustered.

### Rank 5 — Test dropping the foreground service (uncertain saving, low cost to test)

**Idea.** WG's `VpnService` is not a foreground service at all and survives
on the VPN's own lifetime. Bonded runs as `FOREGROUND_SERVICE_SPECIAL_USE`
with a persistent notification. A foreground service exempts the app from
some Doze restrictions, which can mean *more* background work during Doze,
not less. Test whether the Rust worker + session survive without it (Doze
still throttles timers; the tunnel must re-establish on wake).

**Cost.** Low to test (a flag + a Doze soak test), but the saving is
uncertain and the failure mode (dead session after Doze) is bad. Treat as
an experiment, not a recommendation. Do not ship without a Doze soak test
proving the session survives.

### Rank 6 — Stats stay pull-based; keep it that way (no work, guardrail)

WG's stats are pulled at 1 s only on the detail screen and never in the
background. Bonded already matches this shape (4.36: snapshot poll 1 s
foreground / 30 s background; home poll skips when not resumed). No change
— but the new profiling in §3 must follow the same rule: sample on existing
ticks, never add a polling loop of its own.

### What does NOT transfer

- **Kernel WireGuard (Android 12+).** WG on modern Android runs in-kernel;
  Bonded's transports (QUIC, WSS, NaiveTCP, peer relays) are userspace by
  design. Nothing to adopt except the principle (do work in one place,
  once).
- **Single-transport simplicity.** WG has one socket, one peer set, no
  failover. Bonded's multipath + per-path supervision is the product; the
  battery cost of 2–3 live transports is inherent, only tunable (Ranks 1,
  2, 4).
- **No discovery.** WG has no peer discovery at all, so it pays nothing
  for it. Bonded's mDNS discovery is the price of peer sharing; it is
  already windowed (4.38) — the remaining win is only the 5 s poll (Rank 3).
- **No keepalive by default.** WG can afford silent idle because its peers
  initiate on demand and NAT traversal is the user's explicit opt-in.
  Bonded's server reaps transports after 30 s and its supervisor expects
  live paths, so silence needs the re-dial machinery (Rank 1), not just
  deleting a timer.
- **No foreground service.** WG's service holds no session worker; Bonded's
  Rust worker lives in the service process, so the lifetime question (Rank 5)
  is genuinely open, not settled by WG's example.

## 3. Profiling design: in-app battery + CPU monitoring

Goal: answer "did this change save battery, by how much, in which state?"
with numbers from the user's own phone, without root and without a
foreground service beyond the one Bonded already runs.

### What to measure

Battery (via `BatteryManager`, no permission needed):
- `BATTERY_PROPERTY_CHARGE_COUNTER` (µAh remaining) — the primary signal;
  delta over a window ÷ window length = mAh/h for that window.
- `BATTERY_PROPERTY_CURRENT_NOW` / `CURRENT_AVERAGE` (µA) — instantaneous
  draw, sampled, for short-window estimates.
- `BATTERY_PROPERTY_CAPACITY` (%) and level/scale from
  `ACTION_BATTERY_CHANGED` — coarse fallback where the charge counter is
  not implemented (some devices report it in 1% steps or not at all).
- `BATTERY_PROPERTY_STATUS` (charging/discharging) — discard charging
  windows; only discharging windows count.

CPU (own process only):
- `android.os.Process.getElapsedCpuTime()` — whole-process CPU ms; delta
  over a window = process CPU time in that window.
- `Debug.threadCpuTimeNanos()` for the named worker threads (packet I/O,
  FFI worker, heartbeat) — attributes CPU to the subsystems that burn it.
- `/proc/self/stat` utime/stime as a cross-check (same numbers, no API).

Wakeup accounting (the app's own wakeup sources — all countable in-app):
- heartbeat ticks sent, QUIC PINGs sent per transport, snapshot
  serializations, `NetworkCallback` invocations, mDNS windows opened,
  relay tasks started/ended. These are the *causes*; the charge counter is
  the *effect*. Counting both is what makes a change attributable ("PINGs
  fell from 144/h to 0/h and mAh/h fell from X to Y").

Session context (every sample is tagged with these, so rates segment by
state):
- idle vs active traffic (the existing 60 s idle definition), screen on/off,
  Doze (`PowerManager.isDeviceIdleMode()`), power-save
  (`isPowerSaveMode()`), charging or not.
- Peer sharing on/off, active relay count, relayed bytes in the window
  (the 4.45 counters), battery-saver on/off, transport mix (which kinds are
  live), path count, active transport kind.

### Cadence and the cost of profiling itself

- Sample on **existing** ticks only: the FFI worker tick and the snapshot
  poll. No new timers, no exact alarms, no `WorkManager` periodic work.
  A sample is a handful of binder calls + arithmetic (<1 ms); riding
  existing wakeups makes the marginal cost ~zero. Never wake the device to
  sample — a sparse sample set during Doze is itself data (the device
  slept, so no samples).
- Default cadence: one sample per 30 s while the session is up (aligned to
  the background snapshot poll), plus event markers on state transitions
  (connect/disconnect, screen on/off, Doze enter/exit, path change,
  battery-saver toggle). Shorter than 30 s buys little (charge-counter
  granularity is the limit) and costs binder calls.
- Ring buffer in memory (e.g. 24 h at 30 s ≈ 2,880 samples × ~100 bytes ≈
  300 KB), plus persisted hourly aggregates (last 7 days, capped file).
  Raw samples need not survive a process death; aggregates should.

### Where it lives and where it's shown

- Collection: Kotlin (`BatteryManager` + `PowerManager` + `Process`) in
  `BondedVpnService`, sampled on the existing tick; counters from the FFI
  snapshot path (same JSON the home screen already consumes — add a
  `battery` block, or a separate lightweight channel if the snapshot is the
  wrong cadence). Rust side needs nothing new except the wakeup counters
  it already has (heartbeat ticks, PINGs — expose them the way 4.45 exposed
  relayed bytes).
- Storage: in-memory ring + a capped append-only file for hourly
  aggregates (same diagnostics area as the client-log ring).
- Display: a "Battery" card on the Diagnostics screen (next to Network
  tests, where the 4.41 overhead card lives), showing mAh/h over the last
  hour segmented by state (idle vs active, Wi-Fi vs cellular, peer sharing
  on/off, battery-saver on/off), plus process CPU ms/h and wakeups/h. A
  one-line compact form (current mAh/h) can sit on the home screen under
  Totals once the card exists. Export: shareable CSV/JSON (same share path
  as client logs) so a before/after can be compared off-device.
- Complement (not in-app): an adb-side recipe for system attribution —
  `adb shell dumpsys batterystats` + Battery Historian from a bugreport.
  In-app code **cannot** read batterystats (needs the `DUMP` permission,
  not granted to normal apps); the in-app design must not claim
  system-wide attribution it cannot measure.

### Decisions it enables

- Prove a change: run the same usage pattern before/after (e.g. 25 s → 60 s
  heartbeat, or Rank 2 teardown) and read mAh/h in the idle+cellular
  segment. Without this, every battery claim is anecdote.
- Attribute drain to states: "idle + cellular + peer sharing = X mAh/h"
  vs "idle + Wi-Fi = Y" tells the user (and us) where the next fix goes.
- Catch regressions: a release that doubles idle drain shows up in the
  hourly aggregates instead of in a user report a week later.
- Settle Rank 5 honestly: a Doze soak with the FGS on vs off, read as
  mAh/h + session survivals, instead of arguing from first principles.

### Honesty limits

- Charge-counter granularity varies by device; some devices do not
  implement `CURRENT_NOW` or report the counter coarsely. The design must
  degrade to level-% deltas on those devices and say so in the UI.
- The charge counter measures **whole-device** drain, not Bonded's share.
  Attribution is differential and state-segmented (VPN on vs off windows,
  idle vs active, peer sharing on vs off) — never an absolute "Bonded used
  X mAh" claim. A charging phone, a hot phone, or a second app's sync can
  swamp the signal; the UI must show window length and sample count
  alongside every rate.
- Doze and App Standby limit what the app can observe while the device
  sleeps; sparse samples during Doze are expected, not a bug.
- `dumpsys batterystats` / Battery Historian remain the only system-wide
  attribution, and they need adb — the in-app profiler is a complement,
  not a replacement.

## 4. Recommended next slice (smallest useful build)

Build the profiler first, then spend the savings it proves. Order:

1. **Battery profiling slice** (the enabler): sample charge counter +
   current + process CPU + wakeup counters on the existing 30 s tick,
   tag with session context, ring buffer + hourly aggregates, one
   Diagnostics "Battery" card (mAh/h by state) + CSV export. No new
   wakeups, no new permissions (`BATTERY_STATS` is not needed for
   `BatteryManager` properties; `DUMP` is not requested). This is the
   smallest build that makes every later battery claim checkable.
2. **Rank 3** (5 s advertise poll → event-driven): cheap, safe, and its
   effect is immediately visible in the profiler's wakeups/h.
3. **Rank 2** (real cellular teardown in battery-saver) **or Rank 1**
   (idle silence), decided by what the profiler shows: if idle+cellular
   dominates, do Rank 2; if idle+Wi-Fi dominates, do Rank 1. Either is a
   supervisor change with a resume-latency tradeoff — ship behind the
   battery-saver toggle first, measure with the profiler, then decide
   whether it becomes default.

Explicitly not in the next slice: per-peer battery attribution (the 4.45
relayed-bytes counters are session-level; per-peer energy needs per-relay
wakeup accounting that does not exist yet), kernel WireGuard, dropping the
foreground service without a Doze soak test, and any server-side reap
change (needed by Rank 1's 60 s halfway step, but not by the teardown
designs, which re-dial instead of lingering).
