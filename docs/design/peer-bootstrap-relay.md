# Design Document: Peer-Initiated Bootstrap (Offline Consumer)

**Author:** Design draft (agent-authored, for review)
**Date:** 2026-10-17
**Status:** Draft — future feature, not scheduled

## Summary

Today a peer relay can only *join* a session that already exists: the consumer
must reach the server directly to request a server-signed introduction and to
establish its own session, and only then can the server bind a provider's relay
transport into that session. Peer-initiated bootstrap inverts that dependency.
A client with **no working direct Internet path** discovers a LAN peer via
mDNS (LAN-only, works offline), pipes its signed bootstrap requests through
that peer to the server, and creates its session with the relay as its first
transport. The provider remains an untrusted pipe: the consumer's requests are
device-signed, the server's responses are server-signed, and both are verified
end-to-end against keys the two endpoints already trust — the consumer's paired
server pin and the server's authorized-device list.

## Motivation

Peer sharing currently helps a device that is *already connected*. It does
nothing for a device whose own uplinks are unusable while a working uplink is
sitting next to it on the same LAN:

- **WAN-down LAN**: the building/house Internet connection is down (or the
  router's WAN is), but one device on the LAN still has a working path out
  (e.g. cellular). Every other device on the LAN is stranded even though a
  peer could carry them.
- **Wi-Fi-only device**: a tablet or secondary phone with no cellular radio is
  on a LAN whose gateway is broken or captive, while the owner's phone on the
  same LAN has full connectivity.
- **Blocked local uplink**: a device's own path is filtered, metered out, or
  behind a portal it cannot complete, but a peer's path is unrestricted.

In all three cases the missing piece is not the relay data plane — that
exists. The missing piece is the *bootstrap* dependency: discovery is
LAN-local, but the introduction request and session establishment both assume
direct server reachability.

## Goals & Non-Goals

### Goals

- A consumer with zero working direct paths can establish a full server
  session through a single LAN provider.
- Identity verification (cert-proof against the pairing pin) works over the
  relayed path with the same strength as over a direct path.
- Relay-only sessions have defined liveness, recovery, and provider-failover
  semantics — no silent wedge when the provider moves, sleeps, or loses its
  own uplink.
- Reuse the existing discovery, introduction, pinned-cert, relay-registration,
  and session-binding machinery wherever possible.

### Non-Goals

- Peer-to-peer mesh routing between different servers (unchanged from the
  peer-sharing design: the server remains the only trust root).
- Multi-hop relaying (consumer → provider → provider → server). One hop only.
- Session persistence across total path loss: if the sole relay dies and the
  server tears the session down, the client re-bootstraps into a *new*
  session. Keeping the TUN up across the gap is in scope; keeping the same
  server session id is not.
- Replacing pairing: the offline consumer must already be paired (it holds a
  device key the server has authorized and a record pinning the server
  identity). Bootstrap relay cannot create trust, only exercise it.

## Where Things Stand Today

The current flow, for contrast:

1. Consumer discovers the provider over mDNS (`_bonded-peer._udp.local`),
   filtering advertisements by the paired `server_key`.
2. Consumer sends `POST /v1/bootstrap/peer-share/introduction` **directly to
   the server** — a device-signed request naming itself, the provider, the
   provider's instance nonce, endpoint, and listener cert fingerprint. The
   server requires both device keys to be authorized and returns a
   server-signed introduction (300 s validity).
3. Consumer dials the provider's QUIC listener (ALPN `bonded-peer`), pinning
   the listener cert to the fingerprint in the signed claims, and presents
   the introduction. The provider verifies the server signature against its
   own pinned server key, checks the claims name itself and its current
   instance nonce, and accepts.
4. The provider opens a dedicated upstream transport to the server and sends a
   relay-registration control frame carrying the same signed introduction.
   The server verifies it and binds that transport into the consumer's
   **pre-existing** session (`relayed_via_provider=true`).
5. The relay thereafter carries ordinary `SessionFrame` bytes as just another
   `ClientTransport` in the consumer's session.

Steps 2 and the consumer's own direct session establishment are the two
places that assume WAN reachability. Everything after step 3 is already
relay-shaped.

## Proposed Design

### New pieces at a glance

| Piece | Where | Purpose |
| --- | --- | --- |
| `bootstrap-relay` capability | mDNS TXT `capabilities` | Advertisement says this provider offers bootstrap relaying, not just data relay |
| Bootstrap control stream | Peer QUIC listener, pre-introduction | Carries the consumer's signed bootstrap requests to the provider and the server's signed responses back, before any introduction exists |
| Relayed introduction transport | Provider → server bootstrap endpoint | Provider forwards the consumer's introduction request verbatim and returns the response verbatim |
| Relayed cert-proof | Same control stream | Server's signed cert-proof response forwarded verbatim; consumer verifies against its pin |
| Relay-first session creation | Server session binding | A relay registration with no live consumer session creates a pending session; the consumer's session-establishment exchange completes over the relay |
| Relay-only liveness/failover | Client peer runtime | Heartbeat, dead-relay detection, re-bootstrap via the same or another provider |

### Message flow

Actors: **C** = offline consumer, **P** = provider (has uplink), **S** =
server.

1. **Discovery (LAN-only).** C browses mDNS as today and selects an
   advertisement whose `server_key` matches C's paired record and whose
   `capabilities` include `bootstrap-relay`. The advertisement is, as today,
   an unauthenticated hint; nothing in it is trusted yet.
2. **Pre-introduction dial.** C dials P's QUIC listener, pinning the listener
   certificate to the `cert_fingerprint` *from the advertisement*. (Today the
   fingerprint comes from the signed introduction; pre-introduction, the
   advertisement is the only source. This is safe because no trust decision
   rests on this connection alone — see Security Analysis. A substituted
   listener can blackhole the attempt, nothing more.)
3. **Introduction request, relayed.** C opens a bootstrap control stream and
   sends the exact introduction request body it would have POSTed directly:
   its device key, P's device key, P's advertised instance nonce, endpoint,
   listener transport, listener cert fingerprint, and C's signature over the
   canonical body. P performs the shape/identity checks it can (claims name
   P, nonce matches P's current listener instance) and forwards the body
   verbatim to `POST /v1/bootstrap/peer-share/introduction` over its own
   uplink. S verifies C's signature, requires both device keys authorized,
   and returns the server-signed introduction. P returns the response body
   verbatim to C.
4. **Consumer verifies.** C verifies `server_signature` against its pinned
   server key, exactly as today. Only now does C trust the claims — including
   the listener cert fingerprint, which must match the cert C actually dialed
   in step 2 (and the one in the advertisement). A mismatch aborts the
   attempt; this binds the pre-introduction dial to the server-vouched
   listener retroactively.
5. **Cert-proof, relayed.** Over the same control stream, C asks P to fetch
   `GET /v1/bootstrap/cert-proof` from S and return the response verbatim.
   The response is the server identity key's signature over S's TLS cert
   fingerprint; C verifies it against its pin. P must use the pinned-
   fingerprint TLS configuration for the relay upstreams it opens in step 6,
   so the attested fingerprint is the certificate actually in use. (A
   provider connected to a foreign server cannot produce this proof, and a
   foreign server cannot complete step 7's binding for claims it did not
   issue — see Security Analysis.)
6. **Relay establishment (as today).** C presents the introduction on a relay
   stream; P verifies it against P's pinned server key exactly as today,
   opens a dedicated upstream transport to S, and sends the
   relay-registration control frame carrying the introduction.
7. **Relay-first binding (new server behavior).** S verifies the
   registration as today. Finding **no live session** for the introduced
   consumer, S creates a *pending session*: a binding-in-progress keyed by
   (consumer device key, introduction), attached to P's registered upstream,
   with a short completion deadline (proposal: 30 s, aligned with the
   existing per-transport receive timeout). Frames arriving on that upstream
   are routed to the session-establishment handler for that consumer instead
   of to a session router.
8. **Session establishment over the relay.** C runs its normal
   session-establishment exchange — transport authentication with its device
   key and the startup session-discovery (PING/PONG) exchange that returns
   the server-assigned session id — with all frames carried over the relay
   path as ordinary session frames. On completion, S promotes the pending
   session to a live session whose first (and initially only) transport is
   the relay, and normal data forwarding begins. If the deadline passes, S
   discards the pending session and closes the upstream; P observes the
   close and tears down the peer stream, so C can retry or fail over.
9. **Steady state.** The relay is a normal `ClientTransport`. C's heartbeat
   (25 s tick, all paths) traverses it, resetting S's 30 s per-transport
   receive timer on the relay upstream, exactly as on a direct transport.
   If C later gains a direct path, it is added to the same session by the
   existing machinery and the relay demotes to a secondary path under the
   existing scheduling policy — no re-bootstrap.

### Session liveness when the only path is a relay

A relay-only session has two single points of failure a direct session does
not: the provider device itself, and the provider's own session.

- **Provider stall/doze.** If P stops relaying for ≥30 s, S's receive timer
  closes the relay upstream; with no transports left, S tears the session
  down. C detects the dead leg the way build 135 detects dead relays
  (heartbeat tick observes the closed QUIC connection). C keeps its TUN up,
  enters a re-bootstrap state for a bounded grace window, and retries from
  step 1 — using its cached advertisement first (the build-135
  `RedialQueue` pattern: fresh introduction per attempt, bounded attempts,
  ~10 s spacing) and a fresh mDNS resolution if the cached instance nonce is
  stale.
- **Provider session loss.** Per the existing peer-sharing security rule, P
  revokes all exported paths immediately when its own server session is lost
  — bootstrap-relayed consumers included. When P recovers and re-advertises
  (new instance nonce), affected consumers re-bootstrap against the fresh
  advertisement. P should prefer re-accepting recently displaced consumers
  within its consumer cap, but correctness does not depend on it.
- **Ambiguity of silence.** With no direct path, C cannot distinguish "P
  died", "P's uplink died", and "S is unreachable" — all present as silence.
  The client-visible state should say exactly that ("relay path lost,
  retrying") rather than a misleading "server unreachable". Failover (below)
  is the remedy, not diagnosis.

### Provider selection and failover

- **Selection.** Among advertisements passing the existing filters (matching
  `server_key`, not self, `bootstrap-relay` capability), prefer the most
  recently resolved instance. Introductions are provider-bound, so switching
  providers always costs a fresh relayed introduction; there is no way to
  retarget an existing introduction, by design.
- **Establishment failover.** If any step from the dial through session
  promotion fails or times out, C tries the next candidate provider, with
  the bounded retry discipline used for relay redial (max ~3 attempts, ~10 s
  spacing) so a LAN full of dead providers cannot turn into an
  introduction-request storm against S via the surviving providers.
- **Mid-session failover.** If the sole relay dies, C re-runs the whole flow
  with the next provider and attaches the new relay to its existing
  client-side session state. If S already tore the session down, step 8
  yields a fresh session; applications see a path interruption, not a
  re-pair or reconfiguration.
- **Stickiness.** Once a relay-only session is healthy, C does not hop
  providers for marginal gains; it switches only on failure or on a direct
  path appearing. Provider-hopping would churn introductions and server
  bindings for no benefit.

## What Already Exists (Reused Unchanged or Nearly So)

- **Discovery**: mDNS advertisement/browsing, TXT schema, server-affinity and
  self filters. Only change: a new value in the existing `capabilities`
  field.
- **Signed introductions**: request/response shapes, consumer signature,
  server-side authorized-device checks, 300 s expiry, nonce binding. The
  request is byte-identical whether it arrives directly or via a provider;
  the server cannot tell (and does not need to).
- **Pinned listener certs**: introduction claims bind endpoint + listener
  cert fingerprint; the consumer's pinned TLS/QUIC dial already exists. The
  bootstrap dial additionally uses the advertised fingerprint before the
  claims arrive, then cross-checks.
- **Cert-proof endpoint**: `GET /v1/bootstrap/cert-proof` returns the
  identity-key signature over the TLS cert fingerprint; the client-side
  verification (`fetch_and_verify_cert_proof` / proof-response verification)
  already exists. Relayed operation reuses the signed response verbatim.
- **Provider relay registration**: the dedicated upstream + registration
  control frame carrying the introduction is unchanged.
- **Server session binding**: the initial-session-frame exchange that detects
  relay registrations and binds transports to sessions is the hook the
  relay-first path extends.
- **Relay data plane and scheduling**: a relay transport is a
  `ClientTransport`; relay-only is the degenerate one-transport case.
- **Recovery patterns**: heartbeat-on-all-paths, dead-leg retirement, and the
  bounded `RedialQueue` rediscovery from builds 132–135 all carry over.
- **Quotas**: per-provider max-consumers and relay bandwidth cap
  configuration (Android paired record: `peerShareMaxConsumers`,
  `peerShareRelayBandwidthKbps`) apply to bootstrap-relayed consumers without
  new knobs.

## What Is Genuinely New

1. **Bootstrap control stream on the peer listener**, accepted before any
   introduction exists — a new, deliberately minimal pre-trust surface (see
   Security Analysis for its constraints).
2. **Relayed introduction transport**: the provider as a forward proxy for
   one signed request/response pair (and the cert-proof GET), with responses
   passed through unmodified.
3. **Relay-first session creation on the server**: pending-session state,
   completion deadline, and promotion to a live session when the consumer's
   establishment exchange completes over the relay. Today the server only
   binds relays into sessions that already exist; this is the core server
   change.
4. **Client session establishment with zero direct paths**: the session
   runtime must start from the peer runtime's output rather than treating
   peer paths as additions to a direct session — including DNS: the offline
   consumer may be unable to resolve the server hostname at all, so nothing
   in the relayed flow may depend on consumer-side DNS or direct IP
   reachability to the server.
5. **Relay-only liveness semantics**: re-bootstrap loop, grace window, and
   the honest client-visible state described above.
6. **Provider failover for bootstrap**: candidate ordering and bounded
   cross-provider retries with per-provider introductions.

## Security Analysis

The trust model is unchanged: **the server is the only trust root, and the
provider is an untrusted pipe.** Going offline removes the consumer's direct
channel to the trust root, but every bootstrap artifact is still a signed
object verified endpoint-to-endpoint:

- **How the offline consumer authenticates the server.** The consumer trusts
  exactly two things, both from pairing: the server identity public key in
  its paired record, and its own device key. The introduction's server
  signature is verified against the pin; the cert-proof signature is
  verified against the pin; session establishment authenticates the consumer
  to the server with its device key and adopts the session id the server
  assigns through that exchange. At no point does the consumer accept an
  assertion from the provider about the server.
- **How the server authenticates the consumer.** The forwarded introduction
  request carries the consumer's own signature, verified server-side, and
  both device keys must be on the authorized list — identical to the direct
  flow. The provider cannot impersonate a consumer (it cannot sign), cannot
  replay an old request usefully (introductions expire in 300 s and are
  bound to the provider's *current* instance nonce), and cannot retarget a
  request to a different provider (the provider identity is inside the
  signed body).
- **What the provider CAN do**: decline or drop anything (denial of
  service), delay or reorder relayed frames, observe frame timing and sizes
  on the relay leg (the same visibility it has as a relay today), and lie in
  its own mDNS advertisement (which buys it only the ability to be selected
  and then fail). It can also attempt the pre-introduction dial substitution
  in step 2 — presenting its own listener cert under a fingerprint it
  advertised — which is neutralized in step 4 when the server-signed claims
  fail to match the cert actually presented, and by the fact that the
  bootstrap payloads it can then see are signed objects it cannot forge or
  alter undetectably.
- **What the provider CANNOT do**: forge or modify introductions or
  cert-proofs (server signatures, verified against the consumer's pin);
  redirect the consumer's session to a different server (a foreign server
  cannot verify the consumer's request against the real server's authorized
  list, cannot sign introductions the consumer will accept, and cannot
  complete a binding for claims it never issued); impersonate the consumer
  to the server (device-key signatures); or turn a bootstrap relay into
  data-plane access beyond what relaying already grants — the frames it
  carries after session establishment are the consumer's ordinary session
  frames, forwarded to the one server both parties are paired with.
- **The new pre-trust surface is the bootstrap control stream.** It accepts
  connections from any LAN device claiming to be a consumer. Constraints:
  it carries only the fixed bootstrap request/response shapes (no generic
  proxying — the provider must not become an open relay to arbitrary
  endpoints, only to the bootstrap paths of its own paired server); requests
  that do not name this provider and its current instance nonce are dropped
  before any upstream traffic is generated; and the stream is
  rate-limited per source so a LAN neighbor cannot make the provider hammer
  the server's bootstrap endpoint.
- **Fail-closed behavior.** Every signature or binding mismatch aborts the
  attempt and is surfaced as an identity/bootstrap error — consistent with
  the session-start identity verification hardening: an offline consumer
  must never fail *open* into trusting an unverified path just because it
  has no alternative.

### Abuse and quotas

- **Provider-side caps apply from first contact.** A bootstrap-relayed
  consumer occupies one of the provider's consumer slots
  (`peerShareMaxConsumers`) from relay registration onward, and its traffic
  counts against the provider's relay bandwidth cap
  (`peerShareRelayBandwidthKbps`) like any relayed traffic. Bootstrap
  traffic itself is tiny; the cap that matters is the slot.
- **Server-side accounting is per device key, not per source IP.** Relayed
  introduction requests arrive from the provider's address, so per-IP rate
  limits on `/v1/bootstrap/*` would punish providers for their consumers.
  The consumer signature makes per-consumer-key accounting possible: count
  issuance against the *requesting* key. (General bootstrap API rate
  limiting remains on the deferred list; this feature should not ship
  before at least per-key introduction accounting exists, because it
  multiplies the number of devices that can induce server signatures
  indirectly.)
- **A malicious authorized consumer** can burn its own introduction quota
  and a slot on each provider it touches, but cannot exceed the per-provider
  caps, cannot consume other consumers' slots beyond occupying its own, and
  is fully attributable by device key at the server.
- **A malicious LAN neighbor with no authorized key** can reach the
  bootstrap control stream but cannot obtain a valid introduction (server
  rejects unsigned/unauthorized requests) — its ceiling is wasting some
  provider CPU under the rate limit above.

## Alternatives Considered

| Alternative | Pros | Cons | Why not chosen |
| --- | --- | --- | --- |
| Provider shares its uplink at the IP layer (NAT/hotspot-style forwarding to the server's address) | No server changes | Consumer still needs its own TLS/session to the server through raw forwarding; provider becomes a general-purpose forwarder (much larger abuse surface); duplicates OS tethering | Bootstrap relay keeps the provider application-scoped and preserves server-rooted trust |
| Pre-provisioned introductions (consumer fetches a batch while online, spends them offline) | No new server state | Introductions expire in 300 s and are nonce-bound to a provider instance; a stockpile is useless minutes later and after any provider restart | Expiry and nonce binding are security features, not obstacles to route around |
| Provider-initiated introduction (provider asks the server to introduce a named consumer) | Consumer sends nothing pre-trust | Reverses the signature flow: the server would be minting claims on a provider's say-so; consumer consent/attribution gets murkier | The consumer-signed request is the auditable artifact; keep it |
| Long-lived "bootstrap sessions" that survive provider loss | Smoother failover | New server session-persistence semantics for all clients; large scope | Re-bootstrap into a fresh session is acceptable for v1 of this feature |

## Testing Strategy

- **Unit**: bootstrap control-stream message shapes; provider-side
  shape/nonce gating; pending-session state machine (promotion, deadline
  expiry, duplicate registration).
- **Linux/network-namespace validation** (existing Forge harness pattern):
  consumer namespace with its direct server route removed; provider
  namespace bridging LAN and server. Cases: cold bootstrap end-to-end;
  cert-proof relay verification with a correct pin and failure with a wrong
  pin; provider killed mid-bootstrap and mid-session (failover to a second
  provider); provider uplink loss and recovery; server rejection of
  unsigned and unauthorized-consumer requests forwarded by a provider;
  pending-session deadline cleanup with a consumer that never completes
  establishment.
- **Physical devices**: Wi-Fi-only tablet + phone provider on a LAN with the
  gateway WAN disabled; phone consumer with its own uplinks disabled in
  favor of a second phone provider. Verify the client-visible state wording
  during provider loss (no misleading "server unreachable").

## Open Questions

- Does the provider forward bootstrap requests as fresh HTTPS calls to the
  bootstrap endpoint (simple, stateless) or as control frames over its
  existing server session (fewer connections, but couples bootstrap to the
  provider's session health)? The HTTPS form is proposed for v1; the session
  form may be needed if bootstrap endpoints gain client-cert or
  path-specific requirements.
- Pending-session deadline and retry budget: is 30 s right when the
  consumer's establishment includes slow relayed round-trips on a weak LAN?
- Should the advertisement carry a coarse provider health hint (e.g. "my
  server session is up, N paths") to improve selection, accepting that it is
  unauthenticated and gameable?
- How does bootstrap relay interact with the provider's own battery/thermal
  policy on Android — should offering `bootstrap-relay` be a separate
  toggle from data relay, defaulting to on when peer sharing is on?
- When a relay-only consumer later gains a direct path, should the relay be
  kept warm as failover or dropped promptly to release the provider's slot?
  (Scheduling policy currently demotes peer paths to secondary; the slot
  cost argues for prompt release.)
- Per-key introduction accounting: what limits, and does the server need to
  distinguish "relayed" requests for accounting if the signature already
  attributes them?
- Does the desktop/Linux client need this, or is it Android-first? The
  motivating scenarios are phone/tablet-shaped, but the client runtime is
  shared.
