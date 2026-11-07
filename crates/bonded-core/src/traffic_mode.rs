//! Traffic modes + per-destination rules (4.51).
//!
//! A mode picks how a flow's packets are spread over the session's
//! transports. The default mode is today's behavior: pin each flow to
//! one transport by flow hash. The other modes (`best_transport`,
//! `lowest_latency`, `bandwidth_boost`, `redundant`) land in slices
//! 4.52–4.54; until a mode's slice lands, selecting it falls back to
//! default behavior — never silently pretending the mode is live.
//!
//! Rules resolve a mode per flow from the destination IP only. A rule
//! matches an exact IP, a subnet (CIDR), or the IPs a domain resolved
//! to when the rule was saved (domains are pre-resolved by the UI —
//! see the plan row — so matching here never touches DNS). Most
//! specific wins: exact IP > subnet (longer prefix first) >
//! domain-resolved IPs; ties go to the earliest rule in the list.
//!
//! The engine is deliberately data-only: it knows nothing about
//! transports, sessions, or the UI. Both flow-pin points (the Linux
//! client loop and the Android worker) consult it the same way, so
//! 4.52–4.54 only add ordering arms in [`TrafficModeEngine::order_candidates`].

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

use crate::flow::{dst_ip, flow_hash, pick_index};

/// How one flow's traffic is placed on the session's transports.
/// Serializes to its wire name; deserializing an unknown name yields
/// [`TrafficMode::Default`] rather than failing the whole rule set.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TrafficMode {
    /// Current behavior: flow-hash spreading across transports.
    Default,
    /// Send on the transport the most recent data came on (4.52).
    BestTransport,
    /// Send on the lowest-latency transport (4.53).
    LowestLatency,
    /// Flow-level spreading weighted by grade/loss (4.53).
    BandwidthBoost,
    /// Duplicate on all transports, both ways (4.54).
    Redundant,
}

impl TrafficMode {
    /// Wire name shared with the Dart UI (`default`, `best_transport`, …).
    pub fn wire_name(self) -> &'static str {
        match self {
            TrafficMode::Default => "default",
            TrafficMode::BestTransport => "best_transport",
            TrafficMode::LowestLatency => "lowest_latency",
            TrafficMode::BandwidthBoost => "bandwidth_boost",
            TrafficMode::Redundant => "redundant",
        }
    }

    /// Parse a wire name; unknown names fall back to [`TrafficMode::Default`]
    /// rather than failing the whole rule set.
    pub fn from_wire_name(name: &str) -> TrafficMode {
        match name {
            "best_transport" => TrafficMode::BestTransport,
            "lowest_latency" => TrafficMode::LowestLatency,
            "bandwidth_boost" => TrafficMode::BandwidthBoost,
            "redundant" => TrafficMode::Redundant,
            _ => TrafficMode::Default,
        }
    }

    /// Only `default` has behavior in this slice. The rest are
    /// selectable in the UI but fall back to default until their slice
    /// lands (4.52–4.54) — the UI says so, and so does this function.
    pub fn is_implemented(self) -> bool {
        matches!(self, TrafficMode::Default)
    }

    /// The mode that actually governs behavior: an unimplemented mode
    /// resolves to [`TrafficMode::Default`].
    pub fn effective(self) -> TrafficMode {
        if self.is_implemented() {
            self
        } else {
            TrafficMode::Default
        }
    }
}

impl Default for TrafficMode {
    fn default() -> Self {
        TrafficMode::Default
    }
}

impl<'de> Deserialize<'de> for TrafficMode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let name = String::deserialize(deserializer)?;
        Ok(TrafficMode::from_wire_name(&name))
    }
}

/// What a rule matches on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrafficRuleKind {
    /// One exact IP address.
    Ip,
    /// A CIDR subnet (`192.0.2.0/24`, `2001:db8::/32`).
    Subnet,
    /// A domain; matches the IPs it resolved to when saved / on VPN start.
    Domain,
}

/// One row of the rule table. The `target` is what the user typed
/// (domain, IP, or CIDR) and is kept for display; `resolved_ips` is
/// what matching actually uses for domain rules (empty = the domain
/// never resolved, so the rule matches nothing).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrafficRule {
    pub id: String,
    pub kind: TrafficRuleKind,
    pub target: String,
    #[serde(default)]
    pub resolved_ips: Vec<IpAddr>,
    pub mode: TrafficMode,
}

impl TrafficRule {
    /// Specificity rank for "most specific wins": lower is more
    /// specific. Exact IP (0) > subnet (1) > domain-resolved IPs (2).
    /// Within subnets the longer prefix wins; that is decided by the
    /// caller comparing prefix lengths, not by this rank.
    fn specificity_rank(&self) -> u8 {
        match self.kind {
            TrafficRuleKind::Ip => 0,
            TrafficRuleKind::Subnet => 1,
            TrafficRuleKind::Domain => 2,
        }
    }

    /// The subnet prefix length for subnet rules; 0 otherwise. Used
    /// only to break ties between two matching subnets.
    fn prefix_len(&self) -> u8 {
        match self.kind {
            TrafficRuleKind::Subnet => parse_cidr(&self.target)
                .map(|(_, prefix)| prefix)
                .unwrap_or(0),
            _ => 0,
        }
    }

    /// Does this rule match `dst`? A malformed target or an empty
    /// `resolved_ips` on a domain rule matches nothing, never
    /// everything.
    pub fn matches(&self, dst: IpAddr) -> bool {
        match self.kind {
            TrafficRuleKind::Ip => self
                .target
                .parse::<IpAddr>()
                .map(|ip| ip == dst)
                .unwrap_or(false),
            TrafficRuleKind::Subnet => parse_cidr(&self.target)
                .map(|(network, prefix)| ip_in_prefix(dst, network, prefix))
                .unwrap_or(false),
            TrafficRuleKind::Domain => self.resolved_ips.contains(&dst),
        }
    }
}

/// Per-path signals the future modes need (4.52–4.54). Defined now so
/// those slices only add ordering arms instead of changing the
/// [`TrafficModeEngine::order_candidates`] signature. All fields are
/// optional: a mode must treat a missing signal as "unknown", never
/// as a fabricated 0 (the same discipline as the 4.49 loss counters).
#[derive(Clone, Copy, Debug, Default)]
pub struct PathSignal {
    /// Latest round-trip time for this path, if observed.
    pub rtt_ms: Option<u64>,
    /// QUIC loss rate for this path, if observed.
    pub loss_rate: Option<f64>,
    /// Per-transport grade total (0–100) from 4.50, if computed.
    pub grade: Option<u8>,
}

/// The rule table: a default mode plus per-destination overrides.
/// JSON shape (shared with the Dart UI): `{"defaultMode": "default",
/// "rules": [...]}`. Unknown modes in JSON fall back to `default`
/// (see [`TrafficMode::from_wire_name`]); malformed JSON as a whole
/// falls back to an empty default engine — a bad rule set must never
/// break the session, it just means "spread like today".
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrafficModeEngine {
    #[serde(default)]
    pub default_mode: TrafficMode,
    #[serde(default)]
    pub rules: Vec<TrafficRule>,
}

impl TrafficModeEngine {
    /// Parse the JSON the UI hands over (session start / live update).
    /// `Err` on malformed JSON; the caller falls back to
    /// [`TrafficModeEngine::default`].
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Parse, falling back to the empty default engine on any error.
    pub fn from_json_or_default(json: &str) -> Self {
        Self::from_json(json).unwrap_or_default()
    }

    /// The mode governing one flow, from its destination IP: the most
    /// specific matching rule wins, else the default mode. The returned
    /// mode is the *selected* one, not the effective one — an
    /// unimplemented mode is still returned here, and
    /// [`TrafficModeEngine::order_candidates`] applies the fallback to
    /// default ordering. Keeping selection and fallback separate is
    /// what makes the specificity rule testable before 4.52–4.54 land.
    pub fn mode_for(&self, dst: IpAddr) -> TrafficMode {
        let mut best: Option<&TrafficRule> = None;
        for rule in &self.rules {
            if !rule.matches(dst) {
                continue;
            }
            let replace = match best {
                None => true,
                Some(current) => {
                    let rank = rule.specificity_rank();
                    let current_rank = current.specificity_rank();
                    rank < current_rank
                        || (rank == current_rank
                            && rule.prefix_len() > current.prefix_len())
                }
            };
            if replace {
                best = Some(rule);
            }
        }
        best.map(|rule| rule.mode).unwrap_or(self.default_mode)
    }

    /// Order the transport indices for one packet's try-list, given the
    /// mode resolved by [`TrafficModeEngine::mode_for`]. The first
    /// entry is tried first; on send failure the caller tries the next
    /// one (the existing failover discipline is unchanged).
    ///
    /// Only `default` is implemented in this slice: hash-spread the
    /// flow over all transports, active transport last as the final
    /// fallback (it is already in the rotation when transports exist,
    /// so the append only fires for the empty-transport case). The
    /// catch-all arm is the same default order — that is the honest
    /// fallback for modes whose slices have not landed yet, and it is
    /// what makes 4.52–4.54 pure additions: each adds one arm here and
    /// flips its `is_implemented`.
    pub fn order_candidates(
        &self,
        mode: TrafficMode,
        flow_hash: u64,
        count: usize,
        active_index: usize,
        _signals: &[PathSignal],
    ) -> Vec<usize> {
        match mode {
            TrafficMode::Default => default_order(flow_hash, count, active_index),
            // 4.52: BestTransport. 4.53: LowestLatency, BandwidthBoost.
            // 4.54: Redundant. Until then, fall back to default order.
            _ => default_order(flow_hash, count, active_index),
        }
    }

    /// Convenience for the pin points: hash the packet, resolve its
    /// mode from the destination IP, and order the candidates in one
    /// call. Packets without a parseable destination IP (non-IP, or
    /// truncated) use the default mode — they still spread by hash.
    pub fn order_for_packet(
        &self,
        packet: &[u8],
        count: usize,
        active_index: usize,
        signals: &[PathSignal],
    ) -> Vec<usize> {
        let flow = flow_hash(packet);
        let mode = dst_ip(packet).map(|dst| self.mode_for(dst)).unwrap_or_default();
        self.order_candidates(mode, flow, count, active_index, signals)
    }
}

/// Today's spreading, extracted so both pin points share it: rotate
/// `0..count` by the flow hash, active transport appended last only
/// when it is not already in the list (empty transport set).
fn default_order(flow_hash: u64, count: usize, active_index: usize) -> Vec<usize> {
    let mut candidates: Vec<usize> = (0..count).collect();
    if candidates.is_empty() {
        candidates.push(active_index);
    } else {
        let pick = pick_index(flow_hash, candidates.len());
        candidates.rotate_left(pick);
        if !candidates.contains(&active_index) {
            candidates.push(active_index);
        }
    }
    candidates
}

/// Parse `address/prefix` into (network address, prefix length).
/// Returns `None` on any malformed input, including a prefix that is
/// out of range for the address family.
pub fn parse_cidr(cidr: &str) -> Option<(IpAddr, u8)> {
    let (addr_str, prefix_str) = cidr.split_once('/')?;
    let addr: IpAddr = addr_str.parse().ok()?;
    let prefix: u8 = prefix_str.parse().ok()?;
    let max = match addr {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    if prefix > max {
        return None;
    }
    Some((addr, prefix))
}

/// Is `addr` inside `network/prefix`? Families must match; a /0
/// prefix matches the whole family.
fn ip_in_prefix(addr: IpAddr, network: IpAddr, prefix: u8) -> bool {
    match (addr, network) {
        (IpAddr::V4(a), IpAddr::V4(n)) => {
            if prefix == 0 {
                return true;
            }
            let mask = u32::MAX << (32 - prefix);
            (u32::from(a) & mask) == (u32::from(n) & mask)
        }
        (IpAddr::V6(a), IpAddr::V6(n)) => {
            if prefix == 0 {
                return true;
            }
            let mask = u128::MAX << (128 - prefix);
            (u128::from(a) & mask) == (u128::from(n) & mask)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn ip_rule(id: &str, target: &str, mode: TrafficMode) -> TrafficRule {
        TrafficRule {
            id: id.to_string(),
            kind: TrafficRuleKind::Ip,
            target: target.to_string(),
            resolved_ips: vec![],
            mode,
        }
    }

    fn subnet_rule(id: &str, target: &str, mode: TrafficMode) -> TrafficRule {
        TrafficRule {
            id: id.to_string(),
            kind: TrafficRuleKind::Subnet,
            target: target.to_string(),
            resolved_ips: vec![],
            mode,
        }
    }

    fn domain_rule(id: &str, target: &str, ips: Vec<IpAddr>, mode: TrafficMode) -> TrafficRule {
        TrafficRule {
            id: id.to_string(),
            kind: TrafficRuleKind::Domain,
            target: target.to_string(),
            resolved_ips: ips,
            mode,
        }
    }

    #[test]
    fn wire_names_round_trip() {
        for mode in [
            TrafficMode::Default,
            TrafficMode::BestTransport,
            TrafficMode::LowestLatency,
            TrafficMode::BandwidthBoost,
            TrafficMode::Redundant,
        ] {
            assert_eq!(TrafficMode::from_wire_name(mode.wire_name()), mode);
        }
        assert_eq!(TrafficMode::from_wire_name("nonsense"), TrafficMode::Default);
        assert_eq!(TrafficMode::from_wire_name(""), TrafficMode::Default);
    }

    #[test]
    fn only_default_is_implemented() {
        assert!(TrafficMode::Default.is_implemented());
        assert!(!TrafficMode::BestTransport.is_implemented());
        assert!(!TrafficMode::LowestLatency.is_implemented());
        assert!(!TrafficMode::BandwidthBoost.is_implemented());
        assert!(!TrafficMode::Redundant.is_implemented());
        assert_eq!(
            TrafficMode::Redundant.effective(),
            TrafficMode::Default
        );
    }

    #[test]
    fn no_rules_uses_default_mode() {
        let engine = TrafficModeEngine::default();
        assert_eq!(engine.mode_for(v4(1, 2, 3, 4)), TrafficMode::Default);
    }

    #[test]
    fn exact_ip_beats_subnet_beats_domain() {
        let engine = TrafficModeEngine {
            default_mode: TrafficMode::Default,
            rules: vec![
                domain_rule(
                    "d",
                    "example.com",
                    vec![v4(93, 184, 216, 34)],
                    TrafficMode::LowestLatency,
                ),
                subnet_rule("s", "93.184.216.0/24", TrafficMode::BandwidthBoost),
                ip_rule("i", "93.184.216.34", TrafficMode::BestTransport),
            ],
        };
        // All three match; the exact-IP rule wins.
        assert_eq!(
            engine.mode_for(v4(93, 184, 216, 34)),
            TrafficMode::BestTransport
        );
        // Drop the IP rule: the subnet wins over the domain rule.
        let mut engine2 = engine.clone();
        engine2.rules.retain(|r| r.id != "i");
        assert_eq!(
            engine2.mode_for(v4(93, 184, 216, 34)),
            TrafficMode::BandwidthBoost
        );
        // Drop the subnet too: only the domain rule matches.
        engine2.rules.retain(|r| r.id != "s");
        assert_eq!(
            engine2.mode_for(v4(93, 184, 216, 34)),
            TrafficMode::LowestLatency
        );
        // A neighbour in the same /24 matches the subnet but not the
        // domain IPs or the exact IP.
        assert_eq!(
            engine.mode_for(v4(93, 184, 216, 99)),
            TrafficMode::BandwidthBoost
        );
    }

    #[test]
    fn longest_prefix_wins_between_subnets() {
        let engine = TrafficModeEngine {
            default_mode: TrafficMode::Default,
            rules: vec![
                subnet_rule("wide", "10.0.0.0/8", TrafficMode::BestTransport),
                subnet_rule("narrow", "10.1.2.0/24", TrafficMode::LowestLatency),
            ],
        };
        let dst = v4(10, 1, 2, 3);
        assert!(engine.rules[0].matches(dst));
        assert!(engine.rules[1].matches(dst));
        // The narrower /24 wins over the /8.
        assert_eq!(engine.mode_for(dst), TrafficMode::LowestLatency);
        // Order independence: narrow first still wins — specificity
        // beats list order.
        let mut reversed = engine.clone();
        reversed.rules.reverse();
        assert_eq!(reversed.mode_for(dst), TrafficMode::LowestLatency);
    }

    #[test]
    fn first_rule_wins_on_equal_specificity() {
        // Two identical /8 subnets with different modes: the earliest
        // rule wins.
        let engine = TrafficModeEngine {
            default_mode: TrafficMode::Default,
            rules: vec![
                subnet_rule("a", "10.0.0.0/8", TrafficMode::BestTransport),
                subnet_rule("b", "10.0.0.0/8", TrafficMode::LowestLatency),
            ],
        };
        assert_eq!(
            engine.mode_for(v4(10, 9, 9, 9)),
            TrafficMode::BestTransport
        );
        // Reversing the list flips the winner — the tie-break is list
        // order, not mode.
        let mut reversed = engine.clone();
        reversed.rules.reverse();
        assert_eq!(
            reversed.mode_for(v4(10, 9, 9, 9)),
            TrafficMode::LowestLatency
        );
    }

    #[test]
    fn unresolved_domain_rule_matches_nothing() {
        let engine = TrafficModeEngine {
            default_mode: TrafficMode::Default,
            rules: vec![domain_rule("d", "unresolved.example", vec![], TrafficMode::Redundant)],
        };
        assert_eq!(engine.mode_for(v4(1, 2, 3, 4)), TrafficMode::Default);
        assert!(!engine.rules[0].matches(v4(1, 2, 3, 4)));
    }

    #[test]
    fn malformed_rules_match_nothing() {
        assert!(!ip_rule("x", "not-an-ip", TrafficMode::Default).matches(v4(1, 2, 3, 4)));
        assert!(!subnet_rule("x", "10.0.0.0/33", TrafficMode::Default).matches(v4(10, 0, 0, 1)));
        assert!(!subnet_rule("x", "10.0.0.0", TrafficMode::Default).matches(v4(10, 0, 0, 1)));
        assert!(!subnet_rule("x", "10.0.0.0/abc", TrafficMode::Default).matches(v4(10, 0, 0, 1)));
        // Family mismatch: an IPv4 subnet never matches an IPv6 dst.
        assert!(!subnet_rule("x", "10.0.0.0/8", TrafficMode::Default)
            .matches(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn subnet_matching_edges() {
        let rule = subnet_rule("s", "192.0.2.0/24", TrafficMode::Default);
        assert!(rule.matches(v4(192, 0, 2, 0)));
        assert!(rule.matches(v4(192, 0, 2, 255)));
        assert!(!rule.matches(v4(192, 0, 3, 0)));
        let any = subnet_rule("any", "0.0.0.0/0", TrafficMode::Default);
        assert!(any.matches(v4(203, 0, 113, 7)));
        let v6 = TrafficRule {
            id: "v6".to_string(),
            kind: TrafficRuleKind::Subnet,
            target: "2001:db8::/32".to_string(),
            resolved_ips: vec![],
            mode: TrafficMode::Default,
        };
        assert!(v6.matches("2001:db8::1".parse().unwrap()));
        assert!(!v6.matches("2001:db9::1".parse().unwrap()));
    }

    #[test]
    fn json_round_trip_and_bad_json_falls_back() {
        let engine = TrafficModeEngine {
            default_mode: TrafficMode::BestTransport,
            rules: vec![
                domain_rule(
                    "r1",
                    "example.com",
                    vec![v4(93, 184, 216, 34)],
                    TrafficMode::LowestLatency,
                ),
                subnet_rule("r2", "10.0.0.0/8", TrafficMode::Redundant),
            ],
        };
        let json = serde_json::to_string(&engine).expect("serialize");
        assert!(json.contains("\"defaultMode\":\"best_transport\""));
        assert!(json.contains("\"resolvedIps\":[\"93.184.216.34\"]"));
        let back = TrafficModeEngine::from_json(&json).expect("parse");
        assert_eq!(back, engine);
        // Unknown mode string in JSON falls back to default for that field.
        let unknown = r#"{"defaultMode":"nope","rules":[]}"#;
        assert_eq!(
            TrafficModeEngine::from_json(unknown).expect("parse").default_mode,
            TrafficMode::Default
        );
        // Malformed JSON as a whole falls back to the empty engine.
        assert_eq!(
            TrafficModeEngine::from_json_or_default("{not json"),
            TrafficModeEngine::default()
        );
        assert_eq!(
            TrafficModeEngine::from_json_or_default(""),
            TrafficModeEngine::default()
        );
    }

    #[test]
    fn default_order_spreads_by_hash_and_keeps_active() {
        let engine = TrafficModeEngine::default();
        // Two transports: the hash pick is first, the other second.
        for flow in 0..64u64 {
            let ordered = engine.order_candidates(TrafficMode::Default, flow, 2, 0, &[]);
            let pick = (flow % 2) as usize;
            assert_eq!(ordered, vec![pick, 1 - pick], "flow {flow}");
        }
        // Single transport reduces to just it.
        assert_eq!(
            engine.order_candidates(TrafficMode::Default, 7, 1, 0, &[]),
            vec![0]
        );
        // Empty transport set: active transport is the only candidate.
        assert_eq!(
            engine.order_candidates(TrafficMode::Default, 7, 0, 3, &[]),
            vec![3]
        );
        // Unimplemented modes fall back to exactly the default order.
        for mode in [
            TrafficMode::BestTransport,
            TrafficMode::LowestLatency,
            TrafficMode::BandwidthBoost,
            TrafficMode::Redundant,
        ] {
            assert_eq!(
                engine.order_candidates(mode, 5, 3, 1, &[]),
                engine.order_candidates(TrafficMode::Default, 5, 3, 1, &[]),
                "mode {mode:?} must fall back to default order"
            );
        }
    }

    #[test]
    fn listen_mixlr_rule_matches_user_observed_ip() {
        // Tonight's redundant test target (user-corrected 2026-11-06:
        // listen.mixlr.com hosts the actual Winterhawks stream;
        // winterhawks.codingwell.net is just the player page).
        //
        // RESOLVER DEPENDENCE (proven 2026-11-06): the same name yields
        // different IPs on different networks — the user observes
        // 15.235.46.15 on their network, this VM's resolver returns
        // 198.18.232.237. Neither IP is baked into the app: the rule is
        // always resolved on-device with the device's own resolver, at
        // save time and again on VPN start, and matches ALL returned
        // IPs. Here 15.235.46.15 is test INPUT data only (the user's
        // observed reading, passed in as the rule's resolved set), not
        // a claim about what the domain resolves to.
        let engine = TrafficModeEngine {
            default_mode: TrafficMode::Default,
            rules: vec![domain_rule(
                "mixlr",
                "listen.mixlr.com",
                vec![v4(15, 235, 46, 15)],
                TrafficMode::Redundant,
            )],
        };
        assert_eq!(
            engine.mode_for(v4(15, 235, 46, 15)),
            TrafficMode::Redundant,
            "traffic to the user's observed stream IP must take the rule's mode"
        );
        // A destination NOT in the resolved set falls back to the
        // default mode — a rule never captures traffic it was not
        // resolved to. (That includes an address another network's
        // resolver would return for the same name: the rule matches
        // only what THIS device resolved.)
        assert_eq!(
            engine.mode_for(v4(203, 0, 113, 9)),
            TrafficMode::Default,
            "an IP outside the resolved set must fall back to default"
        );
        assert_eq!(
            engine.mode_for(v4(93, 184, 216, 34)),
            TrafficMode::Default
        );
    }

    #[test]
    fn domain_rule_matches_every_resolved_ip() {
        // A resolver may return several IPs for one domain (round-robin
        // / geo-DNS); the rule must match ALL of them, not just the first.
        let engine = TrafficModeEngine {
            default_mode: TrafficMode::Default,
            rules: vec![domain_rule(
                "multi",
                "multi.example",
                vec![v4(203, 0, 113, 1), v4(203, 0, 113, 2), v4(203, 0, 113, 3)],
                TrafficMode::LowestLatency,
            )],
        };
        for ip in [v4(203, 0, 113, 1), v4(203, 0, 113, 2), v4(203, 0, 113, 3)] {
            assert_eq!(engine.mode_for(ip), TrafficMode::LowestLatency);
        }
        assert_eq!(
            engine.mode_for(v4(203, 0, 113, 4)),
            TrafficMode::Default,
            "an unlisted IP in the same /24 still falls back to default"
        );
    }

    #[test]
    fn order_for_packet_uses_dst_ip() {
        // IPv4 UDP packet to 10.1.2.3 with a subnet rule for 10.0.0.0/8.
        let engine = TrafficModeEngine {
            default_mode: TrafficMode::Default,
            rules: vec![subnet_rule("s", "10.0.0.0/8", TrafficMode::Redundant)],
        };
        let mut packet = vec![0x45u8, 0, 0, 28, 0, 0, 0, 0, 64, 17, 0, 0];
        packet.extend_from_slice(&[192, 0, 2, 1]); // src
        packet.extend_from_slice(&[10, 1, 2, 3]); // dst
        packet.extend_from_slice(&[1234u16.to_be_bytes(), 53u16.to_be_bytes()].concat());
        let ordered = engine.order_for_packet(&packet, 2, 0, &[]);
        let expected =
            engine.order_candidates(TrafficMode::Default, flow_hash(&packet), 2, 0, &[]);
        assert_eq!(ordered, expected);
        // Non-IP packet: default mode, still hash-spread.
        let ordered = engine.order_for_packet(&[0x00, 0x01, 0x02], 2, 0, &[]);
        assert_eq!(ordered.len(), 2);
    }
}
