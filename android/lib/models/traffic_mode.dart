/// Traffic modes + per-destination rules (plan 4.51).
///
/// A mode picks how a flow's packets are placed on the session's
/// transports. `default` has behavior since 4.51; `bestTransport`
/// and `lowestLatency` since 4.52. The other modes
/// (`bandwidthBoost`, `redundant`) land in slices 4.53–4.54; until a
/// mode's slice lands, selecting it falls back to default behavior —
/// the UI says so, and so does the Rust engine, so a
/// selected-but-unimplemented mode is never silently pretended.
///
/// Rules resolve a mode per flow from the destination IP only, in
/// Rust (`bonded-core` `TrafficModeEngine`). A rule matches an exact
/// IP, a subnet (CIDR), or the IPs a domain resolved to when the rule
/// was saved — domains are PRE-RESOLVED by the app, never snooped
/// from live DNS traffic (explicit user direction). Matching at
/// flow-pin time is IP-based only, against the stored resolved IPs.
/// A domain rule whose resolution failed (empty `resolvedIps`)
/// matches nothing and is flagged in the UI.
///
/// The JSON shape is shared with Rust (serde camelCase):
/// `{"defaultMode": "default", "rules": [...]}` and per rule
/// `{"id": …, "kind": "domain"|"ip"|"subnet", "target": …,
/// "resolvedIps": […], "mode": "redundant"}`. Wire names are
/// snake_case (`best_transport`, …) on both sides.
///
/// How one flow's traffic is placed on the session's transports.
enum TrafficMode {
  /// Current behavior: flow-hash spreading across transports.
  defaultMode,

  /// Send on the transport the most recent data came on (4.52).
  bestTransport,

  /// Send on the lowest-latency transport (4.52).
  lowestLatency,

  /// Flow-level spreading weighted by grade/loss (4.53).
  bandwidthBoost,

  /// Duplicate on all transports, both ways (4.54).
  redundant;

  /// Wire name shared with Rust (`default`, `best_transport`, …).
  String get wireName => switch (this) {
    TrafficMode.defaultMode => 'default',
    TrafficMode.bestTransport => 'best_transport',
    TrafficMode.lowestLatency => 'lowest_latency',
    TrafficMode.bandwidthBoost => 'bandwidth_boost',
    TrafficMode.redundant => 'redundant',
  };

  /// Short label for the rules UI.
  String get label => switch (this) {
    TrafficMode.defaultMode => 'Default (flow spreading)',
    TrafficMode.bestTransport => 'Best transport',
    TrafficMode.lowestLatency => 'Lowest latency',
    TrafficMode.bandwidthBoost => 'Bandwidth boost',
    TrafficMode.redundant => 'Redundant (all transports)',
  };

  /// `default`, `bestTransport`, and `lowestLatency` have behavior
  /// (4.51–4.52). The rest are selectable but fall back to default
  /// until their slice lands.
  bool get isImplemented =>
      this == TrafficMode.defaultMode ||
      this == TrafficMode.bestTransport ||
      this == TrafficMode.lowestLatency;

  /// The slice that implements this mode, for the UI fallback note.
  String get implementedIn => switch (this) {
    TrafficMode.defaultMode => '4.51',
    TrafficMode.bestTransport => '4.52',
    TrafficMode.lowestLatency => '4.52',
    TrafficMode.bandwidthBoost => '4.53',
    TrafficMode.redundant => '4.54',
  };

  static TrafficMode fromWireName(String? name) => switch (name) {
    'best_transport' => TrafficMode.bestTransport,
    'lowest_latency' => TrafficMode.lowestLatency,
    'bandwidth_boost' => TrafficMode.bandwidthBoost,
    'redundant' => TrafficMode.redundant,
    _ => TrafficMode.defaultMode,
  };
}

/// What a rule matches on.
enum TrafficRuleKind {
  /// One exact IP address.
  ip,

  /// A CIDR subnet (`192.0.2.0/24`, `2001:db8::/32`).
  subnet,

  /// A domain; matches the IPs it resolved to when saved / on VPN start.
  domain;

  String get wireName => name;

  String get label => switch (this) {
    TrafficRuleKind.ip => 'IP address',
    TrafficRuleKind.subnet => 'Subnet (CIDR)',
    TrafficRuleKind.domain => 'Domain',
  };

  static TrafficRuleKind fromWireName(String? name) => switch (name) {
    'ip' => TrafficRuleKind.ip,
    'subnet' => TrafficRuleKind.subnet,
    _ => TrafficRuleKind.domain,
  };
}

/// One row of the rule table. `target` is what the user typed
/// (domain, IP, or CIDR) and is kept for display; `resolvedIps` is
/// what matching actually uses for domain rules.
class TrafficRule {
  final String id;
  final TrafficRuleKind kind;
  final String target;
  final List<String> resolvedIps;
  final TrafficMode mode;

  const TrafficRule({
    required this.id,
    required this.kind,
    required this.target,
    this.resolvedIps = const [],
    this.mode = TrafficMode.defaultMode,
  });

  /// A domain rule with no resolved IPs matches nothing — the domain
  /// never resolved (or has not been resolved yet). Flagged in the UI,
  /// never silently dropped.
  bool get isUnresolved =>
      kind == TrafficRuleKind.domain && resolvedIps.isEmpty;

  TrafficRule copyWith({
    String? id,
    TrafficRuleKind? kind,
    String? target,
    List<String>? resolvedIps,
    TrafficMode? mode,
  }) {
    return TrafficRule(
      id: id ?? this.id,
      kind: kind ?? this.kind,
      target: target ?? this.target,
      resolvedIps: resolvedIps ?? this.resolvedIps,
      mode: mode ?? this.mode,
    );
  }

  Map<String, dynamic> toJson() => {
    'id': id,
    'kind': kind.wireName,
    'target': target,
    'resolvedIps': resolvedIps,
    'mode': mode.wireName,
  };

  factory TrafficRule.fromJson(Map<String, dynamic> json) {
    return TrafficRule(
      id: (json['id'] as String?) ?? '',
      kind: TrafficRuleKind.fromWireName(json['kind'] as String?),
      target: (json['target'] as String?) ?? '',
      resolvedIps: (json['resolvedIps'] as List?)
              ?.map((e) => e.toString())
              .toList() ??
          const [],
      mode: TrafficMode.fromWireName(json['mode'] as String?),
    );
  }

  @override
  bool operator ==(Object other) =>
      other is TrafficRule &&
      id == other.id &&
      kind == other.kind &&
      target == other.target &&
      _listsEqual(resolvedIps, other.resolvedIps) &&
      mode == other.mode;

  @override
  int get hashCode =>
      Object.hash(id, kind, target, Object.hashAll(resolvedIps), mode);
}

bool _listsEqual(List<String> a, List<String> b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

/// The whole rule table: a default mode plus per-destination
/// overrides. This is what is persisted (via the existing
/// AppSettings / SharedPreferences store) and handed to Rust as JSON.
class TrafficModeSettings {
  final TrafficMode defaultMode;
  final List<TrafficRule> rules;

  const TrafficModeSettings({
    this.defaultMode = TrafficMode.defaultMode,
    this.rules = const [],
  });

  TrafficModeSettings copyWith({
    TrafficMode? defaultMode,
    List<TrafficRule>? rules,
  }) {
    return TrafficModeSettings(
      defaultMode: defaultMode ?? this.defaultMode,
      rules: rules ?? this.rules,
    );
  }

  Map<String, dynamic> toJson() => {
    'defaultMode': defaultMode.wireName,
    'rules': rules.map((r) => r.toJson()).toList(),
  };

  factory TrafficModeSettings.fromJson(Map<String, dynamic> json) {
    return TrafficModeSettings(
      defaultMode: TrafficMode.fromWireName(json['defaultMode'] as String?),
      rules: (json['rules'] as List?)
              ?.whereType<Map>()
              .map(
                (m) => TrafficRule.fromJson(
                  Map<String, dynamic>.from(m),
                ),
              )
              .toList() ??
          const [],
    );
  }

  @override
  bool operator ==(Object other) =>
      other is TrafficModeSettings &&
      defaultMode == other.defaultMode &&
      rules.length == other.rules.length &&
      rules.asMap().entries.every((e) => e.value == other.rules[e.key]);

  @override
  int get hashCode =>
      Object.hash(defaultMode, Object.hashAll(rules));
}
