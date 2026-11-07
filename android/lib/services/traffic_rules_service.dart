import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/services.dart';

import '../models/traffic_mode.dart';
import 'app_settings_service.dart';

/// Traffic-mode rules: validation, domain pre-resolution, and the
/// bridge between the rules UI, the persisted settings, and the live
/// Rust session (4.51).
///
/// DOMAIN RULES ARE PRE-RESOLVED — never snooped. A domain is
/// resolved to its IPs when the rule is saved AND again on VPN start
/// (see the home screen's connect path), and matching at flow-pin
/// time is IP-based only, against the stored resolved IPs. No DNS
/// lookup ever happens on the packet path, and no packet content is
/// inspected to learn hostnames.
class TrafficRulesService {
  static const MethodChannel _channel = MethodChannel('bonded/native');

  /// Resolve a domain to its IP addresses (deduplicated, in lookup
  /// order). Throws on lookup failure or timeout — callers decide
  /// whether that means "unresolved rule" or "keep stored IPs".
  static Future<List<String>> resolveDomain(
    String domain, {
    Duration timeout = const Duration(seconds: 5),
  }) async {
    final addresses = await InternetAddress.lookup(
      domain,
    ).timeout(timeout);
    final seen = <String>{};
    return addresses
        .map((a) => a.address)
        .where((ip) => seen.add(ip))
        .toList();
  }

  /// Re-resolve one rule. Non-domain rules pass through untouched.
  /// A domain that fails to resolve comes back with empty
  /// `resolvedIps` (matches nothing) instead of throwing — the UI
  /// flags it and the user can retry.
  static Future<TrafficRule> resolveRule(TrafficRule rule) async {
    if (rule.kind != TrafficRuleKind.domain) return rule;
    try {
      final ips = await resolveDomain(rule.target);
      return rule.copyWith(resolvedIps: ips);
    } catch (_) {
      return rule.copyWith(resolvedIps: const []);
    }
  }

  /// Re-resolve every domain rule in a settings object. A rule that
  /// fails to resolve this time KEEPS its previously stored IPs when
  /// it has any (a transient DNS failure must not un-match traffic
  /// that was matching); a rule that never resolved stays empty.
  static Future<TrafficModeSettings> reResolveAll(
    TrafficModeSettings settings,
  ) async {
    var changed = false;
    final rules = <TrafficRule>[];
    for (final rule in settings.rules) {
      if (rule.kind != TrafficRuleKind.domain) {
        rules.add(rule);
        continue;
      }
      try {
        final ips = await resolveDomain(rule.target);
        rules.add(rule.copyWith(resolvedIps: ips));
        if (!_listsEqual(ips, rule.resolvedIps)) changed = true;
      } catch (_) {
        // Keep the stored IPs: a failed re-resolution is not evidence
        // the domain moved. Only a successful lookup replaces them.
        rules.add(rule);
      }
    }
    return changed ? settings.copyWith(rules: rules) : settings;
  }

  /// Load the persisted rule table.
  static Future<TrafficModeSettings> load() async {
    final settings = await AppSettingsService.load();
    return settings.trafficModeSettings;
  }

  /// Persist the rule table AND push it to the live session when one
  /// is running. The push is best-effort: when no session is running
  /// the native side has nothing to update and the next connect picks
  /// the table up from the store. Failures are swallowed — settings
  /// must never crash the UI.
  static Future<void> save(TrafficModeSettings settings) async {
    final current = await AppSettingsService.load();
    await AppSettingsService.update(
      current.copyWith(trafficModeSettings: settings),
    );
    await pushLive(settings);
  }

  /// Push a rule table to the running Rust session without
  /// restarting it. Returns false when no session is running (or the
  /// push failed); the stored table still applies on next connect.
  static Future<bool> pushLive(TrafficModeSettings settings) async {
    try {
      final ok = await _channel.invokeMethod<bool>('updateTrafficRules', {
        'trafficRulesJson': jsonEncode(settings.toJson()),
      });
      return ok ?? false;
    } catch (_) {
      return false;
    }
  }

  /// The JSON handed to Rust at session start (same shape as
  /// `TrafficModeSettings.toJson`, as a string for the JNI boundary).
  static String toEngineJson(TrafficModeSettings settings) =>
      jsonEncode(settings.toJson());
}

/// What a user-typed rule target is. Detection order matters: an
/// exact IP first, then CIDR, then domain — a bare IP must never be
/// treated as a domain to resolve.
TrafficRuleKind detectTargetKind(String target) {
  final trimmed = target.trim();
  if (InternetAddress.tryParse(trimmed) != null) {
    return TrafficRuleKind.ip;
  }
  if (parseCidr(trimmed) != null) return TrafficRuleKind.subnet;
  return TrafficRuleKind.domain;
}

/// Parse `address/prefix` into (address, prefix), or null when the
/// target is not a well-formed CIDR for its address family.
({String address, int prefix})? parseCidr(String target) {
  final trimmed = target.trim();
  final slash = trimmed.indexOf('/');
  if (slash <= 0 || trimmed.indexOf('/', slash + 1) != -1) return null;
  final address = trimmed.substring(0, slash);
  final prefixText = trimmed.substring(slash + 1);
  final parsed = InternetAddress.tryParse(address);
  if (parsed == null) return null;
  final prefix = int.tryParse(prefixText);
  if (prefix == null) return null;
  final max = parsed.type == InternetAddressType.IPv4 ? 32 : 128;
  if (prefix < 0 || prefix > max) return null;
  return (address: address, prefix: prefix);
}

/// Validate a rule target the user typed. Returns an error string
/// for the dialog, or null when the target is usable. Domains are
/// deliberately lenient here (a bad domain fails at resolution time
/// and is flagged then, not rejected up front); IPs and CIDRs are
/// checked strictly because a typo there can never match.
String? validateTarget(String target) {
  final trimmed = target.trim();
  if (trimmed.isEmpty) return 'Enter a domain, IP address, or subnet.';
  if (trimmed.contains(' ') || trimmed.contains('://')) {
    return 'Enter just the domain, IP, or subnet — no scheme or spaces.';
  }
  final kind = detectTargetKind(trimmed);
  switch (kind) {
    case TrafficRuleKind.ip:
      return null;
    case TrafficRuleKind.subnet:
      return null;
    case TrafficRuleKind.domain:
      if (trimmed.startsWith('.') ||
          trimmed.endsWith('.') ||
          trimmed.contains('..') ||
          !trimmed.contains('.')) {
        return 'That does not look like a domain name.';
      }
      return null;
  }
}

bool _listsEqual(List<String> a, List<String> b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}
