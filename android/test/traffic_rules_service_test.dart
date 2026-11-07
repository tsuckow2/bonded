import 'dart:io';

import 'package:bonded_app/models/traffic_mode.dart';
import 'package:bonded_app/services/traffic_rules_service.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  group('domain pre-resolution', () {
    test('listen.mixlr.com resolves on-device to at least one IP', () async {
      // Tonight's redundant test target. This asserts ONLY that the
      // device's own resolver answers with usable IPs — never WHICH
      // IPs: the domain is resolver-dependent (the user observes
      // 15.235.46.15 on their network, this VM's resolver returns
      // 198.18.232.237), so no address is asserted here. The rule
      // built from whatever the lookup returns is what matches.
      final ips = await TrafficRulesService.resolveDomain(
        'listen.mixlr.com',
      );
      expect(ips, isNotEmpty);
      for (final ip in ips) {
        expect(InternetAddress.tryParse(ip), isNotNull);
      }
      final rule = TrafficRule(
        id: 'mixlr',
        kind: TrafficRuleKind.domain,
        target: 'listen.mixlr.com',
        resolvedIps: ips,
        mode: TrafficMode.redundant,
      );
      expect(rule.isUnresolved, isFalse);
      // The stored rule round-trips through the engine JSON shape.
      final restored = TrafficRule.fromJson(rule.toJson());
      expect(restored, rule);
      expect(restored.resolvedIps, ips);
    });

    test('resolveRule flags an unresolvable domain instead of throwing',
        () async {
      // A 64-character label is rejected by the resolver itself
      // (max 63 per label), so this fails even where the sandbox DNS
      // sinkholes ordinary unresolvable names to a catch-all IP.
      final badName = '${'a' * 64}.invalid';
      final rule = TrafficRule(
        id: 'bad',
        kind: TrafficRuleKind.domain,
        target: badName,
        mode: TrafficMode.redundant,
      );
      final resolved = await TrafficRulesService.resolveRule(rule);
      expect(resolved.resolvedIps, isEmpty);
      expect(resolved.isUnresolved, isTrue);
      expect(resolved.target, rule.target);
      expect(resolved.mode, rule.mode);
    });

    test('resolveRule passes IP/subnet rules through untouched', () async {
      const ip = TrafficRule(
        id: 'i',
        kind: TrafficRuleKind.ip,
        target: '192.0.2.1',
        mode: TrafficMode.lowestLatency,
      );
      expect(await TrafficRulesService.resolveRule(ip), ip);
      const subnet = TrafficRule(
        id: 's',
        kind: TrafficRuleKind.subnet,
        target: '10.0.0.0/8',
        mode: TrafficMode.bandwidthBoost,
      );
      expect(await TrafficRulesService.resolveRule(subnet), subnet);
    });

    test(
        'reResolveAll keeps stored IPs when re-resolution fails',
        () async {
      // A transient DNS failure must not un-match traffic that was
      // matching: only a successful lookup replaces stored IPs.
      // (64-char label: rejected by the resolver itself, so this
      // fails even where the sandbox DNS sinkholes ordinary names.)
      final badName = '${'a' * 64}.invalid';
      final settings = TrafficModeSettings(
        rules: [
          TrafficRule(
            id: 'bad',
            kind: TrafficRuleKind.domain,
            target: badName,
            resolvedIps: ['203.0.113.7'],
            mode: TrafficMode.redundant,
          ),
        ],
      );
      final refreshed = await TrafficRulesService.reResolveAll(settings);
      expect(refreshed.rules.single.resolvedIps, ['203.0.113.7']);
    });
  });
}
