import 'package:bonded_app/models/traffic_mode.dart';
import 'package:bonded_app/services/traffic_rules_service.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  group('TrafficMode wire names', () {
    test('round-trip through wire names', () {
      for (final mode in TrafficMode.values) {
        expect(TrafficMode.fromWireName(mode.wireName), mode);
      }
      expect(TrafficMode.fromWireName('nonsense'), TrafficMode.defaultMode);
      expect(TrafficMode.fromWireName(null), TrafficMode.defaultMode);
    });

    test('all six modes are implemented in 4.100', () {
      expect(TrafficMode.defaultMode.isImplemented, isTrue);
      expect(TrafficMode.bestTransport.isImplemented, isTrue);
      expect(TrafficMode.lowestLatency.isImplemented, isTrue);
      expect(TrafficMode.bandwidthBoost.isImplemented, isTrue);
      expect(TrafficMode.redundant.isImplemented, isTrue);
      expect(TrafficMode.adaptive.isImplemented, isTrue);
      expect(TrafficMode.bestTransport.implementedIn, '4.52');
      expect(TrafficMode.lowestLatency.implementedIn, '4.52');
      expect(TrafficMode.bandwidthBoost.implementedIn, '4.53');
      expect(TrafficMode.redundant.implementedIn, '4.54');
      expect(TrafficMode.adaptive.implementedIn, '4.100');
      expect(TrafficMode.adaptive.wireName, 'adaptive');
      expect(TrafficMode.adaptive.label, 'Adaptive (per-flow)');
    });
  });

  group('TrafficRule JSON', () {
    test('round-trips the Rust serde shape', () {
      const rule = TrafficRule(
        id: 'r1',
        kind: TrafficRuleKind.domain,
        target: 'example.com',
        resolvedIps: ['93.184.216.34'],
        mode: TrafficMode.redundant,
      );
      final json = rule.toJson();
      expect(json, {
        'id': 'r1',
        'kind': 'domain',
        'target': 'example.com',
        'resolvedIps': ['93.184.216.34'],
        'mode': 'redundant',
      });
      expect(TrafficRule.fromJson(json), rule);
    });

    test('unknown kind/mode fall back instead of throwing', () {
      final rule = TrafficRule.fromJson({
        'id': 'r1',
        'kind': 'weird',
        'target': 'example.com',
        'mode': 'weird',
      });
      expect(rule.kind, TrafficRuleKind.domain);
      expect(rule.mode, TrafficMode.defaultMode);
      expect(rule.resolvedIps, isEmpty);
    });

    test('unresolved means a domain rule with no IPs', () {
      const unresolved = TrafficRule(
        id: 'u',
        kind: TrafficRuleKind.domain,
        target: 'unresolved.example',
      );
      expect(unresolved.isUnresolved, isTrue);
      const resolved = TrafficRule(
        id: 'r',
        kind: TrafficRuleKind.domain,
        target: 'example.com',
        resolvedIps: ['93.184.216.34'],
      );
      expect(resolved.isUnresolved, isFalse);
      // IP/subnet rules never count as unresolved: they carry no
      // resolved list by design.
      const ip = TrafficRule(
        id: 'i',
        kind: TrafficRuleKind.ip,
        target: '192.0.2.1',
      );
      expect(ip.isUnresolved, isFalse);
    });
  });

  group('TrafficModeSettings JSON', () {
    test('round-trips default mode + rules', () {
      const settings = TrafficModeSettings(
        defaultMode: TrafficMode.bestTransport,
        rules: [
          TrafficRule(
            id: 'r1',
            kind: TrafficRuleKind.subnet,
            target: '10.0.0.0/8',
            mode: TrafficMode.lowestLatency,
          ),
        ],
      );
      final json = settings.toJson();
      expect(json['defaultMode'], 'best_transport');
      expect(TrafficModeSettings.fromJson(json), settings);
    });

    test('missing fields fall back to the empty default table', () {
      expect(
        TrafficModeSettings.fromJson({}),
        const TrafficModeSettings(),
      );
    });
  });

  group('target detection + validation', () {
    test('exact IP beats CIDR beats domain', () {
      expect(detectTargetKind('192.0.2.1'), TrafficRuleKind.ip);
      expect(detectTargetKind('2001:db8::1'), TrafficRuleKind.ip);
      expect(detectTargetKind('10.0.0.0/8'), TrafficRuleKind.subnet);
      expect(detectTargetKind('2001:db8::/32'), TrafficRuleKind.subnet);
      expect(detectTargetKind('example.com'), TrafficRuleKind.domain);
      expect(detectTargetKind('listen.mixlr.com'), TrafficRuleKind.domain);
    });

    test('CIDR parsing enforces family prefix ranges', () {
      expect(parseCidr('10.0.0.0/8'), isNotNull);
      expect(parseCidr('10.0.0.0/33'), isNull);
      expect(parseCidr('2001:db8::/129'), isNull);
      expect(parseCidr('10.0.0.0'), isNull);
      expect(parseCidr('10.0.0.0/abc'), isNull);
      expect(parseCidr('not-an-ip/24'), isNull);
      expect(parseCidr('10.0.0.0/8/9'), isNull);
    });

    test('validation rejects blanks, schemes, and malformed domains', () {
      expect(validateTarget(''), isNotNull);
      expect(validateTarget('   '), isNotNull);
      expect(validateTarget('https://example.com'), isNotNull);
      expect(validateTarget('exa mple.com'), isNotNull);
      expect(validateTarget('.example.com'), isNotNull);
      expect(validateTarget('example.com.'), isNotNull);
      expect(validateTarget('localhost'), isNotNull);
      expect(validateTarget('example.com'), isNull);
      expect(validateTarget('192.0.2.1'), isNull);
      expect(validateTarget('10.0.0.0/8'), isNull);
    });
  });
}
