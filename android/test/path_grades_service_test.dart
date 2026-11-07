import 'package:bonded_app/services/path_grades_service.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  group('PathGradesService', () {
    test('toJson is a bare array in snapshot order, nulls for ungraded', () {
      expect(PathGradesService.toJson([84, null, 71]), '[84,null,71]');
      expect(PathGradesService.toJson([]), '[]');
      expect(PathGradesService.toJson([null]), '[null]');
    });

    test('pushLive sends the grades JSON and reports the native result',
        () async {
      const channel = MethodChannel('bonded/native');
      final calls = <MethodCall>[];
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (call) async {
        calls.add(call);
        return true;
      });
      addTearDown(() async {
        TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
            .setMockMethodCallHandler(channel, null);
      });

      expect(await PathGradesService.pushLive([84, null, 71]), isTrue);
      expect(calls, hasLength(1));
      expect(calls.single.method, 'updatePathGrades');
      expect(
        (calls.single.arguments as Map)['pathGradesJson'],
        '[84,null,71]',
      );
    });

    test('pushLive returns false when the native side reports false',
        () async {
      const channel = MethodChannel('bonded/native');
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (call) async => false);
      addTearDown(() async {
        TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
            .setMockMethodCallHandler(channel, null);
      });

      expect(await PathGradesService.pushLive([84]), isFalse);
    });

    test('pushLive returns false instead of throwing when the channel fails',
        () async {
      const channel = MethodChannel('bonded/native');
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (call) async {
        throw PlatformException(code: 'boom');
      });
      addTearDown(() async {
        TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
            .setMockMethodCallHandler(channel, null);
      });

      expect(await PathGradesService.pushLive([84]), isFalse);
    });
  });
}
