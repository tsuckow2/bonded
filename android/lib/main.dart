import 'dart:async';

import 'package:app_links/app_links.dart';
import 'package:flutter/material.dart';
import 'screens/home_screen.dart';
import 'screens/qr_scanner_screen.dart';
import 'screens/pair_device_confirm_screen.dart';
import 'screens/pair_tv_screen.dart';
import 'screens/pairing_confirm_screen.dart';
import 'screens/details_screen.dart';
import 'screens/diagnostics_screen.dart';
import 'screens/server_config_screen.dart';
import 'screens/settings_screen.dart';
import 'screens/network_tests_screen.dart';
import 'screens/client_logs_screen.dart';
import 'screens/stress_test_screen.dart';
import 'models/pairing_model.dart';
import 'models/pair_device_model.dart';

void main() {
  runApp(const BondedApp());
}

class BondedApp extends StatefulWidget {
  const BondedApp({super.key});

  @override
  State<BondedApp> createState() => _BondedAppState();
}

class _BondedAppState extends State<BondedApp> {
  final GlobalKey<NavigatorState> _navigatorKey = GlobalKey<NavigatorState>();
  late final AppLinks _appLinks;
  StreamSubscription<Uri>? _linkSubscription;

  @override
  void initState() {
    super.initState();
    _appLinks = AppLinks();
    _initDeepLinks();
  }

  @override
  void dispose() {
    _linkSubscription?.cancel();
    super.dispose();
  }

  Future<void> _initDeepLinks() async {
    // Link that launched the app (cold start).
    try {
      final initialLink = await _appLinks.getInitialLink();
      if (initialLink != null) {
        _handlePairingLink(initialLink);
      }
    } catch (_) {
      // No initial link or platform not supported; ignore.
    }

    // Links received while the app is already running.
    _linkSubscription = _appLinks.uriLinkStream.listen(
      _handlePairingLink,
      onError: (_) {},
    );
  }

  /// Handles `bonded://pair?server=...&token=...&key=...` deep links by
  /// navigating to the pairing confirmation screen with the parsed payload.
  void _handlePairingLink(Uri uri) {
    if (uri.scheme != 'bonded' || uri.host != 'pair') return;

    final params = uri.queryParameters;
    final server = (params['server'] ?? '').trim();
    final token = (params['token'] ?? '').trim();
    final key = (params['key'] ?? '').trim();
    if (server.isEmpty || token.isEmpty || key.isEmpty) return;

    final payload = ServerPairingPayload(
      publicAddress: server,
      inviteToken: token,
      serverIdentityPublicKey: key,
      supportedProtocols: const [],
    );

    // Defer navigation until after the first frame so the Navigator exists.
    WidgetsBinding.instance.addPostFrameCallback((_) {
      _navigatorKey.currentState?.pushNamed(
        '/pairing-confirm',
        arguments: payload,
      );
    });
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Bonded',
      navigatorKey: _navigatorKey,
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.teal),
        useMaterial3: true,
      ),
      initialRoute: '/home',
      routes: {
        '/home': (context) => const HomeScreen(),
        '/qr-scanner': (context) => const QRScannerScreen(),
        '/qr-scanner-pair-device': (context) =>
            const QRScannerScreen(pairDeviceMode: true),
        '/pair-tv': (context) => const PairTvScreen(),
        '/diagnostics': (context) => const DiagnosticsScreen(),
        '/settings': (context) => const SettingsScreen(),
        '/network-tests': (context) => const NetworkTestsScreen(),
        '/stress-tests': (context) => const StressTestScreen(),
        '/client-logs': (context) => const ClientLogsScreen(),
      },
      onGenerateRoute: (settings) {
        if (settings.name == '/pairing-confirm') {
          final payload = settings.arguments as ServerPairingPayload?;
          if (payload != null) {
            return MaterialPageRoute(
              builder: (context) => PairingConfirmScreen(payload: payload),
            );
          }
        }
        if (settings.name == '/pair-device-confirm') {
          final payload = settings.arguments as PairDevicePayload?;
          if (payload != null) {
            return MaterialPageRoute(
              builder: (context) => PairDeviceConfirmScreen(payload: payload),
            );
          }
        }
        if (settings.name == '/details') {
          final args = settings.arguments as Map<String, dynamic>?;
          final deviceId = args?['deviceId'] as String? ?? '';
          return MaterialPageRoute(
            builder: (context) => DetailsScreen(deviceId: deviceId),
          );
        }
        if (settings.name == '/server-config') {
          final server = settings.arguments as PairedServer?;
          if (server != null) {
            return MaterialPageRoute(
              builder: (context) => ServerConfigScreen(server: server),
            );
          }
        }
        return null;
      },
      onUnknownRoute: (settings) {
        return MaterialPageRoute(builder: (context) => const HomeScreen());
      },
    );
  }
}
