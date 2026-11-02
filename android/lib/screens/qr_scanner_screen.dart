import 'package:flutter/material.dart';
import 'package:mobile_scanner/mobile_scanner.dart';
import 'package:permission_handler/permission_handler.dart';

import '../models/pairing_model.dart';
import '../models/pair_device_model.dart';

class QRScannerScreen extends StatefulWidget {
  /// When true, only TV pairing codes are accepted (pair-device flow).
  final bool pairDeviceMode;

  const QRScannerScreen({super.key, this.pairDeviceMode = false});

  @override
  State<QRScannerScreen> createState() => _QRScannerScreenState();
}

class _QRScannerScreenState extends State<QRScannerScreen> {
  late MobileScannerController controller;
  bool hasPermission = false;
  bool isLoading = true;
  bool _isNavigating = false;

  @override
  void initState() {
    super.initState();
    controller = MobileScannerController();
    _checkPermission();
  }

  Future<void> _checkPermission() async {
    final status = await Permission.camera.request();
    final granted = status.isGranted || status.isLimited;

    setState(() {
      hasPermission = granted;
      isLoading = false;
    });
  }

  @override
  void dispose() {
    controller.dispose();
    super.dispose();
  }

  String get _title =>
      widget.pairDeviceMode ? 'Scan TV Pairing Code' : 'Scan Server QR Code';

  void _onDetect(BarcodeCapture capture) {
    if (_isNavigating) {
      return;
    }

    final List<Barcode> barcodes = capture.barcodes;

    for (final barcode in barcodes) {
      if (barcode.rawValue != null) {
        final String qrData = barcode.rawValue!;
        if (widget.pairDeviceMode) {
          final PairDevicePayload? devicePayload =
              PairDevicePayload.parseQrData(qrData);
          if (devicePayload != null) {
            _isNavigating = true;
            controller.stop();
            Navigator.of(context).pushReplacementNamed(
              '/pair-device-confirm',
              arguments: devicePayload,
            );
          } else {
            _showError(
              'This is not a TV pairing code. Show the pairing code on the TV and try again.',
            );
          }
          break;
        }
        final ServerPairingPayload? payload = ServerPairingPayload.parseQrData(
          qrData,
        );

        if (payload != null) {
          _isNavigating = true;
          controller.stop();

          // Successfully parsed QR code, navigate to pairing confirmation
          Navigator.of(
            context,
          ).pushReplacementNamed('/pairing-confirm', arguments: payload);
        } else {
          // Show error - invalid QR code format
          _showError('Invalid Bonded QR code. Please try again.');
        }

        break;
      }
    }
  }

  void _showError(String message) {
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text(message), backgroundColor: Colors.red),
    );
  }

  @override
  Widget build(BuildContext context) {
    if (isLoading) {
      return Scaffold(
        appBar: AppBar(title: Text(_title)),
        body: const Center(child: CircularProgressIndicator()),
      );
    }

    if (!hasPermission) {
      return Scaffold(
        appBar: AppBar(title: Text(_title)),
        body: Center(
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              const Icon(Icons.camera_alt, size: 64, color: Colors.grey),
              const SizedBox(height: 16),
              const Text(
                'Camera permission required',
                style: TextStyle(fontSize: 18),
              ),
              const SizedBox(height: 32),
              ElevatedButton(
                onPressed: _checkPermission,
                child: const Text('Grant Permission'),
              ),
            ],
          ),
        ),
      );
    }

    return Scaffold(
      appBar: AppBar(title: Text(_title)),
      body: Stack(
        children: [
          MobileScanner(controller: controller, onDetect: _onDetect),
          // Scanning overlay
          Container(
            color: Colors.black26,
            child: Stack(
              children: [
                // Dark overlay on sides and top/bottom
                Container(color: Colors.black.withAlpha(200)),
                // Clear rectangle in the center
                Center(
                  child: Container(
                    width: 280,
                    height: 280,
                    decoration: BoxDecoration(
                      border: Border.all(color: Colors.white, width: 2),
                      borderRadius: BorderRadius.circular(12),
                    ),
                  ),
                ),
              ],
            ),
          ),
          // Instructions at bottom
          Positioned(
            bottom: 0,
            left: 0,
            right: 0,
            child: Container(
              color: Colors.black.withAlpha(180),
              padding: const EdgeInsets.all(16),
              child: Column(
                children: [
                  Text(
                    widget.pairDeviceMode
                        ? 'Position the TV pairing code within the frame'
                        : 'Position QR code within the frame',
                    textAlign: TextAlign.center,
                    style: TextStyle(color: Colors.white, fontSize: 16),
                  ),
                  const SizedBox(height: 16),
                  ElevatedButton.icon(
                    onPressed: () => Navigator.of(context).pop(),
                    icon: const Icon(Icons.arrow_back),
                    label: const Text('Cancel'),
                    style: ElevatedButton.styleFrom(
                      backgroundColor: Colors.grey[700],
                    ),
                  ),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }
}
