import 'package:flutter/material.dart';

/// One throughput sample: bytes/sec in each direction at a point in time.
class RateSample {
  final double downBps;
  final double upBps;
  const RateSample(this.downBps, this.upBps);
}

/// Rolling throughput chart (download teal, upload orange) drawn with a
/// plain CustomPaint — no chart dependency, values are simple polylines
/// over the sampled window.
class ThroughputChart extends StatelessWidget {
  final List<RateSample> samples;
  final double height;

  const ThroughputChart({super.key, required this.samples, this.height = 96});

  @override
  Widget build(BuildContext context) {
    return SizedBox(
      height: height,
      width: double.infinity,
      child: CustomPaint(
        painter: _ThroughputPainter(
          samples,
          downColor: Colors.teal,
          upColor: Colors.orange,
          gridColor: Colors.grey.withAlpha(60),
        ),
      ),
    );
  }
}

class _ThroughputPainter extends CustomPainter {
  final List<RateSample> samples;
  final Color downColor;
  final Color upColor;
  final Color gridColor;

  _ThroughputPainter(
    this.samples, {
    required this.downColor,
    required this.upColor,
    required this.gridColor,
  });

  @override
  void paint(Canvas canvas, Size size) {
    final gridPaint = Paint()
      ..color = gridColor
      ..strokeWidth = 1;
    for (var i = 1; i <= 3; i++) {
      final y = size.height * i / 4;
      canvas.drawLine(Offset(0, y), Offset(size.width, y), gridPaint);
    }
    if (samples.length < 2) return;

    var maxValue = 1.0;
    for (final sample in samples) {
      if (sample.downBps > maxValue) maxValue = sample.downBps;
      if (sample.upBps > maxValue) maxValue = sample.upBps;
    }

    void drawSeries(double Function(RateSample) pick, Color color) {
      final path = Path();
      for (var i = 0; i < samples.length; i++) {
        final x = size.width * i / (samples.length - 1);
        final y = size.height - (pick(samples[i]) / maxValue) * size.height;
        if (i == 0) {
          path.moveTo(x, y);
        } else {
          path.lineTo(x, y);
        }
      }
      final line = Paint()
        ..color = color
        ..strokeWidth = 1.8
        ..style = PaintingStyle.stroke;
      canvas.drawPath(path, line);

      // Soft fill under the line.
      final fill = Path.from(path)
        ..lineTo(size.width, size.height)
        ..lineTo(0, size.height)
        ..close();
      canvas.drawPath(
        fill,
        Paint()..color = color.withAlpha(36),
      );
    }

    drawSeries((s) => s.downBps, downColor);
    drawSeries((s) => s.upBps, upColor);
  }

  @override
  bool shouldRepaint(covariant _ThroughputPainter oldDelegate) => true;
}

/// Rolling single-series line chart for the active path's RTT (ms).
class RttChart extends StatelessWidget {
  final List<double> samplesMs;
  final double height;

  const RttChart({super.key, required this.samplesMs, this.height = 64});

  @override
  Widget build(BuildContext context) {
    return SizedBox(
      height: height,
      width: double.infinity,
      child: CustomPaint(
        painter: _RttPainter(
          samplesMs,
          color: Colors.indigo,
          gridColor: Colors.grey.withAlpha(60),
        ),
      ),
    );
  }
}

class _RttPainter extends CustomPainter {
  final List<double> samples;
  final Color color;
  final Color gridColor;

  _RttPainter(this.samples, {required this.color, required this.gridColor});

  @override
  void paint(Canvas canvas, Size size) {
    final gridPaint = Paint()
      ..color = gridColor
      ..strokeWidth = 1;
    for (var i = 1; i <= 2; i++) {
      final y = size.height * i / 3;
      canvas.drawLine(Offset(0, y), Offset(size.width, y), gridPaint);
    }
    // Only plot real measurements (0 = none yet).
    final points = samples.where((v) => v > 0).toList();
    if (points.length < 2) return;

    var maxValue = 50.0;
    for (final value in points) {
      if (value > maxValue) maxValue = value;
    }

    final path = Path();
    for (var i = 0; i < points.length; i++) {
      final x = size.width * i / (points.length - 1);
      final y = size.height - (points[i] / maxValue) * (size.height - 4) - 2;
      if (i == 0) {
        path.moveTo(x, y);
      } else {
        path.lineTo(x, y);
      }
    }
    canvas.drawPath(
      path,
      Paint()
        ..color = color
        ..strokeWidth = 1.8
        ..style = PaintingStyle.stroke,
    );
  }

  @override
  bool shouldRepaint(covariant _RttPainter oldDelegate) => true;
}
