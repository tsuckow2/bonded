import 'package:flutter/material.dart';

/// Hub for the active diagnostic tools — the things you *run*, as opposed
/// to the read-only session details. Each tool keeps its own page.
class DiagnosticsScreen extends StatelessWidget {
  const DiagnosticsScreen({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Diagnostics')),
      body: ListView(
        children: [
          ListTile(
            leading: const Icon(Icons.bolt),
            title: const Text('Protocol stress test'),
            subtitle: const Text(
              'Per-protocol connection tests, including the UDP probe',
            ),
            trailing: const Icon(Icons.arrow_forward),
            onTap: () => Navigator.of(context).pushNamed('/stress-tests'),
          ),
          const Divider(),
          ListTile(
            leading: const Icon(Icons.network_check),
            title: const Text('Network tests'),
            subtitle: const Text('DNS, TCP, and HTTP checks per network'),
            trailing: const Icon(Icons.arrow_forward),
            onTap: () => Navigator.of(context).pushNamed('/network-tests'),
          ),
          const Divider(),
          ListTile(
            leading: const Icon(Icons.article_outlined),
            title: const Text('Client logs'),
            subtitle: const Text('On-device diagnostic log ring'),
            trailing: const Icon(Icons.arrow_forward),
            onTap: () => Navigator.of(context).pushNamed('/client-logs'),
          ),
        ],
      ),
    );
  }
}
