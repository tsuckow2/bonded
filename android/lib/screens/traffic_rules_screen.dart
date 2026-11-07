import 'package:flutter/material.dart';

import '../models/traffic_mode.dart';
import '../services/traffic_rules_service.dart';

/// Traffic modes + rules settings screen (plan 4.51).
///
/// A default mode plus per-destination overrides. A rule takes a
/// domain, an IP address, or a subnet (CIDR) and a mode; domain rules
/// are pre-resolved to their IPs when saved (and again on VPN start)
/// — matching is IP-based only, never DNS snooping.
///
/// A mode whose slice has not landed yet — here or on a rule — falls
/// back to default, and the screen says so next to the picker
/// instead of pretending the mode is live. Since 4.54 every mode has
/// landed, so no mode falls back and the note shows nowhere.
class TrafficRulesScreen extends StatefulWidget {
  const TrafficRulesScreen({super.key});

  @override
  State<TrafficRulesScreen> createState() => _TrafficRulesScreenState();
}

class _TrafficRulesScreenState extends State<TrafficRulesScreen> {
  TrafficModeSettings _settings = const TrafficModeSettings();
  bool _loaded = false;
  bool _saving = false;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    final settings = await TrafficRulesService.load();
    if (!mounted) return;
    setState(() {
      _settings = settings;
      _loaded = true;
    });
  }

  Future<void> _save(TrafficModeSettings settings) async {
    setState(() {
      _settings = settings;
      _saving = true;
    });
    await TrafficRulesService.save(settings);
    if (!mounted) return;
    setState(() => _saving = false);
  }

  Future<void> _changeDefaultMode(TrafficMode mode) async {
    if (mode == _settings.defaultMode) return;
    await _save(_settings.copyWith(defaultMode: mode));
  }

  Future<void> _addRule() async {
    final rule = await _editRuleDialog();
    if (rule == null || !mounted) return;
    await _save(_settings.copyWith(rules: [..._settings.rules, rule]));
    if (rule.isUnresolved && mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(
            'Saved, but ${rule.target} could not be resolved — '
            'the rule matches nothing until it resolves.',
          ),
        ),
      );
    }
  }

  Future<void> _editRule(TrafficRule rule) async {
    final updated = await _editRuleDialog(existing: rule);
    if (updated == null || !mounted) return;
    final rules = _settings.rules
        .map((r) => r.id == rule.id ? updated : r)
        .toList();
    await _save(_settings.copyWith(rules: rules));
    if (updated.isUnresolved && mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(
            'Saved, but ${updated.target} could not be resolved — '
            'the rule matches nothing until it resolves.',
          ),
        ),
      );
    }
  }

  Future<void> _deleteRule(TrafficRule rule) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Delete rule?'),
        content: Text(
          'Remove the ${rule.mode.label} rule for ${rule.target}?',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(false),
            child: const Text('Cancel'),
          ),
          TextButton(
            onPressed: () => Navigator.of(context).pop(true),
            child: const Text('Delete'),
          ),
        ],
      ),
    );
    if (confirmed != true || !mounted) return;
    final rules = _settings.rules.where((r) => r.id != rule.id).toList();
    await _save(_settings.copyWith(rules: rules));
  }

  /// Add/edit dialog. Returns the resolved rule, or null when the
  /// user cancelled. Domain resolution happens here, before save, so
  /// the stored rule already carries its IPs.
  Future<TrafficRule?> _editRuleDialog({TrafficRule? existing}) async {
    final targetController = TextEditingController(
      text: existing?.target ?? '',
    );
    var mode = existing?.mode ?? TrafficMode.redundant;
    var error = '';
    var resolving = false;
    return showDialog<TrafficRule>(
      context: context,
      barrierDismissible: false,
      builder: (context) => StatefulBuilder(
        builder: (context, setDialogState) {
          final target = targetController.text;
          final kind = target.trim().isEmpty
              ? null
              : detectTargetKind(target);
          return AlertDialog(
            title: Text(existing == null ? 'Add rule' : 'Edit rule'),
            content: SingleChildScrollView(
              child: Column(
                mainAxisSize: MainAxisSize.min,
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  TextField(
                    controller: targetController,
                    autofocus: true,
                    decoration: const InputDecoration(
                      labelText: 'Domain, IP address, or subnet',
                      hintText: 'e.g. example.com, 192.0.2.1, 10.0.0.0/8',
                    ),
                    onChanged: (_) => setDialogState(() {}),
                  ),
                  if (kind != null) ...[
                    const SizedBox(height: 8),
                    Text(
                      kind == TrafficRuleKind.domain
                          ? 'Detected: domain — resolved to IPs on save.'
                          : 'Detected: ${kind.label}.',
                      style: Theme.of(context).textTheme.bodySmall,
                    ),
                  ],
                  const SizedBox(height: 16),
                  DropdownButtonFormField<TrafficMode>(
                    key: ValueKey(mode),
                    initialValue: mode,
                    decoration: const InputDecoration(
                      labelText: 'Mode for this destination',
                    ),
                    items: TrafficMode.values
                        .map(
                          (m) => DropdownMenuItem(
                            value: m,
                            child: Text(m.label),
                          ),
                        )
                        .toList(),
                    onChanged: (value) {
                      if (value != null) {
                        setDialogState(() => mode = value);
                      }
                    },
                  ),
                  if (!mode.isImplemented) ...[
                    const SizedBox(height: 8),
                    Text(
                      'Not live yet — falls back to Default until '
                      '${mode.implementedIn}.',
                      style: Theme.of(context).textTheme.bodySmall,
                    ),
                  ],
                  if (error.isNotEmpty) ...[
                    const SizedBox(height: 8),
                    Text(
                      error,
                      style: TextStyle(
                        color: Theme.of(context).colorScheme.error,
                      ),
                    ),
                  ],
                  if (resolving) ...[
                    const SizedBox(height: 16),
                    const Row(
                      children: [
                        SizedBox(
                          width: 16,
                          height: 16,
                          child: CircularProgressIndicator(strokeWidth: 2),
                        ),
                        SizedBox(width: 8),
                        Text('Resolving…'),
                      ],
                    ),
                  ],
                ],
              ),
            ),
            actions: [
              TextButton(
                onPressed: resolving
                    ? null
                    : () => Navigator.of(context).pop(null),
                child: const Text('Cancel'),
              ),
              TextButton(
                onPressed: resolving
                    ? null
                    : () async {
                        final validationError = validateTarget(
                          targetController.text,
                        );
                        if (validationError != null) {
                          setDialogState(() => error = validationError);
                          return;
                        }
                        final trimmed = targetController.text.trim();
                        final draft = TrafficRule(
                          id:
                              existing?.id ??
                              DateTime.now().microsecondsSinceEpoch.toString(),
                          kind: detectTargetKind(trimmed),
                          target: trimmed,
                          resolvedIps: existing?.resolvedIps ?? const [],
                          mode: mode,
                        );
                        setDialogState(() {
                          error = '';
                          resolving = true;
                        });
                        final resolved = await TrafficRulesService.resolveRule(
                          draft,
                        );
                        if (!context.mounted) return;
                        Navigator.of(context).pop(resolved);
                      },
                child: const Text('Save'),
              ),
            ],
          );
        },
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Traffic modes & rules')),
      body: !_loaded
          ? const Center(child: CircularProgressIndicator())
          : ListView(
              children: [
                const ListTile(
                  title: Text(
                    'How traffic is placed',
                    style: TextStyle(fontWeight: FontWeight.w700),
                  ),
                  subtitle: Text(
                    'Modes choose how a flow\u2019s packets are spread over '
                    'your transports. Rules override the default mode for '
                    'one destination (domain, IP, or subnet).',
                  ),
                ),
                Padding(
                  padding: const EdgeInsets.symmetric(horizontal: 16),
                  child: DropdownButtonFormField<TrafficMode>(
                    key: ValueKey(_settings.defaultMode),
                    initialValue: _settings.defaultMode,
                    decoration: const InputDecoration(
                      labelText: 'Default mode',
                    ),
                    items: TrafficMode.values
                        .map(
                          (m) => DropdownMenuItem(
                            value: m,
                            child: Text(m.label),
                          ),
                        )
                        .toList(),
                    onChanged: _saving
                        ? null
                        : (value) {
                            if (value != null) _changeDefaultMode(value);
                          },
                  ),
                ),
                if (!_settings.defaultMode.isImplemented)
                  Padding(
                    padding: const EdgeInsets.fromLTRB(16, 8, 16, 0),
                    child: Text(
                      'Not live yet — falls back to Default until '
                      '${_settings.defaultMode.implementedIn}.',
                      style: Theme.of(context).textTheme.bodySmall,
                    ),
                  ),
                const Divider(),
                const ListTile(
                  title: Text(
                    'Rules',
                    style: TextStyle(fontWeight: FontWeight.w700),
                  ),
                  subtitle: Text(
                    'Most specific match wins: exact IP, then subnet '
                    '(longest prefix), then domain. A rule whose domain '
                    'could not be resolved matches nothing.',
                  ),
                ),
                if (_settings.rules.isEmpty)
                  const ListTile(
                    title: Text('No rules yet'),
                    subtitle: Text(
                      'Add one to send a destination over a different mode.',
                    ),
                  ),
                for (final rule in _settings.rules)
                  ListTile(
                    title: Text(rule.target),
                    subtitle: Text(
                      rule.isUnresolved
                          ? '${rule.mode.label} — could not resolve; '
                                'matches nothing'
                          : rule.kind == TrafficRuleKind.domain
                          ? '${rule.mode.label} — '
                                '${rule.resolvedIps.join(', ')}'
                          : rule.mode.label,
                      style: rule.isUnresolved
                          ? TextStyle(
                              color: Theme.of(context).colorScheme.error,
                            )
                          : null,
                    ),
                    trailing: IconButton(
                      icon: const Icon(Icons.delete),
                      tooltip: 'Delete rule',
                      onPressed: _saving ? null : () => _deleteRule(rule),
                    ),
                    onTap: _saving ? null : () => _editRule(rule),
                  ),
                ListTile(
                  leading: const Icon(Icons.add),
                  title: const Text('Add rule'),
                  onTap: _saving ? null : _addRule,
                ),
              ],
            ),
    );
  }
}
