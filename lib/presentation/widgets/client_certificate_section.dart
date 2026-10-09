import 'dart:typed_data';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:vikunja_app/core/network/client_certificate.dart';
import 'package:vikunja_app/core/network/tls_http_overrides.dart';
import 'package:vikunja_app/l10n/gen/app_localizations.dart';
import 'package:vikunja_app/presentation/manager/client_certificate_controller.dart';

/// Status line plus Import / Remove buttons for the mTLS client certificate.
/// Used on the Settings page and, in [compact] form, on the login page.
class ClientCertificateSection extends ConsumerWidget {
  final bool compact;

  const ClientCertificateSection({super.key, this.compact = false});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final l10n = AppLocalizations.of(context);
    final status =
        ref.watch(clientCertificateControllerProvider).value ??
        ClientCertificateStatus.none;

    final statusText = switch (status) {
      ClientCertificateStatus.none => l10n.clientCertificateNone,
      ClientCertificateStatus.active => l10n.clientCertificateActive,
      ClientCertificateStatus.invalid => l10n.clientCertificateInvalid,
    };

    final buttons = Row(
      children: [
        FilledButton.tonal(
          onPressed: () => _import(context, ref),
          child: Text(l10n.clientCertificateImport),
        ),
        const SizedBox(width: 8),
        OutlinedButton(
          onPressed: status == ClientCertificateStatus.none
              ? null
              : () => _remove(context, ref),
          child: Text(l10n.clientCertificateRemove),
        ),
      ],
    );

    if (compact) {
      return Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Text(statusText, style: Theme.of(context).textTheme.bodySmall),
          const SizedBox(height: 8),
          buttons,
        ],
      );
    }

    return ListTile(
      title: Text(l10n.clientCertificate),
      subtitle: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [Text(statusText), const SizedBox(height: 8), buttons],
      ),
      isThreeLine: true,
    );
  }

  Future<void> _import(BuildContext context, WidgetRef ref) async {
    final l10n = AppLocalizations.of(context);
    final messenger = ScaffoldMessenger.of(context);

    // FileType.any: Android's mime filter hides .p12/.pfx files otherwise.
    final picked = await FilePicker.platform.pickFiles(
      type: FileType.any,
      withData: true,
    );
    final pkcs12 = picked?.files.single.bytes;
    if (pkcs12 == null || !context.mounted) return;

    final input = await showDialog<_PasswordInput>(
      context: context,
      builder: (_) => const _PasswordDialog(),
    );
    if (input == null) return;

    try {
      await ref
          .read(clientCertificateControllerProvider.notifier)
          .importCertificate(
            ClientCertificate(
              pkcs12: pkcs12,
              password: input.password,
              caPem: input.caPem,
            ),
          );
      messenger.showSnackBar(
        SnackBar(content: Text(l10n.clientCertificateImported)),
      );
    } on ClientCertificateException {
      messenger.showSnackBar(
        SnackBar(content: Text(l10n.clientCertificateImportFailed)),
      );
    }
  }

  Future<void> _remove(BuildContext context, WidgetRef ref) async {
    final l10n = AppLocalizations.of(context);
    final messenger = ScaffoldMessenger.of(context);
    await ref
        .read(clientCertificateControllerProvider.notifier)
        .removeCertificate();
    messenger.showSnackBar(
      SnackBar(content: Text(l10n.clientCertificateRemoved)),
    );
  }
}

class _PasswordInput {
  final String password;
  final Uint8List? caPem;
  const _PasswordInput(this.password, this.caPem);
}

class _PasswordDialog extends StatefulWidget {
  const _PasswordDialog();

  @override
  State<_PasswordDialog> createState() => _PasswordDialogState();
}

class _PasswordDialogState extends State<_PasswordDialog> {
  final _controller = TextEditingController();
  Uint8List? _caPem;
  String? _caName;

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  Future<void> _pickCa() async {
    final picked = await FilePicker.platform.pickFiles(
      type: FileType.any,
      withData: true,
    );
    final file = picked?.files.single;
    if (file?.bytes == null) return;
    setState(() {
      _caPem = file!.bytes;
      _caName = file.name;
    });
  }

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context);
    return AlertDialog(
      title: Text(l10n.clientCertificatePasswordTitle),
      content: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          TextField(
            controller: _controller,
            obscureText: true,
            autofocus: true,
            decoration: InputDecoration(
              hintText: l10n.clientCertificatePasswordHint,
            ),
          ),
          const SizedBox(height: 16),
          Text(
            l10n.clientCertificateCaOptional,
            style: Theme.of(context).textTheme.bodySmall,
          ),
          TextButton.icon(
            onPressed: _pickCa,
            icon: const Icon(Icons.attach_file),
            label: Text(_caName ?? l10n.clientCertificatePickCa),
          ),
        ],
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.of(context).pop(),
          child: Text(l10n.cancel),
        ),
        FilledButton(
          onPressed: () => Navigator.of(
            context,
          ).pop(_PasswordInput(_controller.text, _caPem)),
          child: Text(l10n.save),
        ),
      ],
    );
  }
}
