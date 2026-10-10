import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_inappwebview/flutter_inappwebview.dart';
import 'package:path_provider/path_provider.dart';
import 'package:vikunja_app/core/network/client_certificate.dart';
import 'package:vikunja_app/l10n/gen/app_localizations.dart';

const String _certificateFileName = 'oauth-client-cert.p12';

/// True when [uri] is the OAuth redirect `vikunja-flutter://callback`.
bool isCallbackUri(Uri? uri) =>
    uri != null && uri.scheme == 'vikunja-flutter' && uri.host == 'callback';

/// The answer to a server-trust challenge: accept any server certificate
/// only when the user turned on Ignore Certificates.
ServerTrustAuthResponseAction serverTrustAction({
  required bool ignoreCertificates,
}) => ignoreCertificates
    ? ServerTrustAuthResponseAction.PROCEED
    : ServerTrustAuthResponseAction.CANCEL;

/// Runs the OAuth authorize leg in an in-app web view that presents
/// [certificate] when the server asks for a client certificate.
///
/// Pops with the `vikunja-flutter://callback` URI, or with null when the
/// user closes the page.
class OAuthWebViewPage extends StatefulWidget {
  final Uri authorizeUrl;
  final ClientCertificate certificate;
  final bool ignoreCertificates;

  const OAuthWebViewPage({
    super.key,
    required this.authorizeUrl,
    required this.certificate,
    required this.ignoreCertificates,
  });

  @override
  State<OAuthWebViewPage> createState() => _OAuthWebViewPageState();
}

class _OAuthWebViewPageState extends State<OAuthWebViewPage> {
  late final Future<String> _certificatePath = _writeCertificate();
  bool _popped = false;

  Future<String> _writeCertificate() async {
    final dir = await getApplicationSupportDirectory();
    final file = File('${dir.path}/$_certificateFileName');
    await file.writeAsBytes(widget.certificate.pkcs12, flush: true);
    return file.path;
  }

  @override
  void initState() {
    super.initState();
    // Start the write now so the file exists before the first challenge.
    _certificatePath.ignore();
  }

  @override
  void dispose() {
    _deleteCertificate();
    super.dispose();
  }

  Future<void> _deleteCertificate() async {
    try {
      await File(await _certificatePath).delete();
    } catch (_) {
      // Best effort: the file is app-private and overwritten on next login.
    }
  }

  void _finish(Uri? result) {
    if (_popped || !mounted) return;
    _popped = true;
    Navigator.of(context).pop(result);
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        leading: IconButton(
          icon: const Icon(Icons.close),
          tooltip: MaterialLocalizations.of(context).closeButtonTooltip,
          onPressed: () => _finish(null),
        ),
        title: Text(AppLocalizations.of(context).oauthWebViewTitle),
      ),
      body: InAppWebView(
        initialUrlRequest: URLRequest(url: WebUri.uri(widget.authorizeUrl)),
        initialSettings: InAppWebViewSettings(
          useShouldOverrideUrlLoading: true,
        ),
        onReceivedClientCertRequest: (controller, challenge) async {
          final path = await _certificatePath;
          return ClientCertResponse(
            certificatePath: path,
            certificatePassword: widget.certificate.password,
            keyStoreType: 'PKCS12',
            action: ClientCertResponseAction.PROCEED,
          );
        },
        onReceivedServerTrustAuthRequest: (controller, challenge) async {
          return ServerTrustAuthResponse(
            action: serverTrustAction(
              ignoreCertificates: widget.ignoreCertificates,
            ),
          );
        },
        shouldOverrideUrlLoading: (controller, navigationAction) async {
          final uri = navigationAction.request.url;
          if (isCallbackUri(uri)) {
            _finish(Uri.parse(uri.toString()));
            return NavigationActionPolicy.CANCEL;
          }
          return NavigationActionPolicy.ALLOW;
        },
      ),
    );
  }
}
