import 'dart:developer' as developer;
import 'dart:io';

import 'package:vikunja_app/core/network/client_certificate.dart';
import 'package:vikunja_app/data/data_sources/settings_data_source.dart';

enum ClientCertificateStatus {
  /// No certificate stored.
  none,

  /// A certificate is stored and loaded into the current SecurityContext.
  active,

  /// A certificate is stored but failed to load (bad bytes or password).
  invalid,
}

/// Process-wide TLS configuration for every dart:io [HttpClient] created
/// without an explicit [SecurityContext]: the IOClient transport, the
/// token-refresh client and NetworkImage all pick this up.
class TlsHttpOverrides extends HttpOverrides {
  final bool ignoreCertificates;
  final SecurityContext? securityContext;
  final ClientCertificateStatus certificateStatus;

  TlsHttpOverrides({
    required this.ignoreCertificates,
    this.securityContext,
    this.certificateStatus = ClientCertificateStatus.none,
  });

  static TlsHttpOverrides? get current {
    final overrides = HttpOverrides.current;
    return overrides is TlsHttpOverrides ? overrides : null;
  }

  static bool get clientCertificateActive => current?.securityContext != null;

  @override
  HttpClient createHttpClient(SecurityContext? context) {
    return super.createHttpClient(securityContext ?? context)
      ..badCertificateCallback = (_, _, _) => ignoreCertificates;
  }
}

/// Installs [HttpOverrides.global] from the given settings. Never throws: an
/// unloadable certificate is logged and reported as
/// [ClientCertificateStatus.invalid].
ClientCertificateStatus applyTlsSettings({
  required bool ignoreCertificates,
  required ClientCertificate? certificate,
}) {
  SecurityContext? context;
  var status = ClientCertificateStatus.none;

  if (certificate != null) {
    try {
      context = buildSecurityContext(certificate);
      status = ClientCertificateStatus.active;
    } on ClientCertificateException catch (e) {
      developer.log('Stored client certificate failed to load: ${e.message}');
      status = ClientCertificateStatus.invalid;
    }
  }

  HttpOverrides.global = TlsHttpOverrides(
    ignoreCertificates: ignoreCertificates,
    securityContext: context,
    certificateStatus: status,
  );
  return status;
}

/// Reads the ignore-certificates flag and the stored client certificate and
/// installs them. Call this before constructing a [Client] in every isolate.
/// Never throws: corrupt stored certificate data is logged and reported as
/// [ClientCertificateStatus.invalid].
Future<ClientCertificateStatus> applyStoredTlsSettings(
  SettingsDatasource datasource,
) async {
  final ignore = await datasource.getIgnoreCertificates();
  final ClientCertificate? certificate;
  try {
    certificate = await datasource.getClientCertificate();
  } on FormatException catch (e) {
    developer.log('Stored client certificate is corrupt: ${e.message}');
    HttpOverrides.global = TlsHttpOverrides(
      ignoreCertificates: ignore,
      certificateStatus: ClientCertificateStatus.invalid,
    );
    return ClientCertificateStatus.invalid;
  }
  return applyTlsSettings(ignoreCertificates: ignore, certificate: certificate);
}
