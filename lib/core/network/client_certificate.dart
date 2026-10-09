import 'dart:io';
import 'dart:typed_data';

/// A user-imported TLS client identity (PKCS#12 bytes plus password) and an
/// optional private CA certificate in PEM form.
class ClientCertificate {
  final Uint8List pkcs12;
  final String password;
  final Uint8List? caPem;

  const ClientCertificate({
    required this.pkcs12,
    required this.password,
    this.caPem,
  });
}

class ClientCertificateException implements Exception {
  final String message;

  const ClientCertificateException(this.message);

  @override
  String toString() => 'ClientCertificateException: $message';
}

/// Builds a [SecurityContext] that presents [certificate] during the TLS
/// handshake and, when [ClientCertificate.caPem] is set, trusts that CA in
/// addition to the platform roots.
///
/// Throws [ClientCertificateException] when the PKCS#12 bytes do not parse,
/// the password is wrong, the file holds no private key, or the CA PEM does
/// not parse. Never leaves a half-configured context behind.
SecurityContext buildSecurityContext(ClientCertificate certificate) {
  final context = SecurityContext(withTrustedRoots: true);
  try {
    context.useCertificateChainBytes(
      certificate.pkcs12,
      password: certificate.password,
    );
    context.usePrivateKeyBytes(
      certificate.pkcs12,
      password: certificate.password,
    );
    final caPem = certificate.caPem;
    if (caPem != null && caPem.isNotEmpty) {
      context.setTrustedCertificatesBytes(caPem);
    }
  } on TlsException catch (e) {
    throw ClientCertificateException(e.message);
  } on ArgumentError catch (e) {
    throw ClientCertificateException(e.message.toString());
  }
  return context;
}
