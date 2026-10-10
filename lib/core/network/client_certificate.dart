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
  final pkcs12 = _trimTrailingBytes(certificate.pkcs12);
  try {
    context.useCertificateChainBytes(pkcs12, password: certificate.password);
    context.usePrivateKeyBytes(pkcs12, password: certificate.password);
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

/// Returns [der] cut to the length that its outer DER SEQUENCE declares.
///
/// Dart's BoringSSL requires that nothing follows the PKCS#12 PFX structure
/// and rejects the file otherwise, while OpenSSL ignores trailing bytes. Files
/// that pass through e-mail, chat, or text-mode transfers often pick up a
/// trailing newline, so such files open with `openssl pkcs12` but fail here.
///
/// When the header is not a SEQUENCE, or the input is shorter than the
/// declared length, [der] is returned unchanged so that BoringSSL reports the
/// real error.
Uint8List _trimTrailingBytes(Uint8List der) {
  if (der.length < 2 || der[0] != 0x30) return der;
  final first = der[1];
  int headerLength;
  int contentLength;
  if (first < 0x80) {
    headerLength = 2;
    contentLength = first;
  } else {
    final lengthBytes = first & 0x7f;
    // 0x80 is the indefinite form, which DER forbids. Cap the byte count so
    // the length fits in a Dart int on every platform.
    if (lengthBytes == 0 || lengthBytes > 4) return der;
    headerLength = 2 + lengthBytes;
    if (der.length < headerLength) return der;
    contentLength = 0;
    for (var i = 2; i < headerLength; i++) {
      contentLength = (contentLength << 8) | der[i];
    }
  }
  final total = headerLength + contentLength;
  if (der.length <= total) return der;
  return Uint8List.sublistView(der, 0, total);
}
