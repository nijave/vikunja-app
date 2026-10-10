import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:vikunja_app/core/network/client_certificate.dart';

const _password = 'test1234';

Uint8List _fixture(String name) =>
    File('test/fixtures/$name').readAsBytesSync();

void main() {
  group('buildSecurityContext', () {
    test('accepts a PKCS#12 with the correct password', () {
      final context = buildSecurityContext(
        ClientCertificate(pkcs12: _fixture('client.p12'), password: _password),
      );
      expect(context, isA<SecurityContext>());
    });

    test('throws ClientCertificateException on a wrong password', () {
      expect(
        () => buildSecurityContext(
          ClientCertificate(pkcs12: _fixture('client.p12'), password: 'nope'),
        ),
        throwsA(isA<ClientCertificateException>()),
      );
    });

    test('throws ClientCertificateException on garbage bytes', () {
      expect(
        () => buildSecurityContext(
          ClientCertificate(
            pkcs12: Uint8List.fromList([1, 2, 3, 4]),
            password: _password,
          ),
        ),
        throwsA(isA<ClientCertificateException>()),
      );
    });

    test('throws ClientCertificateException when the PKCS#12 has no key', () {
      expect(
        () => buildSecurityContext(
          ClientCertificate(
            pkcs12: _fixture('client-nokey.p12'),
            password: _password,
          ),
        ),
        throwsA(isA<ClientCertificateException>()),
      );
    });

    test('rejects an unparsable CA PEM', () {
      expect(
        () => buildSecurityContext(
          ClientCertificate(
            pkcs12: _fixture('client.p12'),
            password: _password,
            caPem: Uint8List.fromList('not a pem'.codeUnits),
          ),
        ),
        throwsA(isA<ClientCertificateException>()),
      );
    });

    test('accepts a PKCS#12 with a trailing newline', () {
      final context = buildSecurityContext(
        ClientCertificate(
          pkcs12: Uint8List.fromList([..._fixture('client.p12'), 0x0a]),
          password: _password,
        ),
      );
      expect(context, isA<SecurityContext>());
    });

    test('accepts a PKCS#12 with several trailing bytes', () {
      final context = buildSecurityContext(
        ClientCertificate(
          pkcs12: Uint8List.fromList([
            ..._fixture('client.p12'),
            0x0d,
            0x0a,
            0x00,
          ]),
          password: _password,
        ),
      );
      expect(context, isA<SecurityContext>());
    });

    test('still rejects a truncated PKCS#12', () {
      final bytes = _fixture('client.p12');
      expect(
        () => buildSecurityContext(
          ClientCertificate(
            pkcs12: Uint8List.sublistView(bytes, 0, bytes.length - 16),
            password: _password,
          ),
        ),
        throwsA(isA<ClientCertificateException>()),
      );
    });
  });

  group('mTLS round trip against a local HttpServer', () {
    late HttpServer server;

    setUp(() async {
      final serverContext = SecurityContext(withTrustedRoots: false)
        ..useCertificateChainBytes(_fixture('server.p12'), password: _password)
        ..usePrivateKeyBytes(_fixture('server.p12'), password: _password)
        ..setTrustedCertificatesBytes(_fixture('ca.pem'))
        ..setClientAuthoritiesBytes(_fixture('ca.pem'));

      server = await HttpServer.bindSecure(
        InternetAddress.loopbackIPv4,
        0,
        serverContext,
        requestClientCertificate: true,
      );
      server.listen((request) {
        final cert = request.certificate;
        request.response
          ..statusCode = cert == null ? HttpStatus.forbidden : HttpStatus.ok
          ..write(cert?.subject ?? '')
          ..close();
      });
    });

    tearDown(() => server.close(force: true));

    Future<(int, String)> fetch(SecurityContext context) async {
      final client = HttpClient(context: context);
      try {
        final request = await client.getUrl(
          Uri.parse('https://localhost:${server.port}/'),
        );
        final response = await request.close();
        final body = await response
            .transform(const SystemEncoding().decoder)
            .join();
        return (response.statusCode, body);
      } finally {
        client.close(force: true);
      }
    }

    test('client presents the certificate from buildSecurityContext', () async {
      final context = buildSecurityContext(
        ClientCertificate(
          pkcs12: _fixture('client.p12'),
          password: _password,
          caPem: _fixture('ca.pem'),
        ),
      );

      final (status, body) = await fetch(context);

      expect(status, HttpStatus.ok);
      expect(body, contains('vikunja-test-client'));
    });

    test('a context without a client certificate gets 403', () async {
      final context = SecurityContext(withTrustedRoots: false)
        ..setTrustedCertificatesBytes(_fixture('ca.pem'));

      final (status, _) = await fetch(context);

      expect(status, HttpStatus.forbidden);
    });
  });
}
