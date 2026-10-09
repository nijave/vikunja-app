// test/tls_http_overrides_test.dart
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:vikunja_app/core/network/client_certificate.dart';
import 'package:vikunja_app/core/network/tls_http_overrides.dart';
import 'package:vikunja_app/data/data_sources/settings_data_source.dart';

Uint8List _fixture(String name) =>
    File('test/fixtures/$name').readAsBytesSync();

class _FakeSettings implements SettingsDatasource {
  bool ignore = false;
  ClientCertificate? certificate;

  @override
  Future<bool> getIgnoreCertificates() async => ignore;

  @override
  Future<ClientCertificate?> getClientCertificate() async => certificate;

  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

class _CorruptSettings extends _FakeSettings {
  @override
  Future<ClientCertificate?> getClientCertificate() async =>
      throw const FormatException('bad base64');
}

void main() {
  tearDown(() => HttpOverrides.global = null);

  group('applyTlsSettings', () {
    test('installs overrides with no context when there is no certificate', () {
      final status = applyTlsSettings(
        ignoreCertificates: false,
        certificate: null,
      );

      expect(status, ClientCertificateStatus.none);
      expect(TlsHttpOverrides.current, isNotNull);
      expect(TlsHttpOverrides.current!.securityContext, isNull);
      expect(TlsHttpOverrides.clientCertificateActive, isFalse);
    });

    test('installs a context for a valid certificate', () {
      final status = applyTlsSettings(
        ignoreCertificates: false,
        certificate: ClientCertificate(
          pkcs12: _fixture('client.p12'),
          password: 'test1234',
        ),
      );

      expect(status, ClientCertificateStatus.active);
      expect(TlsHttpOverrides.clientCertificateActive, isTrue);
      expect(
        TlsHttpOverrides.current!.certificateStatus,
        ClientCertificateStatus.active,
      );
    });

    test('reports invalid and keeps no context for a bad certificate', () {
      final status = applyTlsSettings(
        ignoreCertificates: true,
        certificate: ClientCertificate(
          pkcs12: Uint8List.fromList([1, 2, 3]),
          password: 'x',
        ),
      );

      expect(status, ClientCertificateStatus.invalid);
      expect(TlsHttpOverrides.clientCertificateActive, isFalse);
      expect(TlsHttpOverrides.current!.ignoreCertificates, isTrue);
    });

    test('createHttpClient applies ignoreCertificates', () async {
      // The server certificate is signed by the untrusted test CA, so the
      // handshake only succeeds when the override accepts bad certificates.
      final serverContext = SecurityContext()
        ..useCertificateChainBytes(_fixture('server.p12'), password: 'test1234')
        ..usePrivateKeyBytes(_fixture('server.p12'), password: 'test1234');
      final server = await HttpServer.bindSecure(
        InternetAddress.loopbackIPv4,
        0,
        serverContext,
      );
      server.listen((request) => request.response.close());
      final url = Uri.parse('https://localhost:${server.port}/');

      try {
        applyTlsSettings(ignoreCertificates: false, certificate: null);
        final strict = HttpClient();
        await expectLater(
          strict.getUrl(url).then((r) => r.close()),
          throwsA(isA<HandshakeException>()),
        );
        strict.close(force: true);

        applyTlsSettings(ignoreCertificates: true, certificate: null);
        final lenient = HttpClient();
        final response = await (await lenient.getUrl(url)).close();
        expect(response.statusCode, 200);
        await response.drain<void>();
        lenient.close(force: true);
      } finally {
        await server.close(force: true);
      }
    });
  });

  group('applyStoredTlsSettings', () {
    test('reads ignore flag and certificate from the datasource', () async {
      final settings = _FakeSettings()
        ..ignore = true
        ..certificate = ClientCertificate(
          pkcs12: _fixture('client.p12'),
          password: 'test1234',
        );

      final status = await applyStoredTlsSettings(settings);

      expect(status, ClientCertificateStatus.active);
      expect(TlsHttpOverrides.current!.ignoreCertificates, isTrue);
      expect(TlsHttpOverrides.clientCertificateActive, isTrue);
    });

    test('returns none when storage has no certificate', () async {
      final status = await applyStoredTlsSettings(_FakeSettings());

      expect(status, ClientCertificateStatus.none);
    });

    test('reports invalid when stored certificate is corrupt base64', () async {
      final status = await applyStoredTlsSettings(_CorruptSettings());

      expect(status, ClientCertificateStatus.invalid);
      expect(TlsHttpOverrides.current, isNotNull);
      expect(TlsHttpOverrides.clientCertificateActive, isFalse);
    });
  });
}
