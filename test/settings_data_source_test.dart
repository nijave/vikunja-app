import 'dart:typed_data';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:vikunja_app/core/network/client_certificate.dart';
import 'package:vikunja_app/data/data_sources/settings_data_source.dart';

/// In-memory stand-in for FlutterSecureStorage. Only read/write/delete are
/// used by SettingsDatasource.
class FakeSecureStorage implements FlutterSecureStorage {
  final Map<String, String> values = {};

  @override
  dynamic noSuchMethod(Invocation invocation) {
    final key = invocation.namedArguments[#key] as String;
    switch (invocation.memberName) {
      case #read:
        return Future<String?>.value(values[key]);
      case #write:
        final value = invocation.namedArguments[#value] as String?;
        if (value == null) {
          values.remove(key);
        } else {
          values[key] = value;
        }
        return Future<void>.value();
      case #delete:
        values.remove(key);
        return Future<void>.value();
    }
    return super.noSuchMethod(invocation);
  }
}

void main() {
  late FakeSecureStorage storage;
  late SettingsDatasource datasource;

  setUp(() {
    storage = FakeSecureStorage();
    datasource = SettingsDatasource(storage);
  });

  group('client certificate persistence', () {
    final pkcs12 = Uint8List.fromList([0x30, 0x82, 0x01, 0x02, 0xff]);
    final caPem = Uint8List.fromList('-----BEGIN CERTIFICATE-----'.codeUnits);

    test('returns null when nothing is stored', () async {
      expect(await datasource.getClientCertificate(), isNull);
    });

    test('round-trips pkcs12, password and CA', () async {
      await datasource.saveClientCertificate(
        ClientCertificate(pkcs12: pkcs12, password: 'pw', caPem: caPem),
      );

      final loaded = await datasource.getClientCertificate();

      expect(loaded, isNotNull);
      expect(loaded!.pkcs12, pkcs12);
      expect(loaded.password, 'pw');
      expect(loaded.caPem, caPem);
    });

    test('round-trips without a CA', () async {
      await datasource.saveClientCertificate(
        ClientCertificate(pkcs12: pkcs12, password: 'pw'),
      );

      final loaded = await datasource.getClientCertificate();

      expect(loaded!.caPem, isNull);
    });

    test('stores bytes as base64, not raw', () async {
      await datasource.saveClientCertificate(
        ClientCertificate(pkcs12: pkcs12, password: 'pw'),
      );

      expect(storage.values['client-cert-pkcs12'], 'MIIBAv8=');
      expect(storage.values['client-cert-password'], 'pw');
    });

    test('returns null when the password entry is missing', () async {
      // Secure storage can lose single entries on backup restore.
      storage.values['client-cert-pkcs12'] = 'MIIBAv8=';

      expect(await datasource.getClientCertificate(), isNull);
    });

    test('clearClientCertificate removes all three keys', () async {
      await datasource.saveClientCertificate(
        ClientCertificate(pkcs12: pkcs12, password: 'pw', caPem: caPem),
      );

      await datasource.clearClientCertificate();

      expect(storage.values.containsKey('client-cert-pkcs12'), isFalse);
      expect(storage.values.containsKey('client-cert-password'), isFalse);
      expect(storage.values.containsKey('client-cert-ca-pem'), isFalse);
      expect(await datasource.getClientCertificate(), isNull);
    });

    test('clearAuthData keeps the certificate', () async {
      await datasource.saveClientCertificate(
        ClientCertificate(pkcs12: pkcs12, password: 'pw'),
      );

      await datasource.clearAuthData();

      expect(await datasource.getClientCertificate(), isNotNull);
    });
  });
}
