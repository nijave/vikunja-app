# Android client-certificate (mTLS) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to work through this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let the Android app authenticate to a Vikunja server behind an mTLS reverse proxy with a user-imported PKCS#12 client certificate, while Cronet stays the default transport.

**Architecture:** A `ClientCertificate` value type and a pure `buildSecurityContext()` function turn stored PKCS#12 bytes into a dart:io `SecurityContext`. A `TlsHttpOverrides` installed in `HttpOverrides.global` carries that context plus the existing ignore-certs flag, so every dart:io `HttpClient` (the `IOClient`, token refresh, `NetworkImage`) presents the certificate. `Client.createClient()` returns an `IOClient` instead of Cronet whenever a certificate is active. Attachment downloads fall back to an in-process download in that case only.

**Tech Stack:** Flutter 3.44.4, Dart 3.9+, `dart:io` `SecurityContext`, `package:http` `IOClient`, `flutter_secure_storage`, `file_picker` 12, Riverpod codegen, `flutter_test`, OpenSSL 3 for fixtures.

**Spec:** `docs/superpowers/specs/2026-10-08-android-client-certificate-mtls-design.md`

## Global Constraints

- Android only. Do not touch `ios/` or add iOS wiring.
- Cronet remains the Android transport when no certificate is active. Do not add `ok_http` or any `labs.dart.dev` package.
- No native Kotlin/Swift code in this iteration.
- Keep `background_downloader` for users without a certificate.
- Logout does not clear the stored certificate.
- New user-facing strings go in `lib/l10n/app_en.arb` only. Other locales fall back automatically.
- Follow existing conventions: Riverpod `@riverpod` codegen with committed `.g.dart` files, `flutter_test` with hand-written fakes (no mockito/mocktail), conventional commit prefixes (`feat:`, `fix:`, `test:`, `chore:`).
- Build environment: export the variables below before every `flutter` command (see `AGENTS.md`):

```bash
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk
export ANDROID_HOME=$HOME/Android/Sdk
export ANDROID_SDK_ROOT=$HOME/Android/Sdk
export PATH="/nix/store/ngaz067k9wbzqc4k0hijrn3s9bmh1g3q-flutter-wrapped-3.44.4-sdk-links/bin:$JAVA_HOME/bin:$ANDROID_HOME/platform-tools:$PATH"
```

## Review Focus

1. A PKCS#12 file that contains a certificate but no private key (Immich issue 17931). Expected: import fails with a clear message, nothing saved. Pinned in Task 2.
2. Secure storage returns the PKCS#12 bytes but not the password after a backup restore. Expected: status `none`, no crash, Cronet transport. Pinned in Task 3.
3. Ignore-certificates toggled after a certificate import. Expected: the `SecurityContext` survives the toggle. Pinned in Task 5.
4. Attachment download under mTLS when the server returns 401. Expected: `TaskStatus.failed` with a `TaskHttpException`, no partial file left behind. Pinned in Task 7.
5. The background WorkManager isolate runs before the user ever opens Settings. Expected: it reads the certificate from storage and presents it. Pinned in Task 6.

---

### Task 1: Test certificate fixtures

**Files:**
- Create: `test/fixtures/generate_certs.sh`
- Create: `test/fixtures/ca.pem`, `test/fixtures/server.p12`, `test/fixtures/client.p12` (generated)
- Create: `test/fixtures/README.md`

**Interfaces:**
- Produces: three fixture files. Password for both `.p12` files is `test1234`. The server certificate has CN `localhost` and SANs `DNS:localhost,IP:127.0.0.1`. The client certificate has CN `vikunja-test-client`. Both PKCS#12 files include the CA in their chain.

- [ ] **Step 1: Write the generator script**

```bash
#!/usr/bin/env bash
# Regenerates the TLS fixtures used by test/client_certificate_test.dart.
# Requires OpenSSL 3. Output files are committed; rerun only when they expire.
set -euo pipefail
cd "$(dirname "$0")"

PASS=test1234
PBE_OPTS=(-keypbe AES-256-CBC -certpbe AES-256-CBC -macalg sha256)

openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem \
  -days 3650 -subj "/CN=Vikunja Test CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"

openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr \
  -subj "/CN=localhost"
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -out server.pem -days 3650 \
  -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth")
openssl pkcs12 -export -in server.pem -inkey server.key -certfile ca.pem \
  -out server.p12 -passout "pass:$PASS" "${PBE_OPTS[@]}"

openssl req -newkey rsa:2048 -nodes -keyout client.key -out client.csr \
  -subj "/CN=vikunja-test-client"
openssl x509 -req -in client.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -out client.pem -days 3650 \
  -extfile <(printf "extendedKeyUsage=clientAuth")
openssl pkcs12 -export -in client.pem -inkey client.key -certfile ca.pem \
  -out client.p12 -passout "pass:$PASS" "${PBE_OPTS[@]}"

# A certificate-only PKCS#12 (no private key) for the negative test.
openssl pkcs12 -export -nokeys -in client.pem -out client-nokey.p12 \
  -passout "pass:$PASS" "${PBE_OPTS[@]}"

rm -f ca.key ca.srl server.key server.csr server.pem client.key client.csr client.pem
```

- [ ] **Step 2: Run it and check the outputs**

Run: `chmod +x test/fixtures/generate_certs.sh && test/fixtures/generate_certs.sh && ls -la test/fixtures`
Expected: `ca.pem`, `server.p12`, `client.p12`, `client-nokey.p12`, and the script. No `.key` files remain.

Run: `openssl pkcs12 -in test/fixtures/client.p12 -passin pass:test1234 -nokeys -clcerts | openssl x509 -noout -subject`
Expected: `subject=CN = vikunja-test-client`

- [ ] **Step 3: Write the README**

```markdown
# TLS test fixtures

Generated by `generate_certs.sh` (OpenSSL 3). Password for every `.p12` is
`test1234`. Test-only material, valid for ten years from generation.

| File | Purpose |
|------|---------|
| `ca.pem` | Test CA that signed both leaf certificates |
| `server.p12` | Server identity for `HttpServer.bindSecure` (CN localhost) |
| `client.p12` | Client identity with private key (CN vikunja-test-client) |
| `client-nokey.p12` | Certificate-only PKCS#12 for the negative import test |
```

- [ ] **Step 4: Commit**

```bash
git add test/fixtures/generate_certs.sh test/fixtures/README.md test/fixtures/ca.pem test/fixtures/server.p12 test/fixtures/client.p12 test/fixtures/client-nokey.p12
git commit -m "test: add PKCS#12 fixtures for client certificate tests"
```

---

### Task 2: `ClientCertificate` and `buildSecurityContext`

**Files:**
- Create: `lib/core/network/client_certificate.dart`
- Test: `test/client_certificate_test.dart`

**Interfaces:**
- Produces:
  - `class ClientCertificate { final Uint8List pkcs12; final String password; final Uint8List? caPem; const ClientCertificate({required this.pkcs12, required this.password, this.caPem}); }`
  - `class ClientCertificateException implements Exception { final String message; }`
  - `SecurityContext buildSecurityContext(ClientCertificate certificate)` — throws `ClientCertificateException` on bad bytes, wrong password, or a PKCS#12 without a private key.

- [ ] **Step 1: Write the failing tests**

```dart
// test/client_certificate_test.dart
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
  });

  group('mTLS round trip against a local HttpServer', () {
    late HttpServer server;

    setUp(() async {
      final serverContext = SecurityContext(withTrustedRoots: false)
        ..useCertificateChainBytes(_fixture('server.p12'), password: _password)
        ..usePrivateKeyBytes(_fixture('server.p12'), password: _password)
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
        final body = await response.transform(const SystemEncoding().decoder).join();
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `flutter test test/client_certificate_test.dart`
Expected: compile error, `client_certificate.dart` does not exist.

- [ ] **Step 3: Write the code**

```dart
// lib/core/network/client_certificate.dart
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
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `flutter test test/client_certificate_test.dart`
Expected: all 7 tests PASS.

If the "no key" test fails because `usePrivateKeyBytes` succeeds on a key-less PKCS#12, keep the test and add an explicit check: after `usePrivateKeyBytes`, open the fixture with `openssl pkcs12 -info` to confirm it has no key, then report the Dart behavior in the PR. Do not delete the test.

- [ ] **Step 5: Commit**

```bash
git add lib/core/network/client_certificate.dart test/client_certificate_test.dart
git commit -m "feat(network): build a SecurityContext from a PKCS#12 client certificate"
```

---

### Task 3: Certificate persistence in `SettingsDatasource` and `SettingsRepository`

**Files:**
- Edit: `lib/data/data_sources/settings_data_source.dart`
- Edit: `lib/domain/repositories/settings_repository.dart`
- Edit: `lib/data/repositories/settings_repository_impl.dart`
- Test: `test/settings_data_source_test.dart`

**Interfaces:**
- Consumes: `ClientCertificate` from Task 2.
- Produces on `SettingsDatasource`, `SettingsRepository`, and `SettingsRepositoryImpl`:
  - `Future<ClientCertificate?> getClientCertificate()`
  - `Future<void> saveClientCertificate(ClientCertificate certificate)`
  - `Future<void> clearClientCertificate()`
- Storage keys: `client-cert-pkcs12` (base64), `client-cert-password`, `client-cert-ca-pem` (base64).

- [ ] **Step 1: Write the failing tests**

```dart
// test/settings_data_source_test.dart
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `flutter test test/settings_data_source_test.dart`
Expected: compile error, `getClientCertificate` undefined.

- [ ] **Step 3: Write the datasource methods**

Add to `lib/data/data_sources/settings_data_source.dart` (imports: `dart:convert` is already there; add `dart:typed_data` and `package:vikunja_app/core/network/client_certificate.dart`):

```dart
  static const _clientCertPkcs12Key = "client-cert-pkcs12";
  static const _clientCertPasswordKey = "client-cert-password";
  static const _clientCertCaPemKey = "client-cert-ca-pem";

  Future<ClientCertificate?> getClientCertificate() async {
    final pkcs12 = await _storage.read(key: _clientCertPkcs12Key);
    final password = await _storage.read(key: _clientCertPasswordKey);
    if (pkcs12 == null || pkcs12.isEmpty || password == null) {
      return null;
    }
    final caPem = await _storage.read(key: _clientCertCaPemKey);
    return ClientCertificate(
      pkcs12: base64Decode(pkcs12),
      password: password,
      caPem: caPem == null || caPem.isEmpty
          ? null
          : Uint8List.fromList(base64Decode(caPem)),
    );
  }

  Future<void> saveClientCertificate(ClientCertificate certificate) async {
    await _storage.write(
      key: _clientCertPkcs12Key,
      value: base64Encode(certificate.pkcs12),
    );
    await _storage.write(
      key: _clientCertPasswordKey,
      value: certificate.password,
    );
    final caPem = certificate.caPem;
    if (caPem != null && caPem.isNotEmpty) {
      await _storage.write(key: _clientCertCaPemKey, value: base64Encode(caPem));
    } else {
      await _storage.delete(key: _clientCertCaPemKey);
    }
  }

  Future<void> clearClientCertificate() async {
    await _storage.delete(key: _clientCertPkcs12Key);
    await _storage.delete(key: _clientCertPasswordKey);
    await _storage.delete(key: _clientCertCaPemKey);
  }
```

`base64Decode` returns `Uint8List`, so the `pkcs12` field needs no wrapping.

- [ ] **Step 4: Add the repository interface and implementation**

In `lib/domain/repositories/settings_repository.dart`, add the import `package:vikunja_app/core/network/client_certificate.dart` and:

```dart
  Future<ClientCertificate?> getClientCertificate();

  Future<void> saveClientCertificate(ClientCertificate certificate);

  Future<void> clearClientCertificate();
```

In `lib/data/repositories/settings_repository_impl.dart`, add the same import and:

```dart
  @override
  Future<ClientCertificate?> getClientCertificate() {
    return _datasource.getClientCertificate();
  }

  @override
  Future<void> saveClientCertificate(ClientCertificate certificate) {
    return _datasource.saveClientCertificate(certificate);
  }

  @override
  Future<void> clearClientCertificate() {
    return _datasource.clearClientCertificate();
  }
```

- [ ] **Step 5: Run the tests and the analyzer**

Run: `flutter test test/settings_data_source_test.dart && flutter analyze`
Expected: 7 tests PASS, analyzer reports no issues. If any test fake elsewhere `implements SettingsRepository` without `noSuchMethod`, the analyzer lists it; add the three methods there as `throw UnimplementedError()`.

- [ ] **Step 6: Commit**

```bash
git add lib/data/data_sources/settings_data_source.dart lib/domain/repositories/settings_repository.dart lib/data/repositories/settings_repository_impl.dart test/settings_data_source_test.dart
git commit -m "feat(settings): persist an imported client certificate in secure storage"
```

---

### Task 4: `TlsHttpOverrides` and `applyStoredTlsSettings`

**Files:**
- Create: `lib/core/network/tls_http_overrides.dart`
- Test: `test/tls_http_overrides_test.dart`

**Interfaces:**
- Consumes: `ClientCertificate`, `buildSecurityContext`, `ClientCertificateException` (Task 2); `SettingsDatasource.getIgnoreCertificates()` / `getClientCertificate()` (Task 3).
- Produces:
  - `enum ClientCertificateStatus { none, active, invalid }`
  - `class TlsHttpOverrides extends HttpOverrides { final bool ignoreCertificates; final SecurityContext? securityContext; final ClientCertificateStatus certificateStatus; TlsHttpOverrides({required this.ignoreCertificates, this.securityContext, this.certificateStatus = ClientCertificateStatus.none}); static TlsHttpOverrides? get current; static bool get clientCertificateActive; }`
  - `ClientCertificateStatus applyTlsSettings({required bool ignoreCertificates, required ClientCertificate? certificate})` — synchronous, installs `HttpOverrides.global`, never throws.
  - `Future<ClientCertificateStatus> applyStoredTlsSettings(SettingsDatasource datasource)` — reads both settings and calls `applyTlsSettings`.

- [ ] **Step 1: Write the failing tests**

```dart
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
      expect(TlsHttpOverrides.current!.certificateStatus,
          ClientCertificateStatus.active);
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

    test('createHttpClient applies ignoreCertificates', () {
      applyTlsSettings(ignoreCertificates: true, certificate: null);

      final client = HttpClient();
      final cert = _FakeX509();
      expect(client.badCertificateCallback!(cert, 'host', 443), isTrue);
      client.close();
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
  });
}

class _FakeX509 extends Fake implements X509Certificate {}
```

`badCertificateCallback` is a plain field on `HttpClient`, so the test can read it back after construction.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `flutter test test/tls_http_overrides_test.dart`
Expected: compile error, `tls_http_overrides.dart` does not exist.

- [ ] **Step 3: Write the code**

```dart
// lib/core/network/tls_http_overrides.dart
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

  static bool get clientCertificateActive =>
      current?.securityContext != null;

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
Future<ClientCertificateStatus> applyStoredTlsSettings(
  SettingsDatasource datasource,
) async {
  final ignore = await datasource.getIgnoreCertificates();
  final certificate = await datasource.getClientCertificate();
  return applyTlsSettings(
    ignoreCertificates: ignore,
    certificate: certificate,
  );
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `flutter test test/tls_http_overrides_test.dart`
Expected: 6 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add lib/core/network/tls_http_overrides.dart test/tls_http_overrides_test.dart
git commit -m "feat(network): add TlsHttpOverrides carrying the client certificate context"
```

---

### Task 5: Switch `Client` to `IOClient` when a certificate is active

**Files:**
- Edit: `lib/core/network/client.dart:32-84` (fields, constructor, `createClient`, `setIgnoreCerts`), `:194-200` (`_createIOClient`), `:321-333` (delete `IgnoreCertHttpOverrides`)
- Test: `test/client_test.dart`

**Interfaces:**
- Consumes: `TlsHttpOverrides`, `applyTlsSettings` (Task 4).
- Produces:
  - `Client.createClient()` returns `io_client.IOClient()` first whenever `TlsHttpOverrides.clientCertificateActive` is true; otherwise unchanged platform branching.
  - `Client()` constructor initialises `ignoreCertificates` from `TlsHttpOverrides.current?.ignoreCertificates ?? false`.
  - `Client.setIgnoreCerts(bool)` preserves `securityContext` and `certificateStatus` of the current overrides.
  - `Future<http.Response> Client.getRaw({required String url})` — authenticated GET of `$apiBase$url`, 60 s timeout, used by the foreground attachment download in Task 7.
  - `IgnoreCertHttpOverrides` removed.

- [ ] **Step 1: Write the failing tests**

Append to `test/client_test.dart` (add imports `package:vikunja_app/core/network/tls_http_overrides.dart` and `package:vikunja_app/core/network/client_certificate.dart`; the file already imports `dart:io`):

```dart
  group('Client TLS configuration', () {
    tearDown(() => HttpOverrides.global = null);

    test('constructor reads ignoreCertificates from current overrides', () {
      applyTlsSettings(ignoreCertificates: true, certificate: null);

      final client = Client(base: _baseUrl);

      expect(client.ignoreCertificates, isTrue);
    });

    test('setIgnoreCerts keeps the security context', () {
      applyTlsSettings(
        ignoreCertificates: false,
        certificate: ClientCertificate(
          pkcs12: File('test/fixtures/client.p12').readAsBytesSync(),
          password: 'test1234',
        ),
      );
      final contextBefore = TlsHttpOverrides.current!.securityContext;
      final client = Client(base: _baseUrl);

      client.setIgnoreCerts(true);

      expect(TlsHttpOverrides.current!.ignoreCertificates, isTrue);
      expect(TlsHttpOverrides.current!.securityContext, same(contextBefore));
      expect(TlsHttpOverrides.current!.certificateStatus,
          ClientCertificateStatus.active);
    });

    test('setIgnoreCerts installs TlsHttpOverrides when none exist', () {
      final client = Client(base: _baseUrl);

      client.setIgnoreCerts(true);

      expect(TlsHttpOverrides.current, isNotNull);
      expect(TlsHttpOverrides.current!.ignoreCertificates, isTrue);
      expect(TlsHttpOverrides.current!.securityContext, isNull);
    });

    test('createClient returns an IOClient when a certificate is active', () {
      applyTlsSettings(
        ignoreCertificates: false,
        certificate: ClientCertificate(
          pkcs12: File('test/fixtures/client.p12').readAsBytesSync(),
          password: 'test1234',
        ),
      );

      final client = Client(base: _baseUrl);

      expect(client.createClient(), isA<io_client.IOClient>());
    });
  });

  group('Client.getRaw', () {
    test('sends the auth header and returns the raw response', () async {
      final settings = MockSettingsDatasource()..token = 'tok';
      final client = _createClient(
        settings,
        http_testing.MockClient((request) async {
          expect(request.url.toString(), '$_baseUrl/api/v1/tasks/1/attachments/2');
          expect(request.headers['Authorization'], 'Bearer tok');
          return http.Response.bytes([1, 2, 3], 200);
        }),
      );

      final response = await client.getRaw(url: '/tasks/1/attachments/2');

      expect(response.statusCode, 200);
      expect(response.bodyBytes, [1, 2, 3]);
    });
  });
```

Add `import 'package:http/io_client.dart' as io_client;` to the test file.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `flutter test test/client_test.dart`
Expected: compile errors for `getRaw` and `applyTlsSettings`, and the IOClient test fails on the host because the constructor does not consult overrides yet.

- [ ] **Step 3: Write the code**

In `lib/core/network/client.dart`:

Replace the import block's `IgnoreCertHttpOverrides` usage. Add:

```dart
import 'package:vikunja_app/core/network/tls_http_overrides.dart';
```

Replace lines 31-32 and the constructor body so the overrides supply `ignoreCertificates`:

```dart
  String _base = '';
  bool ignoreCertificates =
      TlsHttpOverrides.current?.ignoreCertificates ?? false;
```

Replace `createClient()` (lines 55-79):

```dart
  http.Client createClient() {
    // A user-imported client certificate lives in HttpOverrides.global.
    // Cronet cannot present client certificates, so route through dart:io.
    if (TlsHttpOverrides.clientCertificateActive) {
      return io_client.IOClient();
    }

    try {
      if (Platform.isAndroid) {
        final engine = cronet_http.CronetEngine.build(
          cacheMode: cronet_http.CacheMode.memory,
          cacheMaxSize: 1000000,
        );
        return cronet_http.CronetClient.fromCronetEngine(engine);
      } else if (Platform.isIOS || Platform.isMacOS) {
        final config =
            cupertino_http
                  .URLSessionConfiguration.ephemeralSessionConfiguration()
              ..cache = cupertino_http.URLCache.withCapacity(
                memoryCapacity: 1000000,
              );
        return cupertino_http.CupertinoClient.fromSessionConfiguration(config);
      }
    } catch (e) {
      developer.log(
        "Error creating http client: $e. Falling back to default client.",
      );
    }

    return io_client.IOClient();
  }
```

Replace `setIgnoreCerts` (lines 81-84):

```dart
  void setIgnoreCerts(bool val) {
    ignoreCertificates = val;
    final current = TlsHttpOverrides.current;
    HttpOverrides.global = TlsHttpOverrides(
      ignoreCertificates: val,
      securityContext: current?.securityContext,
      certificateStatus:
          current?.certificateStatus ?? ClientCertificateStatus.none,
    );
  }
```

Add `getRaw` after `postUnauthenticated` (line 192):

```dart
  static const Duration _downloadTimeout = Duration(seconds: 60);

  /// Authenticated GET that returns the raw response. Used for attachment
  /// downloads when the certificate-presenting IOClient must be used.
  Future<http.Response> getRaw({required String url}) async {
    return _httpClient
        .get('$apiBase$url'.toUri()!, headers: await getHeaders())
        .timeout(_downloadTimeout);
  }
```

Leave `_createIOClient()` as is. `HttpClient()` inside it already goes through `HttpOverrides.global`, so it presents the certificate.

Delete `class IgnoreCertHttpOverrides` (lines 321-333).

- [ ] **Step 4: Run tests and analyzer**

Run: `flutter test test/client_test.dart && flutter analyze && rg -n IgnoreCertHttpOverrides lib test integration_test`
Expected: all tests PASS, analyzer clean, `rg` finds nothing.

- [ ] **Step 5: Commit**

```bash
git add lib/core/network/client.dart test/client_test.dart
git commit -m "feat(network): use IOClient when a client certificate is active"
```

---

### Task 6: Apply stored TLS settings at every `Client` entry point

**Files:**
- Edit: `lib/presentation/manager/init_controller.dart:33-41`
- Edit: `lib/core/background_work.dart:54-68`
- Edit: `lib/presentation/manager/notifications.dart:33-45`
- Edit: `lib/presentation/manager/widget_controller.dart:18-29`
- Edit: `lib/core/di/data_source_provider.dart` (no change expected: `settingsDataSourceProvider` already exists at line 75)

**Interfaces:**
- Consumes: `applyStoredTlsSettings(SettingsDatasource)` (Task 4).
- Produces: every isolate installs `TlsHttpOverrides` before constructing `Client`, so `createClient()` sees the certificate.

- [ ] **Step 1: App init**

In `lib/presentation/manager/init_controller.dart`, add imports:

```dart
import 'package:vikunja_app/core/di/data_source_provider.dart';
import 'package:vikunja_app/core/network/tls_http_overrides.dart';
```

Change the top of `_runInit` so the overrides exist before `authDataProvider.set` builds the `Client`:

```dart
Future<InitOutcome> _runInit(Ref ref) async {
  final settingsRepo = ref.read(settingsRepositoryProvider);

  // Install ignore-certs and client certificate before the Client is built.
  await applyStoredTlsSettings(ref.read(settingsDataSourceProvider));

  final server = await settingsRepo.getServer();
  if (server == null) {
    return const InitGoLogin();
  }

  ref.read(authDataProvider.notifier).set(AuthModel(server));
```

- [ ] **Step 2: WorkManager task**

In `lib/core/background_work.dart`, add `import 'package:vikunja_app/core/network/tls_http_overrides.dart';` and replace lines 63-67:

```dart
  await applyStoredTlsSettings(datasource);
  Client client = Client(base: base);
  tz.initializeTimeZones();
```

`Client` now seeds `ignoreCertificates` from the overrides, so the explicit `setIgnoreCerts` call goes away.

- [ ] **Step 3: Notification action**

In `lib/presentation/manager/notifications.dart`, add the same import and replace lines 42-45:

```dart
  await applyStoredTlsSettings(datasource);
  Client client = Client(base: base);
```

- [ ] **Step 4: Home widget**

In `lib/presentation/manager/widget_controller.dart`, add the same import and replace lines 23-28 of `_initWidgetClient`:

```dart
  await applyStoredTlsSettings(datasource);
  Client client = Client(base: base);
  tz.initializeTimeZones();
  return client;
```

- [ ] **Step 5: Verify**

Run: `flutter analyze && flutter test && rg -n 'setIgnoreCerts' lib`
Expected: analyzer clean, all tests pass, `setIgnoreCerts` remains only in `client.dart`, `login_page.dart`, and `settings_controller.dart`.

- [ ] **Step 6: Commit**

```bash
git add lib/presentation/manager/init_controller.dart lib/core/background_work.dart lib/presentation/manager/notifications.dart lib/presentation/manager/widget_controller.dart
git commit -m "feat(network): install stored TLS settings before building the client in every isolate"
```

---

### Task 7: Foreground attachment download under mTLS

**Files:**
- Create: `lib/data/data_sources/attachment_downloader.dart`
- Edit: `lib/data/data_sources/task_data_source.dart:90-106`
- Test: `test/attachment_downloader_test.dart`

**Interfaces:**
- Consumes: `Client.getRaw({required String url})` (Task 5), `TlsHttpOverrides.clientCertificateActive` (Task 4), `DownloadTask`, `TaskStatusUpdate`, `TaskStatus`, `TaskHttpException`, `TaskConnectionException` from `background_downloader`.
- Produces: `class ForegroundAttachmentDownloader { ForegroundAttachmentDownloader(Client client, {Future<Directory> Function() directoryProvider = getApplicationSupportDirectory}); Future<TaskStatusUpdate> download(DownloadTask task, String relativeUrl); }`

`background_downloader` 9.x constructors used here: `TaskStatusUpdate(task, status, [exception])`, `TaskHttpException(description, httpResponseCode)`, `TaskConnectionException(description)`. If `flutter analyze` disagrees, open the resolved package under the path listed in `.dart_tool/package_config.json` and match its signature.

- [ ] **Step 1: Write the failing tests**

```dart
// test/attachment_downloader_test.dart
import 'dart:io';

import 'package:background_downloader/background_downloader.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart' as http_testing;
import 'package:vikunja_app/core/network/client.dart';
import 'package:vikunja_app/data/data_sources/attachment_downloader.dart';
import 'package:vikunja_app/data/data_sources/settings_data_source.dart';

const _baseUrl = 'https://vikunja.example.com';

class _Settings implements SettingsDatasource {
  @override
  Future<String?> getUserToken() async => 'tok';

  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

class _TestableClient extends Client {
  final http.Client mock;
  _TestableClient(this.mock) : super(base: _baseUrl);
  @override
  http.Client createClient() => mock;
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  late Directory dir;

  setUp(() async {
    dir = await Directory.systemTemp.createTemp('attachment_test_');
  });

  tearDown(() async {
    if (await dir.exists()) await dir.delete(recursive: true);
  });

  ForegroundAttachmentDownloader downloader(http.Client mock) {
    final client = _TestableClient(mock)..settingsDatasource = _Settings();
    return ForegroundAttachmentDownloader(
      client,
      directoryProvider: () async => dir,
    );
  }

  DownloadTask task() => DownloadTask(
        url: '$_baseUrl/api/v1/tasks/1/attachments/2',
        baseDirectory: BaseDirectory.applicationSupport,
        filename: 'notes.txt',
      );

  test('writes the body to the task filename and reports complete', () async {
    final result = await downloader(
      http_testing.MockClient((request) async {
        expect(request.headers['Authorization'], 'Bearer tok');
        return http.Response.bytes([104, 105], 200);
      }),
    ).download(task(), '/tasks/1/attachments/2');

    expect(result.status, TaskStatus.complete);
    expect(File('${dir.path}/notes.txt').readAsStringSync(), 'hi');
  });

  test('reports failed with TaskHttpException on a 401 and leaves no file',
      () async {
    final result = await downloader(
      http_testing.MockClient((_) async => http.Response('denied', 401)),
    ).download(task(), '/tasks/1/attachments/2');

    expect(result.status, TaskStatus.failed);
    expect(result.exception, isA<TaskHttpException>());
    expect((result.exception as TaskHttpException).httpResponseCode, 401);
    expect(File('${dir.path}/notes.txt').existsSync(), isFalse);
  });

  test('reports failed with TaskConnectionException when the request throws',
      () async {
    final result = await downloader(
      http_testing.MockClient((_) async => throw const SocketException('down')),
    ).download(task(), '/tasks/1/attachments/2');

    expect(result.status, TaskStatus.failed);
    expect(result.exception, isA<TaskConnectionException>());
  });
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `flutter test test/attachment_downloader_test.dart`
Expected: compile error, `attachment_downloader.dart` does not exist.

- [ ] **Step 3: Write the downloader**

```dart
// lib/data/data_sources/attachment_downloader.dart
import 'dart:io';

import 'package:background_downloader/background_downloader.dart';
import 'package:path_provider/path_provider.dart';
import 'package:vikunja_app/core/network/client.dart';

/// Downloads an attachment through the app's own [Client] instead of
/// background_downloader. Used only when a client certificate is active,
/// because background_downloader's native stack cannot present it.
///
/// Writes to the same application-support location background_downloader
/// uses for [BaseDirectory.applicationSupport], so the task page can keep
/// calling FileDownloader().openFile(task: ...) on the returned task.
class ForegroundAttachmentDownloader {
  final Client _client;
  final Future<Directory> Function() _directoryProvider;

  ForegroundAttachmentDownloader(
    this._client, {
    Future<Directory> Function() directoryProvider =
        getApplicationSupportDirectory,
  }) : _directoryProvider = directoryProvider;

  Future<TaskStatusUpdate> download(DownloadTask task, String relativeUrl) async {
    try {
      final response = await _client.getRaw(url: relativeUrl);
      if (response.statusCode < 200 || response.statusCode >= 300) {
        return TaskStatusUpdate(
          task,
          TaskStatus.failed,
          TaskHttpException(
            'Attachment download failed',
            response.statusCode,
          ),
        );
      }

      final directory = await _directoryProvider();
      final file = File('${directory.path}/${task.filename}');
      await file.parent.create(recursive: true);
      await file.writeAsBytes(response.bodyBytes, flush: true);

      return TaskStatusUpdate(task, TaskStatus.complete);
    } catch (e) {
      return TaskStatusUpdate(
        task,
        TaskStatus.failed,
        TaskConnectionException(e.toString()),
      );
    }
  }
}
```

- [ ] **Step 4: Branch in `TaskDataSource.downloadAttachment`**

Replace lines 90-106 of `lib/data/data_sources/task_data_source.dart` and add imports for `attachment_downloader.dart` and `tls_http_overrides.dart`:

```dart
  Future<TaskStatusUpdate> downloadAttachment(
    int taskId,
    TaskAttachmentDto attachment,
  ) async {
    final relativeUrl = '/tasks/$taskId/attachments/${attachment.id}';

    final task = DownloadTask(
      url: '${client.apiBase}$relativeUrl',
      baseDirectory: BaseDirectory.applicationSupport,
      filename: attachment.file.name,
      headers: await client.getHeaders(),
      updates: Updates.statusAndProgress,
    );

    // background_downloader's native stack cannot present a client
    // certificate, so download in-process while one is active.
    if (TlsHttpOverrides.clientCertificateActive) {
      return ForegroundAttachmentDownloader(client).download(task, relativeUrl);
    }

    return await FileDownloader().download(task);
  }
```

- [ ] **Step 5: Run tests and analyzer**

Run: `flutter test test/attachment_downloader_test.dart && flutter analyze`
Expected: 3 tests PASS, analyzer clean.

- [ ] **Step 6: Commit**

```bash
git add lib/data/data_sources/attachment_downloader.dart lib/data/data_sources/task_data_source.dart test/attachment_downloader_test.dart
git commit -m "feat(attachments): download in-process when a client certificate is active"
```

---

### Task 8: `ClientCertificateController`, dependency, and strings

**Files:**
- Edit: `pubspec.yaml:15-44` (add `file_picker: ^12.0.0`)
- Edit: `lib/l10n/app_en.arb`
- Create: `lib/presentation/manager/client_certificate_controller.dart` (+ generated `.g.dart`)
- Test: `test/presentation/manager/client_certificate_controller_test.dart`

**Interfaces:**
- Consumes: `SettingsRepository.getClientCertificate/saveClientCertificate/clearClientCertificate` and `getIgnoreCertificates` (Task 3), `applyTlsSettings`, `ClientCertificateStatus` (Task 4), `buildSecurityContext`, `ClientCertificateException` (Task 2), `clientProviderProvider` (existing).
- Produces:
  - `clientCertificateControllerProvider` with state `AsyncValue<ClientCertificateStatus>`.
  - `Future<void> importCertificate(ClientCertificate certificate)` — validates with `buildSecurityContext`, throws `ClientCertificateException` without saving when invalid, otherwise saves, applies, invalidates the client, and sets state `active`.
  - `Future<void> removeCertificate()` — clears storage, applies, invalidates the client, sets state `none`.
- l10n keys (English): `clientCertificate`, `clientCertificateNone`, `clientCertificateActive`, `clientCertificateInvalid`, `clientCertificateImport`, `clientCertificateRemove`, `clientCertificatePasswordTitle`, `clientCertificatePasswordHint`, `clientCertificateCaOptional`, `clientCertificatePickCa`, `clientCertificateImportFailed`, `clientCertificateImported`, `clientCertificateRemoved`, `clientCertificateMayBeRequired`.

- [ ] **Step 1: Add the dependency and strings**

In `pubspec.yaml` dependencies (alphabetical, after `dynamic_color`):

```yaml
  file_picker: ^12.0.0
```

Run: `flutter pub get`
Expected: resolves without conflicts. If `file_picker` 12 fails to resolve against the current SDK pin, use the newest 10.x instead and record the version in the commit message.

Append to `lib/l10n/app_en.arb` before the closing brace (keep the file valid JSON):

```json
  "clientCertificate": "Client certificate",
  "clientCertificateNone": "No client certificate imported. Import a PKCS#12 (.p12/.pfx) file if your server requires one.",
  "clientCertificateActive": "A client certificate is active. Requests are sent through the certificate-aware client.",
  "clientCertificateInvalid": "The stored certificate failed to load. Import it again.",
  "clientCertificateImport": "Import certificate",
  "clientCertificateRemove": "Remove certificate",
  "clientCertificatePasswordTitle": "Certificate password",
  "clientCertificatePasswordHint": "Password of the PKCS#12 file",
  "clientCertificateCaOptional": "Optional: also trust a private CA certificate (PEM).",
  "clientCertificatePickCa": "Choose CA file",
  "clientCertificateImportFailed": "Could not read the certificate. Check the file and password.",
  "clientCertificateImported": "Client certificate imported",
  "clientCertificateRemoved": "Client certificate removed",
  "clientCertificateMayBeRequired": "The server rejected the connection before login (HTTP {status}). It may require a client certificate. Import one below and try again.",
  "@clientCertificateMayBeRequired": {
    "placeholders": {
      "status": {"type": "int"}
    }
  }
```

Run: `flutter gen-l10n`
Expected: `lib/l10n/gen/app_localizations.dart` gains the getters and `clientCertificateMayBeRequired(int status)`.

- [ ] **Step 2: Write the failing controller test**

```dart
// test/presentation/manager/client_certificate_controller_test.dart
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:vikunja_app/core/di/network_provider.dart';
import 'package:vikunja_app/core/di/repository_provider.dart';
import 'package:vikunja_app/core/network/client.dart';
import 'package:vikunja_app/core/network/client_certificate.dart';
import 'package:vikunja_app/core/network/tls_http_overrides.dart';
import 'package:vikunja_app/domain/repositories/settings_repository.dart';
import 'package:vikunja_app/presentation/manager/client_certificate_controller.dart';

class _FakeSettingsRepository implements SettingsRepository {
  ClientCertificate? stored;
  bool ignore = false;

  @override
  Future<ClientCertificate?> getClientCertificate() async => stored;

  @override
  Future<void> saveClientCertificate(ClientCertificate certificate) async {
    stored = certificate;
  }

  @override
  Future<void> clearClientCertificate() async => stored = null;

  @override
  Future<bool> getIgnoreCertificates() async => ignore;

  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

Uint8List _fixture(String name) =>
    File('test/fixtures/$name').readAsBytesSync();

void main() {
  late _FakeSettingsRepository repo;
  late int clientBuilds;

  setUp(() {
    repo = _FakeSettingsRepository();
    clientBuilds = 0;
    HttpOverrides.global = null;
  });

  tearDown(() => HttpOverrides.global = null);

  ProviderContainer container() {
    final c = ProviderContainer(
      overrides: [
        settingsRepositoryProvider.overrideWithValue(repo),
        clientProviderProvider.overrideWith(() => _CountingClientProvider(() {
              clientBuilds++;
            })),
      ],
    );
    addTearDown(c.dispose);
    return c;
  }

  test('build reports none when nothing is stored', () async {
    final c = container();

    final status = await c.read(clientCertificateControllerProvider.future);

    expect(status, ClientCertificateStatus.none);
  });

  test('build reports active for a stored valid certificate', () async {
    repo.stored = ClientCertificate(
      pkcs12: _fixture('client.p12'),
      password: 'test1234',
    );
    final c = container();

    final status = await c.read(clientCertificateControllerProvider.future);

    expect(status, ClientCertificateStatus.active);
    expect(TlsHttpOverrides.clientCertificateActive, isTrue);
  });

  test('importCertificate saves, applies and rebuilds the client', () async {
    final c = container();
    await c.read(clientCertificateControllerProvider.future);
    c.read(clientProviderProvider);
    final buildsBefore = clientBuilds;

    await c.read(clientCertificateControllerProvider.notifier).importCertificate(
          ClientCertificate(pkcs12: _fixture('client.p12'), password: 'test1234'),
        );

    expect(repo.stored, isNotNull);
    expect(c.read(clientCertificateControllerProvider).value,
        ClientCertificateStatus.active);
    expect(TlsHttpOverrides.clientCertificateActive, isTrue);
    c.read(clientProviderProvider);
    expect(clientBuilds, greaterThan(buildsBefore));
  });

  test('importCertificate rejects a wrong password and saves nothing', () async {
    final c = container();
    await c.read(clientCertificateControllerProvider.future);

    await expectLater(
      c.read(clientCertificateControllerProvider.notifier).importCertificate(
            ClientCertificate(pkcs12: _fixture('client.p12'), password: 'bad'),
          ),
      throwsA(isA<ClientCertificateException>()),
    );

    expect(repo.stored, isNull);
    expect(c.read(clientCertificateControllerProvider).value,
        ClientCertificateStatus.none);
  });

  test('removeCertificate clears storage and context', () async {
    repo.stored = ClientCertificate(
      pkcs12: _fixture('client.p12'),
      password: 'test1234',
    );
    final c = container();
    await c.read(clientCertificateControllerProvider.future);

    await c.read(clientCertificateControllerProvider.notifier).removeCertificate();

    expect(repo.stored, isNull);
    expect(TlsHttpOverrides.clientCertificateActive, isFalse);
    expect(c.read(clientCertificateControllerProvider).value,
        ClientCertificateStatus.none);
  });
}

class _CountingClientProvider extends ClientProvider {
  final void Function() onBuild;
  _CountingClientProvider(this.onBuild);

  @override
  Client build() {
    onBuild();
    return Client(base: 'https://vikunja.example.com');
  }
}
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `flutter test test/presentation/manager/client_certificate_controller_test.dart`
Expected: compile error, controller file missing.

- [ ] **Step 4: Write the controller**

```dart
// lib/presentation/manager/client_certificate_controller.dart
import 'package:riverpod_annotation/riverpod_annotation.dart';
import 'package:vikunja_app/core/di/network_provider.dart';
import 'package:vikunja_app/core/di/repository_provider.dart';
import 'package:vikunja_app/core/network/client_certificate.dart';
import 'package:vikunja_app/core/network/tls_http_overrides.dart';

part 'client_certificate_controller.g.dart';

/// Owns the imported client certificate: loads it on build, validates and
/// stores a new one, or removes it. Every change re-installs
/// [HttpOverrides.global] and rebuilds the HTTP client so the transport
/// switch between Cronet and IOClient takes effect immediately.
@riverpod
class ClientCertificateController extends _$ClientCertificateController {
  @override
  Future<ClientCertificateStatus> build() async {
    return _apply();
  }

  Future<ClientCertificateStatus> _apply() async {
    final repo = ref.read(settingsRepositoryProvider);
    return applyTlsSettings(
      ignoreCertificates: await repo.getIgnoreCertificates(),
      certificate: await repo.getClientCertificate(),
    );
  }

  /// Validates [certificate] by building a SecurityContext, then persists it.
  /// Throws [ClientCertificateException] and leaves storage untouched when
  /// the bytes or password are wrong.
  Future<void> importCertificate(ClientCertificate certificate) async {
    buildSecurityContext(certificate); // throws on invalid input

    await ref.read(settingsRepositoryProvider).saveClientCertificate(certificate);
    state = AsyncData(await _apply());
    ref.invalidate(clientProviderProvider);
  }

  Future<void> removeCertificate() async {
    await ref.read(settingsRepositoryProvider).clearClientCertificate();
    state = AsyncData(await _apply());
    ref.invalidate(clientProviderProvider);
  }
}
```

Run: `dart run build_runner build --delete-conflicting-outputs`
Expected: `lib/presentation/manager/client_certificate_controller.g.dart` generated.

- [ ] **Step 5: Run the tests**

Run: `flutter test test/presentation/manager/client_certificate_controller_test.dart && flutter analyze`
Expected: 5 tests PASS, analyzer clean.

- [ ] **Step 6: Commit**

```bash
git add pubspec.yaml pubspec.lock lib/l10n/app_en.arb lib/presentation/manager/client_certificate_controller.dart lib/presentation/manager/client_certificate_controller.g.dart test/presentation/manager/client_certificate_controller_test.dart
git commit -m "feat(settings): add client certificate controller, strings and file_picker"
```

If `flutter gen-l10n` wrote `lib/l10n/untranslated_messages.json`, add it to the commit as well; the project tracks that file.

---

### Task 9: Certificate section widget, Settings page, and login page

**Files:**
- Create: `lib/presentation/widgets/client_certificate_section.dart`
- Edit: `lib/presentation/pages/settings_page.dart:124-133`
- Edit: `lib/presentation/pages/login/login_page.dart:222-289` (custom URL view) and `:467-473` (info failure)
- Test: `test/presentation/widgets/client_certificate_section_test.dart`

**Interfaces:**
- Consumes: `clientCertificateControllerProvider`, `importCertificate`, `removeCertificate` (Task 8), `ClientCertificateStatus` (Task 4), l10n keys (Task 8), `FilePicker.platform.pickFiles` from `file_picker`.
- Produces: `class ClientCertificateSection extends ConsumerWidget { const ClientCertificateSection({super.key, this.compact = false}); }` — `compact` renders a single-line status plus buttons for the login page.

- [ ] **Step 1: Write the failing widget test**

```dart
// test/presentation/widgets/client_certificate_section_test.dart
import 'package:flutter/material.dart';
import 'package:flutter_localizations/flutter_localizations.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:vikunja_app/core/network/tls_http_overrides.dart';
import 'package:vikunja_app/l10n/gen/app_localizations.dart';
import 'package:vikunja_app/presentation/manager/client_certificate_controller.dart';
import 'package:vikunja_app/presentation/widgets/client_certificate_section.dart';

class _FixedStatus extends ClientCertificateController {
  final ClientCertificateStatus status;
  _FixedStatus(this.status);

  @override
  Future<ClientCertificateStatus> build() async => status;
}

Widget _wrap(ClientCertificateStatus status) {
  return ProviderScope(
    overrides: [
      clientCertificateControllerProvider.overrideWith(() => _FixedStatus(status)),
    ],
    child: const MaterialApp(
      localizationsDelegates: [
        AppLocalizations.delegate,
        GlobalMaterialLocalizations.delegate,
        GlobalWidgetsLocalizations.delegate,
      ],
      supportedLocales: [Locale('en')],
      home: Scaffold(body: ClientCertificateSection()),
    ),
  );
}

void main() {
  testWidgets('shows import only when no certificate is stored', (tester) async {
    await tester.pumpWidget(_wrap(ClientCertificateStatus.none));
    await tester.pumpAndSettle();

    expect(find.text('Import certificate'), findsOneWidget);
    final remove = tester.widget<OutlinedButton>(
      find.widgetWithText(OutlinedButton, 'Remove certificate'),
    );
    expect(remove.onPressed, isNull);
    expect(find.textContaining('No client certificate imported'), findsOneWidget);
  });

  testWidgets('enables remove when a certificate is active', (tester) async {
    await tester.pumpWidget(_wrap(ClientCertificateStatus.active));
    await tester.pumpAndSettle();

    final remove = tester.widget<OutlinedButton>(
      find.widgetWithText(OutlinedButton, 'Remove certificate'),
    );
    expect(remove.onPressed, isNotNull);
    expect(find.textContaining('is active'), findsOneWidget);
  });

  testWidgets('explains an invalid stored certificate', (tester) async {
    await tester.pumpWidget(_wrap(ClientCertificateStatus.invalid));
    await tester.pumpAndSettle();

    expect(find.textContaining('failed to load'), findsOneWidget);
    expect(find.text('Import certificate'), findsOneWidget);
  });
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `flutter test test/presentation/widgets/client_certificate_section_test.dart`
Expected: compile error, widget file missing.

- [ ] **Step 3: Write the widget**

```dart
// lib/presentation/widgets/client_certificate_section.dart
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
    final status = ref.watch(clientCertificateControllerProvider).value ??
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
        children: [
          Text(statusText),
          const SizedBox(height: 8),
          buttons,
        ],
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
          onPressed: () => Navigator.of(context).pop(
            _PasswordInput(_controller.text, _caPem),
          ),
          child: Text(l10n.save),
        ),
      ],
    );
  }
}
```

- [ ] **Step 4: Run the widget tests**

Run: `flutter test test/presentation/widgets/client_certificate_section_test.dart`
Expected: 3 tests PASS.

- [ ] **Step 5: Add the section to the Settings page**

In `lib/presentation/pages/settings_page.dart`, import `package:vikunja_app/presentation/widgets/client_certificate_section.dart` and insert directly after the ignore-certificates `CheckboxListTile` (after line 132, before the `Divider()` on line 133):

```dart
              const ClientCertificateSection(),
```

- [ ] **Step 6: Add the compact section and the 401/403 hint to the login page**

In `lib/presentation/pages/login/login_page.dart`, import `package:vikunja_app/presentation/widgets/client_certificate_section.dart` and `package:vikunja_app/core/network/tls_http_overrides.dart`.

In `_buildCustomUrlView()`, after the final `TextButton` cancel block (after line 285) and before the closing `],` of the `Column`, add:

```dart
          const SizedBox(height: 24),
          const ClientCertificateSection(compact: true),
```

In `_connectAndLogin`, replace lines 467-473 so an auth-level rejection of the unauthenticated `/info` probe names the likely cause:

```dart
      if (!info.isSuccessful) {
        final statusCode = info.isError ? info.toError().statusCode : null;
        final certHint = (statusCode == 401 || statusCode == 403) &&
            !TlsHttpOverrides.clientCertificateActive;
        setState(() {
          _serverError = certHint
              ? AppLocalizations.of(context)
                  .clientCertificateMayBeRequired(statusCode!)
              : AppLocalizations.of(context).cannotReachServer;
        });
        _formKey.currentState?.validate();
        return;
      }
```

`Response.isError` and `toError().statusCode` already exist in `lib/core/network/response.dart`; confirm the getter names there before compiling.

- [ ] **Step 7: Full verification**

Run: `flutter analyze && flutter test`
Expected: analyzer clean, every test passes.

Run: `flutter build apk --debug`
Expected: `BUILD SUCCESSFUL`, APK at `build/app/outputs/flutter-apk/app-debug.apk`. Ignore the pre-existing Kotlin Gradle Plugin warnings.

- [ ] **Step 8: Commit**

```bash
git add lib/presentation/widgets/client_certificate_section.dart lib/presentation/pages/settings_page.dart lib/presentation/pages/login/login_page.dart test/presentation/widgets/client_certificate_section_test.dart
git commit -m "feat(settings): import and remove a client certificate from Settings and login"
```

---

### Task 10: Device verification and PR description

**Files:**
- Create: `docs/superpowers/plans/2026-10-08-android-client-certificate-mtls-verification.md` (manual test record)

**Interfaces:**
- Consumes: the debug APK from Task 9; the Pixel 7 over wireless ADB; a PKCS#12 export of the client certificate accepted by `vikunja.apps.somemissing.info`.

- [ ] **Step 1: Install on the Pixel 7**

```bash
PORT=$(avahi-browse -rpt _adb-tls-connect._tcp 2>/dev/null \
  | awk -F';' '/IPv4/ && /172.16.0.5/ {print $9}' | sort -u | tail -1)
DEV=172.16.0.5:$PORT
adb connect "$DEV"
adb -s "$DEV" install -r build/app/outputs/flutter-apk/app-debug.apk
```

Expected: `Success`.

- [ ] **Step 2: Walk the scenarios and record each result**

Copy the client `.p12` to the phone's Downloads folder first (`adb -s "$DEV" push <file> /sdcard/Download/`). Then record pass/fail for each row in the verification file:

| # | Scenario | Expected |
|---|----------|----------|
| 1 | Fresh install, custom URL `https://vikunja.apps.somemissing.info`, Login without a certificate | Error text mentions a client certificate and the HTTP status |
| 2 | Import the `.p12` with the correct password from the login page | Snackbar "Client certificate imported"; status line says active |
| 3 | Login again | OAuth flow completes, home page loads |
| 4 | Settings page | Section shows active; Remove enabled |
| 5 | Open a task with an attachment, tap download | File opens; `adb logcat` shows no `background_downloader` activity for that request |
| 6 | Avatar in Settings header | Renders (NetworkImage presented the certificate) |
| 7 | Set background refresh to 15 min, wait for the WorkManager run, check `adb logcat -s flutter` | `update-tasks` runs without a 401/403 |
| 8 | Toggle Ignore Certificates on and off | Requests keep working; no re-import needed |
| 9 | Remove certificate, pull to refresh | Requests fail with 401/403 as expected |
| 10 | Import with a wrong password | Snackbar "Could not read the certificate"; nothing stored |
| 11 | Login with `https://try.vikunja.io` with no certificate | Still uses Cronet; works unchanged |

- [ ] **Step 3: Commit the record**

```bash
git add docs/superpowers/plans/2026-10-08-android-client-certificate-mtls-verification.md
git commit -m "docs: record device verification for client certificate support"
```

- [ ] **Step 4: Draft the PR description**

Use the `atomic-git` skill when opening the PR. The body must cover, in this order: the Cronet limitation (quote the `cronet_url_request.cc` comment), why this replaces #301, the transport switch, the attachment fallback and why background downloads stay for everyone else, the private-CA import, what iOS needs later (the same Dart code plus a `cupertino_http` bypass, untested here), and a link to the verification record. Title: `feat(android): client certificate (mTLS) support via imported PKCS#12`. Reference `Closes #147` and `Supersedes #301`.
