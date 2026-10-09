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
        clientProviderProvider.overrideWith(
          () => _CountingClientProvider(() {
            clientBuilds++;
          }),
        ),
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

    await c
        .read(clientCertificateControllerProvider.notifier)
        .importCertificate(
          ClientCertificate(
            pkcs12: _fixture('client.p12'),
            password: 'test1234',
          ),
        );

    expect(repo.stored, isNotNull);
    expect(
      c.read(clientCertificateControllerProvider).value,
      ClientCertificateStatus.active,
    );
    expect(TlsHttpOverrides.clientCertificateActive, isTrue);
    c.read(clientProviderProvider);
    expect(clientBuilds, greaterThan(buildsBefore));
  });

  test(
    'importCertificate rejects a wrong password and saves nothing',
    () async {
      final c = container();
      await c.read(clientCertificateControllerProvider.future);

      await expectLater(
        c
            .read(clientCertificateControllerProvider.notifier)
            .importCertificate(
              ClientCertificate(
                pkcs12: _fixture('client.p12'),
                password: 'bad',
              ),
            ),
        throwsA(isA<ClientCertificateException>()),
      );

      expect(repo.stored, isNull);
      expect(
        c.read(clientCertificateControllerProvider).value,
        ClientCertificateStatus.none,
      );
    },
  );

  test('removeCertificate clears storage and context', () async {
    repo.stored = ClientCertificate(
      pkcs12: _fixture('client.p12'),
      password: 'test1234',
    );
    final c = container();
    await c.read(clientCertificateControllerProvider.future);

    await c
        .read(clientCertificateControllerProvider.notifier)
        .removeCertificate();

    expect(repo.stored, isNull);
    expect(TlsHttpOverrides.clientCertificateActive, isFalse);
    expect(
      c.read(clientCertificateControllerProvider).value,
      ClientCertificateStatus.none,
    );
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
