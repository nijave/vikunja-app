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

    await ref
        .read(settingsRepositoryProvider)
        .saveClientCertificate(certificate);
    state = AsyncData(await _apply());
    ref.invalidate(clientProviderProvider);
  }

  Future<void> removeCertificate() async {
    await ref.read(settingsRepositoryProvider).clearClientCertificate();
    state = AsyncData(await _apply());
    ref.invalidate(clientProviderProvider);
  }
}
