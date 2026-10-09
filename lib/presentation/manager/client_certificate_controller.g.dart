// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'client_certificate_controller.dart';

// **************************************************************************
// RiverpodGenerator
// **************************************************************************

String _$clientCertificateControllerHash() =>
    r'cbcd8cdbcd8b0f3a8834562ac0447e4395ed9e1c';

/// Owns the imported client certificate: loads it on build, validates and
/// stores a new one, or removes it. Every change re-installs
/// [HttpOverrides.global] and rebuilds the HTTP client so the transport
/// switch between Cronet and IOClient takes effect immediately.
///
/// Copied from [ClientCertificateController].
@ProviderFor(ClientCertificateController)
final clientCertificateControllerProvider =
    AutoDisposeAsyncNotifierProvider<
      ClientCertificateController,
      ClientCertificateStatus
    >.internal(
      ClientCertificateController.new,
      name: r'clientCertificateControllerProvider',
      debugGetCreateSourceHash: const bool.fromEnvironment('dart.vm.product')
          ? null
          : _$clientCertificateControllerHash,
      dependencies: null,
      allTransitiveDependencies: null,
    );

typedef _$ClientCertificateController =
    AutoDisposeAsyncNotifier<ClientCertificateStatus>;
// ignore_for_file: type=lint
// ignore_for_file: subtype_of_sealed_class, invalid_use_of_internal_member, invalid_use_of_visible_for_testing_member, deprecated_member_use_from_same_package
