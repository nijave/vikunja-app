import 'dart:convert';
import 'dart:core';
import 'dart:io';

import 'package:cupertino_http/cupertino_http.dart' as cupertino_http;
import 'package:flutter/foundation.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:http/http.dart' as http;
import 'package:http/io_client.dart' as io_client;
import 'package:logging/logging.dart';
import 'package:ok_http/ok_http.dart' as ok_http;
import 'package:sentry_flutter/sentry_flutter.dart';
import 'package:vikunja_app/core/network/keychain_alias.dart' as keychain;
import 'package:vikunja_app/core/network/response.dart';
import 'package:vikunja_app/core/network/token_lock.dart';
import 'package:vikunja_app/core/utils/constants.dart';
import 'package:vikunja_app/data/data_sources/settings_data_source.dart';
import 'package:vikunja_app/main.dart';
import 'package:vikunja_app/presentation/widgets/string_extension.dart';

/// Reports an error on both the device log and Sentry before recovering.
void reportSwallowedError(String message, Object error, StackTrace stackTrace) {
  debugPrint('$message: $error\n$stackTrace');
  Sentry.captureException(error, stackTrace: stackTrace);
}

/// Builds an [ok_http.OkHttpClientConfiguration] for the given client
/// certificate Keystore [alias]. Returns a plain (no client-cert)
/// configuration when [alias] is null, or when [loadFromAlias] throws (e.g.
/// the alias no longer resolves to a Keystore entry) — reporting the failure
/// rather than taking down all networking over a stale setting.
///
/// [loadFromAlias] defaults to
/// [keychain.loadPrivateKeyAndCertificateChain] and is only overridden in
/// tests, since the real implementation requires a live Android Keystore.
Future<ok_http.OkHttpClientConfiguration> buildOkHttpConfiguration(
  String? alias, {
  bool validateServerCertificates = true,
  Future<(ok_http.PrivateKey, List<ok_http.X509Certificate>)> Function(
        String alias,
      )
      loadFromAlias =
      keychain.loadPrivateKeyAndCertificateChain,
}) async {
  if (alias == null) {
    return ok_http.OkHttpClientConfiguration(
      validateServerCertificates: validateServerCertificates,
    );
  }

  try {
    final (privateKey, chain) = await loadFromAlias(alias);
    return ok_http.OkHttpClientConfiguration(
      clientPrivateKey: privateKey,
      clientCertificateChain: chain,
      validateServerCertificates: validateServerCertificates,
    );
  } catch (e, s) {
    reportSwallowedError(
      "Failed to load client certificate for alias '$alias'. "
      "Connecting without one; TLS client authentication will fail.",
      e,
      s,
    );
    return ok_http.OkHttpClientConfiguration(
      validateServerCertificates: validateServerCertificates,
    );
  }
}

class Client {
  final log = Logger('Client logger');

  // If the server is reachable but does not respond (e.g. container paused),
  // Platform transports can hang for a long time. Enforce a sane client-side
  // timeout so the UI can surface an error and allow recovery.
  static const Duration _requestTimeout = Duration(seconds: 10);

  final JsonDecoder _decoder = JsonDecoder();
  final JsonEncoder _encoder = JsonEncoder();

  String _base = '';
  bool ignoreCertificates = false;
  String? _clientCertAlias;

  SettingsDatasource settingsDatasource = SettingsDatasource(
    FlutterSecureStorage(),
  );

  late http.Client _httpClient;

  String get apiBase => '$_base/api/v1';

  Client({required String base}) {
    base = base.replaceAll(" ", "");
    if (base.endsWith("/")) {
      base = base.substring(0, base.length - 1);
    }
    if (base.endsWith('/api/v1')) {
      base = base.substring(0, base.length - '/api/v1'.length);
    }
    _base = base;

    _httpClient = createClient();
  }

  /// Builds the initial client. Any configured client certificate is applied
  /// afterwards via [setClientCertificateAlias], which has to be async because
  /// reading the Keystore cannot happen on the platform thread — so this
  /// starts out without one.
  http.Client createClient() {
    try {
      if (Platform.isAndroid) {
        return ok_http.OkHttpClient();
      } else if (Platform.isIOS || Platform.isMacOS) {
        final config =
            cupertino_http
                  .URLSessionConfiguration.ephemeralSessionConfiguration()
              ..cache = cupertino_http.URLCache.withCapacity(
                memoryCapacity: 1000000,
              );
        return cupertino_http.CupertinoClient.fromSessionConfiguration(config);
      }
    } catch (e, s) {
      reportSwallowedError(
        'Error creating the platform http client. '
        'Falling back to the default client.',
        e,
        s,
      );
    }

    return io_client.IOClient();
  }

  Future<void> setSecurityConfiguration({
    required bool ignoreCertificates,
    required String? clientCertificateAlias,
  }) async {
    this.ignoreCertificates = ignoreCertificates;
    _clientCertAlias = clientCertificateAlias;
    HttpOverrides.global = IgnoreCertHttpOverrides(ignoreCertificates);

    if (!Platform.isAndroid) return;

    final replacement = ok_http.OkHttpClient(
      configuration: await buildOkHttpConfiguration(
        clientCertificateAlias,
        validateServerCertificates: !ignoreCertificates,
      ),
    );
    _httpClient = replacement;
  }

  Future<void> setIgnoreCerts(bool val) {
    return setSecurityConfiguration(
      ignoreCertificates: val,
      clientCertificateAlias: _clientCertAlias,
    );
  }

  /// Reconfigures the Android HTTP client to present the certificate stored
  /// under [alias] in the Android Keystore for TLS client authentication, or
  /// to stop presenting one if [alias] is null. No-op on non-Android
  /// platforms, which have no client-certificate code path.
  Future<void> setClientCertificateAlias(String? alias) async {
    await setSecurityConfiguration(
      ignoreCertificates: ignoreCertificates,
      clientCertificateAlias: alias,
    );
  }

  /// `ok_http.close()` can perform a blocking TLS write on Android's main
  /// thread. Idle OkHttp resources self-release, so Android relies on that
  /// lifecycle while other transports close explicitly.
  void close() {
    if (Platform.isAndroid) return;
    _httpClient.close();
  }

  Future<Map<String, String>> getHeaders() async {
    var headers = {'Content-Type': 'application/json', 'User-Agent': userAgent};

    var token = await settingsDatasource.getUserToken();
    if (token != null && token.isNotEmpty) {
      headers['Authorization'] = 'Bearer $token';
    }

    return headers;
  }

  Future<Response<T>> get<T>({
    required String url,
    T Function(dynamic body)? mapper,
    Map<String, List<String>>? queryParameters,
  }) async {
    try {
      Uri uri = Uri.tryParse('$apiBase$url')!;

      uri = Uri(
        scheme: uri.scheme,
        userInfo: uri.userInfo,
        query: uri.query,
        host: uri.host,
        port: uri.port,
        path: uri.path,
        queryParameters: queryParameters,
        fragment: uri.fragment,
      );

      return _handleResponseWithRefresh(mapper, () async {
        return _httpClient.get(uri, headers: await getHeaders());
      });
    } catch (e, s) {
      return _handleException(e, s);
    }
  }

  Future<Response<T>> delete<T>({
    required String url,
    T Function(dynamic body)? mapper,
  }) async {
    try {
      return await _handleResponseWithRefresh(mapper, () async {
        return _httpClient.delete(
          '$apiBase$url'.toUri()!,
          headers: await getHeaders(),
        );
      });
    } catch (e, s) {
      return _handleException(e, s);
    }
  }

  Future<Response<T>> post<T>({
    required String url,
    T Function(dynamic body)? mapper,
    dynamic body,
  }) async {
    try {
      var encodedBody = _encoder.convert(body);
      return await _handleResponseWithRefresh(mapper, () async {
        return _httpClient.post(
          '$apiBase$url'.toUri()!,
          headers: await getHeaders(),
          body: encodedBody,
        );
      });
    } catch (e, s) {
      return _handleException(e, s);
    }
  }

  Future<Response<T>> put<T>({
    required String url,
    T Function(dynamic body)? mapper,
    dynamic body,
  }) async {
    try {
      var encodedBody = _encoder.convert(body);
      return await _handleResponseWithRefresh(mapper, () async {
        return _httpClient.put(
          '$apiBase$url'.toUri()!,
          headers: await getHeaders(),
          body: encodedBody,
        );
      });
    } catch (e, s) {
      return _handleException(e, s);
    }
  }

  Future<http.Response> postUnauthenticated({
    required String url,
    dynamic body,
  }) async {
    return _httpClient
        .post(
          '$apiBase$url'.toUri()!,
          headers: {
            'Content-Type': 'application/json',
            'User-Agent': userAgent,
          },
          body: _encoder.convert(body),
        )
        .timeout(_requestTimeout);
  }

  Future<Response<T>> _handleResponse<T>(
    http.Response response,
    T Function(dynamic body)? mapper,
  ) async {
    if (response.statusCode < 200 || response.statusCode >= 400) {
      try {
        Map<String, dynamic> error = _decoder.convert(response.body);

        if (response.statusCode == 401 &&
            globalNavigatorKey.currentContext != null) {
          globalNavigatorKey.currentState?.pushNamed("/login");
        }

        return ErrorResponse<T>(response.statusCode, await getHeaders(), error);
      } on FormatException catch (e, s) {
        return ExceptionResponse(e, s);
      }
    }

    var decode = utf8.decode(response.bodyBytes);

    if (mapper != null) {
      //Empty lists can be returned as "null" from the backend
      if (decode.trim() == "null") {
        return SuccessResponse<T>(
          mapper.call([]),
          response.statusCode,
          response.headers,
        );
      }

      var convert = _decoder.convert(decode);
      return SuccessResponse<T>(
        mapper.call(convert),
        response.statusCode,
        response.headers,
      );
    }

    return VoidResponse<T>();
  }

  Future<bool> tryRefreshToken() async {
    try {
      return await TokenLock.synchronized(() async {
        var refreshToken = await settingsDatasource.getRefreshToken();
        if (refreshToken == null || refreshToken.isEmpty) {
          return false;
        }

        // Refresh on the configured transport. On Android this is the
        // OkHttpClient carrying the selected client certificate; creating an
        // IOClient here bypassed mTLS and made every expired session fail.
        var response = await _httpClient
            .post(
              '$apiBase/oauth/token'.toUri()!,
              headers: {
                'Content-Type': 'application/json',
                'User-Agent': userAgent,
              },
              body: _encoder.convert({
                'grant_type': 'refresh_token',
                'refresh_token': refreshToken,
              }),
            )
            .timeout(_requestTimeout);

        if (response.statusCode >= 200 && response.statusCode < 400) {
          var body = _decoder.convert(utf8.decode(response.bodyBytes));
          var newAccessToken = body['access_token'] as String?;
          var newRefreshToken = body['refresh_token'] as String?;

          if (newAccessToken != null && newAccessToken.isNotEmpty) {
            await settingsDatasource.saveUserToken(newAccessToken);
            if (newRefreshToken != null && newRefreshToken.isNotEmpty) {
              await settingsDatasource.saveRefreshToken(newRefreshToken);
            }
            return true;
          }
        }

        return false;
      });
    } catch (e, s) {
      reportSwallowedError('Error refreshing token', e, s);
      return false;
    }
  }

  Future<Response<T>> _handleResponseWithRefresh<T>(
    T Function(dynamic body)? mapper,
    Future<http.Response> Function() executeRequest,
  ) async {
    var response = await executeRequest().timeout(_requestTimeout);

    if (response.statusCode == 401) {
      Map<String, dynamic> error = _decoder.convert(response.body);
      if (error.containsKey('code') && error['code'] == 11) {
        bool refreshed = await tryRefreshToken();
        if (refreshed) {
          var retryResponse = await executeRequest().timeout(_requestTimeout);
          return _handleResponse(retryResponse, mapper);
        }
      }
    }

    return _handleResponse(response, mapper);
  }

  ExceptionResponse<T> _handleException<T>(Object e, StackTrace s) {
    if (e is! FormatException && e is! http.ClientException) {
      Sentry.captureException(e, stackTrace: s);
    }
    return ExceptionResponse<T>(e, s);
  }
}

class IgnoreCertHttpOverrides extends HttpOverrides {
  bool ignoreCerts = false;

  IgnoreCertHttpOverrides(bool ignore) {
    ignoreCerts = ignore;
  }

  @override
  HttpClient createHttpClient(SecurityContext? context) {
    return super.createHttpClient(context)
      ..badCertificateCallback = (_, _, _) => ignoreCerts;
  }
}
