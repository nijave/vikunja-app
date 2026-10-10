import 'dart:convert';
import 'dart:core';
import 'dart:developer' as developer;
import 'dart:io';

import 'package:cronet_http/cronet_http.dart' as cronet_http;
import 'package:cupertino_http/cupertino_http.dart' as cupertino_http;
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:http/http.dart' as http;
import 'package:http/io_client.dart' as io_client;
import 'package:logging/logging.dart';
import 'package:sentry_flutter/sentry_flutter.dart';
import 'package:vikunja_app/core/network/response.dart';
import 'package:vikunja_app/core/network/tls_http_overrides.dart';
import 'package:vikunja_app/core/network/token_lock.dart';
import 'package:vikunja_app/core/utils/constants.dart';
import 'package:vikunja_app/data/data_sources/settings_data_source.dart';
import 'package:vikunja_app/main.dart';
import 'package:vikunja_app/presentation/widgets/string_extension.dart';

class Client {
  final log = Logger('Client logger');

  // If the server is reachable but does not respond (e.g. container paused),
  // Cronet/URLSession can hang for a long time. Enforce a sane client-side
  // timeout so the UI can surface an error and allow recovery.
  static const Duration _requestTimeout = Duration(seconds: 10);

  final JsonDecoder _decoder = JsonDecoder();
  final JsonEncoder _encoder = JsonEncoder();

  String _base = '';
  bool ignoreCertificates =
      TlsHttpOverrides.current?.ignoreCertificates ?? false;

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

      return await _handleResponseWithRefresh(mapper, () async {
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

  /// Unauthenticated GET that does not follow redirects, so callers can read
  /// a `Location` header. Used by the OAuth authorize leg under mTLS.
  Future<http.StreamedResponse> getUnauthenticatedNoRedirect(Uri uri) {
    final request = http.Request('GET', uri)
      ..followRedirects = false
      ..headers['User-Agent'] = userAgent;
    return _httpClient.send(request).timeout(_requestTimeout);
  }

  static const Duration _downloadTimeout = Duration(seconds: 60);

  /// Authenticated GET that returns the raw response. Used for attachment
  /// downloads when the certificate-presenting IOClient must be used.
  Future<http.Response> getRaw({required String url}) async {
    return _httpClient
        .get('$apiBase$url'.toUri()!, headers: await getHeaders())
        .timeout(_downloadTimeout);
  }

  io_client.IOClient _createIOClient() {
    final httpClient = HttpClient();
    if (ignoreCertificates) {
      httpClient.badCertificateCallback = (_, _, _) => true;
    }
    return io_client.IOClient(httpClient);
  }

  Future<Response<T>> _handleResponse<T>(
    http.Response response,
    T Function(dynamic body)? mapper,
  ) async {
    if (response.statusCode < 200 || response.statusCode >= 400) {
      final error = _decodeErrorBody(response.body);
      if (error == null) {
        // A proxy (for example an mTLS gate) can answer with a plain-text or
        // empty body. Keep the status code so callers can still react to it.
        return ErrorResponse<T>(response.statusCode, await getHeaders(), {
          'message': response.body,
        });
      }

      if (response.statusCode == 401 &&
          globalNavigatorKey.currentContext != null) {
        globalNavigatorKey.currentState?.pushNamed("/login");
      }

      return ErrorResponse<T>(response.statusCode, await getHeaders(), error);
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
        final refreshClient = _createIOClient();
        try {
          var refreshToken = await settingsDatasource.getRefreshToken();
          if (refreshToken == null || refreshToken.isEmpty) {
            return false;
          }

          var response = await refreshClient
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
        } finally {
          refreshClient.close();
        }

        return false;
      });
    } catch (e) {
      developer.log("Error refreshing token: $e");
      return false;
    }
  }

  Future<Response<T>> _handleResponseWithRefresh<T>(
    T Function(dynamic body)? mapper,
    Future<http.Response> Function() executeRequest,
  ) async {
    var response = await executeRequest().timeout(_requestTimeout);

    if (response.statusCode == 401) {
      final error = _decodeErrorBody(response.body);
      if (error != null && error['code'] == 11) {
        bool refreshed = await tryRefreshToken();
        if (refreshed) {
          var retryResponse = await executeRequest().timeout(_requestTimeout);
          return _handleResponse(retryResponse, mapper);
        }
      }
    }

    return _handleResponse(response, mapper);
  }

  /// Decodes a JSON object error body. Returns null when the body is not a
  /// JSON object, for example a plain-text deny from a proxy.
  Map<String, dynamic>? _decodeErrorBody(String body) {
    try {
      final decoded = _decoder.convert(body);
      return decoded is Map<String, dynamic> ? decoded : null;
    } on FormatException {
      return null;
    }
  }

  ExceptionResponse<T> _handleException<T>(Object e, StackTrace s) {
    if (e is! FormatException && e is! http.ClientException) {
      Sentry.captureException(e, stackTrace: s);
    }
    return ExceptionResponse<T>(e, s);
  }
}
