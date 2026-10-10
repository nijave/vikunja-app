import 'dart:async';
import 'dart:convert';
import 'dart:developer' as developer;
import 'dart:io';

import 'package:app_links/app_links.dart';
import 'package:http/http.dart' as http;
import 'package:url_launcher/url_launcher.dart';
import 'package:vikunja_app/core/network/client.dart';
import 'package:vikunja_app/core/network/tls_http_overrides.dart';
import 'package:vikunja_app/core/oauth/pkce.dart';

class OAuthTokenResponse {
  final String accessToken;
  final String refreshToken;
  final int expiresIn;

  OAuthTokenResponse({
    required this.accessToken,
    required this.refreshToken,
    required this.expiresIn,
  });

  factory OAuthTokenResponse.fromJson(Map<String, dynamic> json) {
    return OAuthTokenResponse(
      accessToken: json['access_token'] as String,
      refreshToken: json['refresh_token'] as String,
      expiresIn: json['expires_in'] as int,
    );
  }
}

enum OAuthError {
  browserLaunchFailed,
  stateMismatch,
  noAuthorizationCode,
  tokenExchangeFailed,
  cancelled,
}

class OAuthException implements Exception {
  final OAuthError error;
  final String? serverMessage;

  OAuthException(this.error, {this.serverMessage});
}

/// Opens [url] outside the app. Returns false when no handler launched it.
typedef UrlLauncher = Future<bool> Function(Uri url);

/// Runs the authorize leg in an in-app web view. Returns the
/// `vikunja-flutter://callback` URI, or null when the user cancelled.
typedef WebViewAuthorizer = Future<Uri?> Function(Uri authorizeUrl);

class OAuthService {
  static const String _clientId = 'vikunja-flutter';
  static const String _redirectUri = 'vikunja-flutter://callback';
  static const Set<int> _redirectStatuses = {301, 302, 303, 307, 308};

  final UrlLauncher _launcher;
  final WebViewAuthorizer? _webViewAuthorizer;

  OAuthService({UrlLauncher? launcher, WebViewAuthorizer? webViewAuthorizer})
    : _launcher =
          launcher ??
          ((url) => launchUrl(url, mode: LaunchMode.externalApplication)),
      _webViewAuthorizer = webViewAuthorizer;

  String _codeVerifier = '';
  String _state = '';
  StreamSubscription<Uri>? _linkSubscription;
  Completer<Uri>? _callbackCompleter;

  bool get isWaitingForCallback =>
      _callbackCompleter != null && !_callbackCompleter!.isCompleted;

  /// Cancels a pending authorization flow.
  void cancelAuthorize() {
    _linkSubscription?.cancel();
    _linkSubscription = null;
    if (_callbackCompleter != null && !_callbackCompleter!.isCompleted) {
      _callbackCompleter!.completeError(OAuthException(OAuthError.cancelled));
    }
    _callbackCompleter = null;
  }

  /// Runs the OAuth authorization flow and returns the authorization code.
  ///
  /// With an active client certificate and a [client], the app first sends
  /// the authorize request itself and reads a redirect to the app scheme.
  /// When that does not produce a callback, it uses the in-app web view if
  /// one is available, else the system browser and the callback deep link.
  Future<String> authorize(String serverUrl, {Client? client}) async {
    cancelAuthorize();

    _codeVerifier = generateRandomString(128);
    _state = generateRandomString(32);
    final codeChallenge = generateCodeChallenge(_codeVerifier);

    final authorizeUrl = Uri.parse('$serverUrl/oauth/authorize').replace(
      queryParameters: {
        'response_type': 'code',
        'client_id': _clientId,
        'redirect_uri': _redirectUri,
        'code_challenge': codeChallenge,
        'code_challenge_method': 'S256',
        'state': _state,
      },
    );

    final certificateActive = TlsHttpOverrides.clientCertificateActive;

    if (client != null && certificateActive) {
      final callbackUri = await _authorizeInApp(client, authorizeUrl);
      if (callbackUri != null) {
        return _codeFromCallback(callbackUri);
      }
    }

    final webViewAuthorizer = _webViewAuthorizer;
    if (certificateActive && webViewAuthorizer != null) {
      final callbackUri = await webViewAuthorizer(authorizeUrl);
      if (callbackUri == null) {
        throw OAuthException(OAuthError.cancelled);
      }
      return _codeFromCallback(callbackUri);
    }

    return _authorizeInBrowser(authorizeUrl);
  }

  /// Sends the authorize request through [client] without following
  /// redirects. Returns the callback URI when the server redirects to the app
  /// scheme, or null when the caller should fall back to another path.
  Future<Uri?> _authorizeInApp(Client client, Uri authorizeUrl) async {
    final http.StreamedResponse response;
    try {
      response = await client.getUnauthenticatedNoRedirect(authorizeUrl);
    } on Exception catch (e) {
      if (e is http.ClientException ||
          e is TimeoutException ||
          e is SocketException ||
          e is HandshakeException) {
        developer.log('In-app authorize request failed: $e');
        return null;
      }
      rethrow;
    }

    try {
      if (!_redirectStatuses.contains(response.statusCode)) {
        developer.log(
          'In-app authorize got HTTP ${response.statusCode}, not a redirect',
        );
        return null;
      }
      final location = response.headers['location'];
      final callbackUri = location == null ? null : Uri.tryParse(location);
      if (callbackUri == null ||
          callbackUri.scheme != 'vikunja-flutter' ||
          callbackUri.host != 'callback') {
        developer.log(
          'In-app authorize redirect is not the app callback: $location',
        );
        return null;
      }
      return callbackUri;
    } finally {
      try {
        await response.stream.drain<void>();
      } catch (_) {
        // The body is irrelevant; draining only releases the connection.
      }
    }
  }

  /// Opens [authorizeUrl] in the system browser and waits for the callback
  /// deep link.
  Future<String> _authorizeInBrowser(Uri authorizeUrl) async {
    final launched = await _launcher(authorizeUrl);

    if (!launched) {
      throw OAuthException(OAuthError.browserLaunchFailed);
    }

    _callbackCompleter = Completer<Uri>();
    final appLinks = AppLinks();
    _linkSubscription = appLinks.uriLinkStream.listen((uri) {
      if (uri.scheme == 'vikunja-flutter' && uri.host == 'callback') {
        if (!_callbackCompleter!.isCompleted) {
          _callbackCompleter!.complete(uri);
        }
      }
    });

    final callbackUri = await _callbackCompleter!.future.timeout(
      const Duration(minutes: 10),
      onTimeout: () {
        cancelAuthorize();
        throw OAuthException(OAuthError.noAuthorizationCode);
      },
    );

    _linkSubscription?.cancel();
    _linkSubscription = null;
    _callbackCompleter = null;

    return _codeFromCallback(callbackUri);
  }

  /// Checks the `state` of a callback URI and returns its `code`.
  String _codeFromCallback(Uri callbackUri) {
    final returnedState = callbackUri.queryParameters['state'];
    if (returnedState != _state) {
      throw OAuthException(OAuthError.stateMismatch);
    }

    final code = callbackUri.queryParameters['code'];
    if (code == null || code.isEmpty) {
      throw OAuthException(OAuthError.noAuthorizationCode);
    }

    return code;
  }

  /// Exchanges the authorization code for access and refresh tokens.
  Future<OAuthTokenResponse> exchangeCode(Client client, String code) async {
    final response = await client.postUnauthenticated(
      url: '/oauth/token',
      body: {
        'grant_type': 'authorization_code',
        'code': code,
        'client_id': _clientId,
        'redirect_uri': _redirectUri,
        'code_verifier': _codeVerifier,
      },
    );

    if (response.statusCode != 200) {
      final error = jsonDecode(response.body);
      throw OAuthException(
        OAuthError.tokenExchangeFailed,
        serverMessage: error['message'] as String?,
      );
    }

    return OAuthTokenResponse.fromJson(jsonDecode(response.body));
  }
}
