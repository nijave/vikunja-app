import 'dart:async';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart' as http_testing;
import 'package:vikunja_app/core/network/client.dart';
import 'package:vikunja_app/core/network/client_certificate.dart';
import 'package:vikunja_app/core/network/tls_http_overrides.dart';
import 'package:vikunja_app/core/oauth/oauth_service.dart';
import 'package:vikunja_app/data/data_sources/settings_data_source.dart';

const _baseUrl = 'https://vikunja.example.com';

class MockSettingsDatasource implements SettingsDatasource {
  @override
  Future<String?> getUserToken() async => null;

  @override
  noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

/// A Client subclass that accepts a mock http.Client.
class TestableClient extends Client {
  final http.Client mockHttpClient;

  TestableClient({required super.base, required this.mockHttpClient});

  @override
  http.Client createClient() => mockHttpClient;
}

TestableClient _createClient(http.Client mockHttp) {
  final client = TestableClient(base: _baseUrl, mockHttpClient: mockHttp);
  client.settingsDatasource = MockSettingsDatasource();
  return client;
}

void _activateCertificate() {
  applyTlsSettings(
    ignoreCertificates: false,
    certificate: ClientCertificate(
      pkcs12: File('test/fixtures/client.p12').readAsBytesSync(),
      password: 'test1234',
    ),
  );
}

final _isCancelled = throwsA(
  isA<OAuthException>().having((e) => e.error, 'error', OAuthError.cancelled),
);

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  setUp(_activateCertificate);

  tearDown(() {
    HttpOverrides.global = null;
  });

  /// A launcher fake that records the URL and cancels the pending flow once
  /// `authorize` has started waiting for the deep link.
  ({List<Uri> calls, UrlLauncher launcher}) cancellingLauncher(
    OAuthService Function() service,
  ) {
    final calls = <Uri>[];
    Future<bool> launcher(Uri url) async {
      calls.add(url);
      Timer.run(() => service().cancelAuthorize());
      return true;
    }

    return (calls: calls, launcher: launcher);
  }

  test(
    'returns the code from a 302 to the app scheme without opening a browser',
    () async {
      final launched = <Uri>[];
      final mock = http_testing.MockClient((request) async {
        expect(request.url.path, '/oauth/authorize');
        expect(request.url.queryParameters['client_id'], 'vikunja-flutter');
        expect(request.url.queryParameters['code_challenge_method'], 'S256');
        final state = request.url.queryParameters['state'];
        return http.Response(
          '',
          302,
          headers: {
            'location': 'vikunja-flutter://callback?code=abc123&state=$state',
          },
        );
      });
      final service = OAuthService(
        launcher: (url) async {
          launched.add(url);
          return true;
        },
      );

      final code = await service.authorize(
        _baseUrl,
        client: _createClient(mock),
      );

      expect(code, 'abc123');
      expect(launched, isEmpty);
    },
  );

  test(
    'throws stateMismatch when the redirect carries another state',
    () async {
      final launched = <Uri>[];
      final mock = http_testing.MockClient((request) async {
        return http.Response(
          '',
          302,
          headers: {
            'location': 'vikunja-flutter://callback?code=abc&state=wrong',
          },
        );
      });
      final service = OAuthService(
        launcher: (url) async {
          launched.add(url);
          return true;
        },
      );

      await expectLater(
        service.authorize(_baseUrl, client: _createClient(mock)),
        throwsA(
          isA<OAuthException>().having(
            (e) => e.error,
            'error',
            OAuthError.stateMismatch,
          ),
        ),
      );
      expect(launched, isEmpty);
    },
  );

  test('falls back to the browser when the server answers 200', () async {
    final mock = http_testing.MockClient(
      (request) async => http.Response('<html>login</html>', 200),
    );
    late OAuthService service;
    final fake = cancellingLauncher(() => service);
    service = OAuthService(launcher: fake.launcher);

    await expectLater(
      service.authorize(_baseUrl, client: _createClient(mock)),
      _isCancelled,
    );
    expect(fake.calls, hasLength(1));
    expect(fake.calls.single.path, '/oauth/authorize');
  });

  test('falls back to the browser when the request fails', () async {
    final mock = http_testing.MockClient(
      (request) async => throw http.ClientException('boom'),
    );
    late OAuthService service;
    final fake = cancellingLauncher(() => service);
    service = OAuthService(launcher: fake.launcher);

    await expectLater(
      service.authorize(_baseUrl, client: _createClient(mock)),
      _isCancelled,
    );
    expect(fake.calls, hasLength(1));
  });

  test('skips the in-app leg when no certificate is active', () async {
    HttpOverrides.global = null;
    var requests = 0;
    final mock = http_testing.MockClient((request) async {
      requests++;
      final state = request.url.queryParameters['state'];
      return http.Response(
        '',
        302,
        headers: {'location': 'vikunja-flutter://callback?code=x&state=$state'},
      );
    });
    late OAuthService service;
    final fake = cancellingLauncher(() => service);
    service = OAuthService(launcher: fake.launcher);

    await expectLater(
      service.authorize(_baseUrl, client: _createClient(mock)),
      _isCancelled,
    );
    expect(requests, 0);
    expect(fake.calls, hasLength(1));
  });

  test('prefers the webViewAuthorizer over the browser when provided and the '
      'server answers 200', () async {
    final launched = <Uri>[];
    final mock = http_testing.MockClient(
      (request) async => http.Response('<html>login</html>', 200),
    );
    final service = OAuthService(
      launcher: (url) async {
        launched.add(url);
        return true;
      },
      webViewAuthorizer: (authorizeUrl) async {
        final state = authorizeUrl.queryParameters['state'];
        return Uri.parse(
          'vikunja-flutter://callback?code=fromwebview&state=$state',
        );
      },
    );

    final code = await service.authorize(_baseUrl, client: _createClient(mock));

    expect(code, 'fromwebview');
    expect(launched, isEmpty);
  });

  test('honors cancelAuthorize while the in-app request is pending', () async {
    final launched = <Uri>[];
    var webViewCalls = 0;
    final requestStarted = Completer<void>();
    final release = Completer<void>();
    final mock = http_testing.MockClient((request) async {
      requestStarted.complete();
      await release.future;
      final state = request.url.queryParameters['state'];
      return http.Response(
        '',
        302,
        headers: {
          'location': 'vikunja-flutter://callback?code=late&state=$state',
        },
      );
    });
    final service = OAuthService(
      launcher: (url) async {
        launched.add(url);
        return true;
      },
      webViewAuthorizer: (url) async {
        webViewCalls++;
        return null;
      },
    );

    final result = service.authorize(_baseUrl, client: _createClient(mock));
    await requestStarted.future;
    service.cancelAuthorize();
    release.complete();

    await expectLater(result, _isCancelled);
    expect(launched, isEmpty);
    expect(webViewCalls, 0);
  });

  test(
    'falls back to the browser when the redirect is not the callback',
    () async {
      final mock = http_testing.MockClient(
        (request) async => http.Response(
          '',
          302,
          headers: {'location': 'https://example.com/elsewhere'},
        ),
      );
      late OAuthService service;
      final fake = cancellingLauncher(() => service);
      service = OAuthService(launcher: fake.launcher);

      await expectLater(
        service.authorize(_baseUrl, client: _createClient(mock)),
        _isCancelled,
      );
      expect(fake.calls, hasLength(1));
    },
  );

  test('throws cancelled when the webViewAuthorizer returns null', () async {
    final launched = <Uri>[];
    final mock = http_testing.MockClient(
      (request) async => http.Response('<html>login</html>', 200),
    );
    final service = OAuthService(
      launcher: (url) async {
        launched.add(url);
        return true;
      },
      webViewAuthorizer: (url) async => null,
    );

    await expectLater(
      service.authorize(_baseUrl, client: _createClient(mock)),
      _isCancelled,
    );
    expect(launched, isEmpty);
  });

  test(
    'uses the browser when no client is given and a certificate is active',
    () async {
      late OAuthService service;
      final fake = cancellingLauncher(() => service);
      service = OAuthService(launcher: fake.launcher);

      await expectLater(service.authorize(_baseUrl), _isCancelled);
      expect(fake.calls, hasLength(1));
      expect(fake.calls.single.path, '/oauth/authorize');
    },
  );
}
