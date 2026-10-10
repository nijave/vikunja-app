// OAuthWebViewPage itself hosts an InAppWebView, which is an Android/iOS
// platform view. flutter_test has no platform-view backend, so a widget test
// of the page cannot run here. These tests cover the two pure decisions the
// page delegates to; the page is verified on a device.
import 'package:flutter_inappwebview/flutter_inappwebview.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:vikunja_app/presentation/pages/login/oauth_webview_page.dart';

void main() {
  group('isCallbackUri', () {
    test('accepts the vikunja-flutter callback', () {
      expect(
        isCallbackUri(Uri.parse('vikunja-flutter://callback?code=a&state=b')),
        isTrue,
      );
    });

    test('rejects an https URL', () {
      expect(
        isCallbackUri(Uri.parse('https://vikunja.example.com/oauth/authorize')),
        isFalse,
      );
    });

    test('rejects null', () {
      expect(isCallbackUri(null), isFalse);
    });

    test('rejects another host on the app scheme', () {
      expect(isCallbackUri(Uri.parse('vikunja-flutter://other')), isFalse);
    });
  });

  group('serverTrustAction', () {
    test('proceeds when certificates are ignored', () {
      expect(
        serverTrustAction(ignoreCertificates: true),
        ServerTrustAuthResponseAction.PROCEED,
      );
    });

    test('cancels when certificates are checked', () {
      expect(
        serverTrustAction(ignoreCertificates: false),
        ServerTrustAuthResponseAction.CANCEL,
      );
    });
  });
}
