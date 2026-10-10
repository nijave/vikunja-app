# Android client-certificate (mTLS) support — design

Status: approved in conversation on 2026-10-08. Replaces the approach in PR #301.
Scope: Android only for this iteration. The code paths are platform-neutral
Dart, but iOS is neither wired nor tested here.

## Problem

Issue #147: the app cannot talk to a Vikunja server that sits behind a
reverse proxy requiring a TLS client certificate. PR #301 solved this on
Android by swapping the transport to `ok_http` and reading the system
KeyChain. The maintainer declined it because `ok_http` is experimental with a
single two-year-old release, the change is Android-only, and it removed the
background attachment downloader.

## Constraints learned during review

- `main` already uses `cronet_http` on Android and `cupertino_http` on iOS,
  built in `lib/core/network/client.dart`. The project picked Cronet so
  Android honors user-installed CAs (issue #66).
- Cronet cannot present a client certificate. Chromium's
  `components/cronet/cronet_url_request.cc` answers every certificate request
  with `ContinueWithCertificate(nullptr, nullptr)`. `cronet_http` exposes no
  TLS hooks. The Android KeyChain route stays closed while Cronet
  is the transport.
- dart:io `SecurityContext` accepts PKCS#12 bytes with a password in both
  `useCertificateChainBytes` and `usePrivateKeyBytes`. No PEM conversion is
  needed.
- `background_downloader` uses `HttpURLConnection` inside WorkManager on
  Android and exposes no TLS hooks, so it cannot present the certificate.
- Flutter 3.44.4's default `minSdkVersion` is already 24, so the Android 5/6
  concern from PR #301 no longer applies.
- Immich's first mTLS release (PR 10860) used exactly the imported-PKCS#12
  approach below. Their later move to native code is out of scope here.

## Design

### Transport selection

Cronet stays the default Android transport. When the user has imported a
client certificate, `Client.createClient()` returns a dart:io `IOClient`
instead. The app talks to one server per install, so a global switch covers
every request.

### TLS configuration lives in `HttpOverrides.global`

A new `TlsHttpOverrides` (replacing `IgnoreCertHttpOverrides`) carries three
values: `ignoreCertificates`, an optional `SecurityContext`, and a
`ClientCertificateStatus` (`none`, `active`, `invalid`). Every dart:io
`HttpClient()` created without an explicit context goes through it, so the
`IOClient`, the token-refresh client, and `NetworkImage` for the avatar all
present the certificate with no further wiring.

`applyStoredTlsSettings(SettingsDatasource)` reads the ignore-certs flag and
the stored certificate, builds the context, and installs the overrides. It
never throws: an unreadable certificate logs, sets status `invalid`, and
leaves the context null. Every entry point that constructs a `Client` calls
it first: app init, the WorkManager task, the notification action, and the
home-widget callbacks.

### Certificate storage

`SettingsDatasource` gains three secure-storage keys: `client-cert-pkcs12`
(base64), `client-cert-password`, and `client-cert-ca-pem` (base64, optional).
A `ClientCertificate` value type holds the decoded form. The certificate is
per device, not per login, so logout does not clear it.

### Private CA trust

Because dart:io on Android ignores user-installed CAs, the import flow accepts
an optional CA certificate in PEM form, which `buildSecurityContext` adds with
`setTrustedCertificatesBytes`. Users without a private CA leave it empty.

### Attachment download

`TaskDataSource.downloadAttachment` keeps `background_downloader` when no
certificate is active. When one is active, a `ForegroundAttachmentDownloader`
fetches the file through the app's `Client`, writes it to the same
application-support location the plugin would use, and returns a
`TaskStatusUpdate` so the existing `FileDownloader().openFile` call in the
task page keeps working. Nobody without a certificate loses background
downloads.

### User interface

A `ClientCertificateSection` widget shows the status (none, active, failed to
load) with Import and Remove buttons. Import opens the system file
picker (`file_picker`, any file type, since Android mime filtering hides
`.p12` files), asks for the password and an optional CA file, validates by
building a `SecurityContext`, saves, and re-applies the overrides. It appears
in Settings under the ignore-certificates checkbox and on the login page's
custom-URL view so first login against an mTLS server works.

If the login page's `/api/v1/info` probe fails with HTTP 401 or 403 and no
certificate is active, the error text says the server may need a client
certificate instead of the generic cannot-reach-server message. That endpoint
needs no login, so those codes almost always come from an mTLS gate such as
Envoy `ext_authz`.

### Missing or unreadable certificate

Status `invalid` renders in the section as "The stored certificate failed to
load. Import it again." Status `none` after a known import (secure storage
can lose entries on backup restore or keystore reset) renders as the ordinary
not-configured state. Neither state crashes or blocks login.

### OAuth login with a client certificate

A system browser cannot use the certificate that the user imported into the
app. The device test on 2026-10-10 confirmed this: Firefox for Android sent no
certificate on the `/oauth/authorize` request, and the proxy denied it.
`OAuthService.authorize()` picks one of three paths:

1. **No certificate active.** Unchanged: `url_launcher` opens the system
   browser and the deep link `vikunja-flutter://callback` returns the code.
2. **Certificate active, redirecting proxy.** The app sends the `/oauth/authorize` GET
   itself through `Client` with redirects disabled. When the response is a 30x
   whose `Location` is `vikunja-flutter://callback`, the app treats it as the
   callback: same `state` check, same `code` extraction. No browser opens.
   This matches a federating proxy that mints the code from the mTLS identity.
3. **Certificate active, any other response.** The app opens the `/oauth/authorize` URL
   in an in-app `InAppWebView` page. The page answers the client-certificate
   challenge from the stored bundle, written to an app-private temporary file
   for the duration of the login and deleted when the page closes. A navigation
   to `vikunja-flutter://callback` completes the flow; the back button cancels
   it. With Ignore Certificates on, the page also accepts the server-trust
   challenge; otherwise it trusts the system and user CA stores, as Chrome
   does.

`flutter_inappwebview` already ships with the app as a dependency of the HTML
editor, so path 3 adds no plugin and no native code. The token exchange still
goes through `Client` on every path.

## Out of scope

- iOS wiring and testing.
- Android KeyChain / system certificate manager.
- A native `HttpsURLConnection.setDefaultSSLSocketFactory` shim to keep
  background downloads working under mTLS. Candidate follow-up.
- HtmlWidget inline images. They already load without auth headers today.

## Testing

Unit tests use committed PKCS#12 fixtures generated by an OpenSSL script in
`test/fixtures/`. The core test starts a dart:io `HttpServer.bindSecure` with
`requestClientCertificate: true` and asserts the client presents the fixture
certificate. Storage, overrides, foreground download, and the controller get
their own unit tests. End-to-end verification is a debug APK on the Pixel 7
against `vikunja.apps.somemissing.info`.
