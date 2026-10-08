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
