import 'package:flutter_test/flutter_test.dart';
import 'package:vikunja_app/core/network/response.dart';
import 'package:vikunja_app/presentation/pages/login/login_page.dart';

void main() {
  ErrorResponse<Object?> error(int status) =>
      ErrorResponse(status, const {}, const {'message': 'denied'});

  test('returns the status for a 401 or 403 without a certificate', () {
    expect(
      clientCertificateHintStatus(error(401), certificateActive: false),
      401,
    );
    expect(
      clientCertificateHintStatus(error(403), certificateActive: false),
      403,
    );
  });

  test('returns null when a certificate is already active', () {
    expect(
      clientCertificateHintStatus(error(403), certificateActive: true),
      isNull,
    );
  });

  test('returns null for other status codes', () {
    expect(
      clientCertificateHintStatus(error(500), certificateActive: false),
      isNull,
    );
  });

  test('returns null for an exception response', () {
    expect(
      clientCertificateHintStatus(
        ExceptionResponse<Object?>(Exception('offline'), StackTrace.empty),
        certificateActive: false,
      ),
      isNull,
    );
  });
}
