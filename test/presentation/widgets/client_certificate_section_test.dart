import 'package:flutter/material.dart';
import 'package:flutter_localizations/flutter_localizations.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:vikunja_app/core/network/tls_http_overrides.dart';
import 'package:vikunja_app/l10n/gen/app_localizations.dart';
import 'package:vikunja_app/presentation/manager/client_certificate_controller.dart';
import 'package:vikunja_app/presentation/widgets/client_certificate_section.dart';

class _FixedStatus extends ClientCertificateController {
  final ClientCertificateStatus status;
  _FixedStatus(this.status);

  @override
  Future<ClientCertificateStatus> build() async => status;
}

Widget _wrap(ClientCertificateStatus status) {
  return ProviderScope(
    overrides: [
      clientCertificateControllerProvider.overrideWith(
        () => _FixedStatus(status),
      ),
    ],
    child: const MaterialApp(
      localizationsDelegates: [
        AppLocalizations.delegate,
        GlobalMaterialLocalizations.delegate,
        GlobalWidgetsLocalizations.delegate,
      ],
      supportedLocales: [Locale('en')],
      home: Scaffold(body: ClientCertificateSection()),
    ),
  );
}

void main() {
  testWidgets('shows import only when no certificate is stored', (
    tester,
  ) async {
    await tester.pumpWidget(_wrap(ClientCertificateStatus.none));
    await tester.pumpAndSettle();

    expect(find.text('Import certificate'), findsOneWidget);
    final remove = tester.widget<OutlinedButton>(
      find.widgetWithText(OutlinedButton, 'Remove certificate'),
    );
    expect(remove.onPressed, isNull);
    expect(
      find.textContaining('No client certificate imported'),
      findsOneWidget,
    );
  });

  testWidgets('enables remove when a certificate is active', (tester) async {
    await tester.pumpWidget(_wrap(ClientCertificateStatus.active));
    await tester.pumpAndSettle();

    final remove = tester.widget<OutlinedButton>(
      find.widgetWithText(OutlinedButton, 'Remove certificate'),
    );
    expect(remove.onPressed, isNotNull);
    expect(find.textContaining('is active'), findsOneWidget);
  });

  testWidgets('explains an invalid stored certificate', (tester) async {
    await tester.pumpWidget(_wrap(ClientCertificateStatus.invalid));
    await tester.pumpAndSettle();

    expect(find.textContaining('failed to load'), findsOneWidget);
    expect(find.text('Import certificate'), findsOneWidget);
  });
}
