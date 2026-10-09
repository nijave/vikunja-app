import 'dart:io';

import 'package:background_downloader/background_downloader.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart' as http_testing;
import 'package:vikunja_app/core/network/client.dart';
import 'package:vikunja_app/data/data_sources/attachment_downloader.dart';
import 'package:vikunja_app/data/data_sources/settings_data_source.dart';

const _baseUrl = 'https://vikunja.example.com';

class _Settings implements SettingsDatasource {
  @override
  Future<String?> getUserToken() async => 'tok';

  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

class _TestableClient extends Client {
  final http.Client mock;
  _TestableClient(this.mock) : super(base: _baseUrl);
  @override
  http.Client createClient() => mock;
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  late Directory dir;

  setUp(() async {
    dir = await Directory.systemTemp.createTemp('attachment_test_');
  });

  tearDown(() async {
    if (await dir.exists()) await dir.delete(recursive: true);
  });

  ForegroundAttachmentDownloader downloader(http.Client mock) {
    final client = _TestableClient(mock)..settingsDatasource = _Settings();
    return ForegroundAttachmentDownloader(
      client,
      directoryProvider: () async => dir,
    );
  }

  DownloadTask task() => DownloadTask(
    url: '$_baseUrl/api/v1/tasks/1/attachments/2',
    baseDirectory: BaseDirectory.applicationSupport,
    filename: 'notes.txt',
  );

  test('writes the body to the task filename and reports complete', () async {
    final result = await downloader(
      http_testing.MockClient((request) async {
        expect(request.headers['Authorization'], 'Bearer tok');
        return http.Response.bytes([104, 105], 200);
      }),
    ).download(task(), '/tasks/1/attachments/2');

    expect(result.status, TaskStatus.complete);
    expect(File('${dir.path}/notes.txt').readAsStringSync(), 'hi');
  });

  test(
    'reports failed with TaskHttpException on a 401 and leaves no file',
    () async {
      final result = await downloader(
        http_testing.MockClient((_) async => http.Response('denied', 401)),
      ).download(task(), '/tasks/1/attachments/2');

      expect(result.status, TaskStatus.failed);
      expect(result.exception, isA<TaskHttpException>());
      expect((result.exception as TaskHttpException).httpResponseCode, 401);
      expect(File('${dir.path}/notes.txt').existsSync(), isFalse);
    },
  );

  test(
    'reports failed with TaskConnectionException when the request throws',
    () async {
      final result = await downloader(
        http_testing.MockClient(
          (_) async => throw const SocketException('down'),
        ),
      ).download(task(), '/tasks/1/attachments/2');

      expect(result.status, TaskStatus.failed);
      expect(result.exception, isA<TaskConnectionException>());
    },
  );
}
