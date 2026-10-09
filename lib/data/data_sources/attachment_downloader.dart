import 'dart:io';

import 'package:background_downloader/background_downloader.dart';
import 'package:path_provider/path_provider.dart';
import 'package:vikunja_app/core/network/client.dart';

/// Downloads an attachment through the app's own [Client] instead of
/// background_downloader. Used only when a client certificate is active,
/// because background_downloader's native stack cannot present it.
///
/// Writes to the same application-support location background_downloader
/// uses for [BaseDirectory.applicationSupport], so the task page can keep
/// calling FileDownloader().openFile(task: ...) on the returned task.
class ForegroundAttachmentDownloader {
  final Client _client;
  final Future<Directory> Function() _directoryProvider;

  ForegroundAttachmentDownloader(
    this._client, {
    Future<Directory> Function() directoryProvider =
        getApplicationSupportDirectory,
  }) : _directoryProvider = directoryProvider;

  Future<TaskStatusUpdate> download(
    DownloadTask task,
    String relativeUrl,
  ) async {
    try {
      final response = await _client.getRaw(url: relativeUrl);
      if (response.statusCode < 200 || response.statusCode >= 300) {
        return TaskStatusUpdate(
          task,
          TaskStatus.failed,
          TaskHttpException('Attachment download failed', response.statusCode),
        );
      }

      final directory = await _directoryProvider();
      final file = File('${directory.path}/${task.filename}');
      await file.parent.create(recursive: true);
      await file.writeAsBytes(response.bodyBytes, flush: true);

      return TaskStatusUpdate(task, TaskStatus.complete);
    } catch (e) {
      return TaskStatusUpdate(
        task,
        TaskStatus.failed,
        TaskConnectionException(e.toString()),
      );
    }
  }
}
