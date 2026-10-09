import 'dart:async';

import 'package:background_downloader/background_downloader.dart';
import 'package:vikunja_app/core/network/remote_data_source.dart';
import 'package:vikunja_app/core/network/response.dart';
import 'package:vikunja_app/core/network/tls_http_overrides.dart';
import 'package:vikunja_app/data/data_sources/attachment_downloader.dart';
import 'package:vikunja_app/data/models/task_attachment_dto.dart';
import 'package:vikunja_app/data/models/task_dto.dart';

class TaskDataSource extends RemoteDataSource {
  TaskDataSource(super.client);

  Future<Response<TaskDto>> add(int projectId, TaskDto task) {
    return client.put(
      url: '/projects/$projectId/tasks',
      body: task.toJSON(),
      mapper: (body) {
        return TaskDto.fromJson(body);
      },
    );
  }

  Future<Response<Object>> delete(int taskId) async {
    return client.delete(url: '/tasks/$taskId');
  }

  Future<Response<TaskDto>> update(TaskDto task) async {
    return await client.post(
      url: '/tasks/${task.id}',
      body: task.toJSON(),
      mapper: (body) {
        return TaskDto.fromJson(body);
      },
    );
  }

  Future<Response<List<TaskDto>>> getAllByProject(
    int projectId, [
    Map<String, List<String>>? queryParameters,
  ]) {
    return client.get(
      url: '/projects/$projectId/tasks',
      mapper: (body) {
        return convertList(body, (result) => TaskDto.fromJson(result));
      },
      queryParameters: queryParameters,
    );
  }

  Future<Response<TaskDto>> getTask(int taskId) async {
    return await client.get(
      url: '/tasks/$taskId',
      mapper: (body) {
        return TaskDto.fromJson(body);
      },
    );
  }

  Future<Response<List<TaskDto>>> getAllByProjectView(
    int projectId,
    int view, [
    Map<String, List<String>>? queryParameters,
  ]) {
    return client.get(
      url: '/projects/$projectId/views/$view/tasks',
      mapper: (body) {
        return convertList(body, (result) => TaskDto.fromJson(result));
      },
      queryParameters: queryParameters,
    );
  }

  Future<Response<List<TaskDto>>> getByFilterString(
    String filterString, [
    Map<String, List<String>>? queryParameters,
  ]) async {
    Map<String, List<String>> parameters = {
      "filter": [filterString],
      ...?queryParameters,
    };

    return await client.get(
      url: '/tasks',
      mapper: (body) {
        return convertList(body, (result) => TaskDto.fromJson(result));
      },
      queryParameters: parameters,
    );
  }

  Future<TaskStatusUpdate> downloadAttachment(
    int taskId,
    TaskAttachmentDto attachment,
  ) async {
    final relativeUrl = '/tasks/$taskId/attachments/${attachment.id}';

    final task = DownloadTask(
      url: '${client.apiBase}$relativeUrl',
      baseDirectory: BaseDirectory.applicationSupport,
      filename: attachment.file.name,
      headers: await client.getHeaders(),
      updates: Updates.statusAndProgress,
    );

    // background_downloader's native stack cannot present a client
    // certificate, so download in-process while one is active.
    if (TlsHttpOverrides.clientCertificateActive) {
      return ForegroundAttachmentDownloader(client).download(task, relativeUrl);
    }

    return await FileDownloader().download(task);
  }
}
