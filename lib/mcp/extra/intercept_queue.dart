/*
 * Copyright 2026 Hongen Wang All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import 'dart:async';
import 'dart:collection';

import 'package:proxypin/mcp/capture/flow_view.dart';
import 'package:proxypin/mcp/capture/sensitive_data.dart';
import 'package:proxypin/network/http/http.dart';

/// MCP 对一条挂起断点的处置决定。
///
/// [action] 为 `continue` 或 `drop`；[headers] 为增量合并（同名覆盖），
/// [body] 为整体替换的文本，[statusCode] 仅对响应阶段生效。
class InterceptDecision {
  final String action;
  final Map<String, String>? headers;
  final String? body;
  final int? statusCode;

  const InterceptDecision({this.action = 'continue', this.headers, this.body, this.statusCode});

  /// 超时/取消时使用：原样放行
  static const InterceptDecision continueUnchanged = InterceptDecision();

  bool get shouldDrop => action == 'drop';
}

/// 一条被断点挂起、等待 MCP 决策的请求/响应。
class PendingIntercept {
  final String id;
  final String flowId;
  final String phase;
  final HttpRequest request;
  final HttpResponse? response;
  final DateTime createdAt;
  final DateTime expiresAt;

  final Completer<InterceptDecision> _completer = Completer<InterceptDecision>();
  Timer? _timer;

  PendingIntercept({
    required this.id,
    required this.flowId,
    required this.phase,
    required this.request,
    required this.response,
    required this.createdAt,
    required this.expiresAt,
  });

  Future<InterceptDecision> get future => _completer.future;

  bool get isResolved => _completer.isCompleted;

  void _complete(InterceptDecision decision) {
    _timer?.cancel();
    if (!_completer.isCompleted) _completer.complete(decision);
  }

  /// 给 MCP 客户端看的快照。超过 [previewBytes] 的 body 截断并标记。
  Future<Map<String, dynamic>> toJson({bool redact = true, int previewBytes = 8192}) async {
    var message = phase == 'response' ? response : request;
    var body = '';
    var bodyTruncated = false;
    var bodyBinary = false;
    if (message != null && message.body != null && message.body!.isNotEmpty) {
      if (FlowView.isBinary(message)) {
        bodyBinary = true;
      } else {
        var text = await message.decodeBodyString();
        if (text.length > previewBytes) {
          text = text.substring(0, previewBytes);
          bodyTruncated = true;
        }
        body = text;
      }
    }

    return {
      'id': id,
      'flowId': flowId,
      'phase': phase,
      'method': request.method.name,
      'url': request.requestUrl,
      if (phase == 'response' && response != null) 'statusCode': response!.status.code,
      'headers': _headers(message, redact),
      'body': body,
      if (bodyBinary) 'bodyBinary': true,
      if (bodyTruncated) 'bodyTruncated': true,
      'createdAtMs': createdAt.millisecondsSinceEpoch,
      'expiresAtMs': expiresAt.millisecondsSinceEpoch,
      'remainingMs': expiresAt.difference(DateTime.now()).inMilliseconds.clamp(0, 1 << 31),
    };
  }

  static Map<String, String> _headers(HttpMessage? message, bool redact) {
    var result = <String, String>{};
    message?.headers.forEach((name, values) {
      var value = values.length == 1 ? values.first : values.join(', ');
      result[name] = redact ? SensitiveData.redactValue(name, value) : value;
    });
    return result;
  }
}

/// 进程内的断点挂起队列。
///
/// 断点命中时由 MCP 钩子投递一条记录；UI 与 MCP 谁先处置谁生效，另一侧收到取消。
/// 每条记录都有 [timeout] 超时自动放行，避免 AI 客户端掉线后把目标 App 的请求挂死。
class InterceptQueue {
  static final InterceptQueue instance = InterceptQueue._();

  static const int maxPending = 50;

  InterceptQueue._();

  /// 单条挂起记录的最长等待时间；超时后原样放行
  Duration timeout = const Duration(seconds: 60);

  final LinkedHashMap<String, PendingIntercept> _items = LinkedHashMap();

  int get count => _items.length;

  PendingIntercept enqueueRequest(String flowId, HttpRequest request) =>
      _enqueue(flowId: flowId, phase: 'request', request: request, response: null);

  PendingIntercept enqueueResponse(String flowId, HttpRequest request, HttpResponse response) =>
      _enqueue(flowId: flowId, phase: 'response', request: request, response: response);

  PendingIntercept _enqueue({
    required String flowId,
    required String phase,
    required HttpRequest request,
    required HttpResponse? response,
  }) {
    var id = '${phase == 'request' ? 'req' : 'res'}_$flowId';
    // 同一 flow 同一阶段重复挂起时，先放行旧记录，避免队列里留下永远等不到结果的项
    _items.remove(id)?._complete(InterceptDecision.continueUnchanged);

    var now = DateTime.now();
    var item = PendingIntercept(
      id: id,
      flowId: flowId,
      phase: phase,
      request: request,
      response: response,
      createdAt: now,
      expiresAt: now.add(timeout),
    );
    _items[id] = item;

    while (_items.length > maxPending) {
      _items.remove(_items.keys.first)?._complete(InterceptDecision.continueUnchanged);
    }

    item._timer = Timer(timeout, () => resolve(id, InterceptDecision.continueUnchanged));
    return item;
  }

  List<PendingIntercept> list({String? phase, int limit = 20}) {
    var values = _items.values.where((item) => phase == null || phase.isEmpty || item.phase == phase);
    return values.take(limit.clamp(1, maxPending)).toList();
  }

  /// 按 id 处置一条挂起记录；记录不存在或已被另一侧处置时返回 false。
  bool resolve(String id, InterceptDecision decision) {
    var item = _items.remove(id);
    if (item == null || item.isResolved) return false;
    item._complete(decision);
    return true;
  }

  /// UI 侧先完成编辑时调用，从队列移除对应记录。
  void cancel(String requestId, {required bool response}) {
    var id = '${response ? 'res' : 'req'}_$requestId';
    _items.remove(id)?._complete(InterceptDecision.continueUnchanged);
  }

  /// 服务停止时清空：所有挂起请求原样放行。
  void clear() {
    for (var item in _items.values) {
      item._complete(InterceptDecision.continueUnchanged);
    }
    _items.clear();
  }
}
