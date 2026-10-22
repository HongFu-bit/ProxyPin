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

import 'package:proxypin/network/bin/listener.dart';
import 'package:proxypin/network/channel/channel.dart';
import 'package:proxypin/network/channel/channel_context.dart';
import 'package:proxypin/network/http/http.dart';
import 'package:proxypin/network/http/websocket.dart';

/// 把抓包事件转成轻量 JSON 事件流，供 `/mcp/events` 的 SSE 长连接消费。
///
/// 注册为 [EventListener] 后与 UI 同源接收流量；没有订阅者时不构造事件。
class FlowBroadcaster extends EventListener {
  FlowBroadcaster._();

  static final FlowBroadcaster instance = FlowBroadcaster._();

  final StreamController<Map<String, dynamic>> _controller =
      StreamController<Map<String, dynamic>>.broadcast(sync: true);

  Stream<Map<String, dynamic>> get stream => _controller.stream;

  bool get hasSubscribers => _controller.hasListener;

  @override
  void onRequest(Channel channel, HttpRequest request) => publishRequest(request);

  @override
  void onResponse(ChannelContext channelContext, HttpResponse response) =>
      publishResponse(response);

  @override
  void onMessage(Channel channel, HttpMessage message, WebSocketFrame frame) {
    if (!hasSubscribers) return;
    _emit({
      'event': 'flow_message',
      'flowId': message.requestId,
      'opcode': frame.opcode,
      'size': frame.payloadData.length,
      'ts': DateTime.now().millisecondsSinceEpoch,
    });
  }

  void publishRequest(HttpRequest request) {
    if (!hasSubscribers) return;
    _emit({
      'event': 'flow_started',
      'flowId': request.requestId,
      'method': request.method.name.toUpperCase(),
      'url': request.requestUrl,
      'ts': request.requestTime.millisecondsSinceEpoch,
    });
  }

  void publishResponse(HttpResponse response) {
    if (!hasSubscribers) return;
    var request = response.request;
    _emit({
      'event': 'flow_completed',
      'flowId': request?.requestId ?? response.requestId,
      'method': request?.method.name.toUpperCase(),
      'url': request?.requestUrl,
      'status': response.status.code,
      'size': response.body?.length ?? 0,
      'contentType': response.headers.contentType,
      'elapsedMs': request == null
          ? null
          : DateTime.now().difference(request.requestTime).inMilliseconds,
      'ts': DateTime.now().millisecondsSinceEpoch,
    });
  }

  void _emit(Map<String, dynamic> event) {
    if (_controller.isClosed) return;
    _controller.add(event);
  }
}
