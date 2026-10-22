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
import 'dart:convert';
import 'dart:io';

import 'package:proxypin/network/util/logger.dart';

import '../extra/audit_log.dart';
import '../extra/flow_broadcaster.dart';
import '../protocol/json_rpc.dart';
import '../protocol/mcp_server.dart';
import 'bearer_auth.dart';
import 'setup_script.dart';

/// MCP Streamable HTTP 传输（无状态，单 JSON 响应）。
///
/// 绑定地址由调用方决定（桌面默认 loopback，移动端默认 0.0.0.0，移动端可由用户自定义），
/// AI 客户端直接以 HTTP 连接（无额外桥进程）；绑到非回环地址时要求 Bearer token。
///
/// @author wanghongen
class McpHttpServer {
  static const String path = '/mcp';

  final McpServer mcp;

  /// 绑定地址：由调用方决定（桌面默认 loopback，移动端默认 0.0.0.0 / 用户自定义）
  final InternetAddress address;

  /// 非空时 /mcp 请求必须携带 `Authorization: Bearer <token>`
  final String? token;

  /// 可选的工具调用审计（opt-in；未配置或关闭时不产生 IO）
  final AuditLog? audit;

  HttpServer? _server;

  McpHttpServer({required this.mcp, InternetAddress? address, this.token, this.audit})
      : address = address ?? InternetAddress.loopbackIPv4;

  bool get isRunning => _server != null;

  int? get port => _server?.port;

  Future<void> start(int preferredPort) async {
    if (_server != null) return;
    _server = await HttpServer.bind(address, preferredPort, shared: false);
    _server!.listen(_handle, onError: (e) => logger.e('MCP http server error: $e'));
    logger.i('MCP http server listening on ${address.address}:${_server!.port}');
  }

  Future<void> stop() async {
    await _server?.close(force: true);
    _server = null;
  }

  void _handle(HttpRequest req) async {
    try {
      if (req.method == 'GET' && req.uri.path == '/') {
        if (!_authorized(req)) return;
        req.response.headers.contentType = ContentType.json;
        req.response.statusCode = HttpStatus.ok;
        req.response.write(jsonEncode({'service': 'proxypin-mcp', 'status': 'running'}));
        await req.response.close();
        return;
      }

      // 一键配置脚本下发（仅 LAN token 模式有意义）：/mcp/setup.sh、/mcp/setup.ps1
      if (req.method == 'GET' && (req.uri.path == '$path/setup.sh' || req.uri.path == '$path/setup.ps1')) {
        await _handleSetupScript(req);
        return;
      }

      // 实时流量事件流（SSE）：GET /mcp/events?host=&method=&events=flow_started,flow_completed
      if (req.method == 'GET' && req.uri.path == '$path/events') {
        if (!_authorized(req)) return;
        await _streamEvents(req);
        return;
      }

      if (req.method != 'POST' || req.uri.path != path) {
        req.response.statusCode = HttpStatus.notFound;
        await req.response.close();
        return;
      }

      // LAN 模式鉴权：Bearer token 不匹配直接 401
      if (!_authorized(req)) return;

      var body = await req.cast<List<int>>().transform(utf8.decoder).join();
      Map<String, dynamic> message;
      try {
        var decoded = jsonDecode(body);
        if (decoded is! Map<String, dynamic>) {
          throw const FormatException('expected JSON object');
        }
        message = decoded;
      } catch (e) {
        await _writeJson(req, JsonRpcResponse.error(null, JsonRpcError(JsonRpcError.parseError, 'Parse error: $e')),
            HttpStatus.badRequest);
        return;
      }

      var stopwatch = Stopwatch()..start();
      var response = await mcp.handle(message);
      _auditToolCall(message, response, req, stopwatch.elapsed);
      if (response == null) {
        // 通知：202 无响应体
        req.response.statusCode = HttpStatus.accepted;
        await req.response.close();
        return;
      }

      var accept = req.headers.value(HttpHeaders.acceptHeader) ?? '';
      if (accept.contains('text/event-stream') && !accept.contains('application/json')) {
        await _writeSse(req, response);
      } else {
        await _writeJson(req, response, HttpStatus.ok);
      }
    } catch (e, st) {
      logger.e('MCP request error', error: e, stackTrace: st);
      try {
        req.response.statusCode = HttpStatus.internalServerError;
        await req.response.close();
      } catch (_) {}
    }
  }

  /// 只审计 tools/call；参数脱敏与落盘都由 [AuditLog] 负责，这里不阻塞响应。
  void _auditToolCall(Map<String, dynamic> message, Map<String, dynamic>? response, HttpRequest req, Duration elapsed) {
    var log = audit;
    if (log == null || message['method'] != 'tools/call') return;
    var params = (message['params'] as Map?)?.cast<String, dynamic>() ?? const <String, dynamic>{};
    var tool = params['name']?.toString() ?? 'unknown';
    var args = (params['arguments'] as Map?)?.cast<String, dynamic>();

    var ok = true;
    String? error;
    var rpcError = response?['error'];
    if (rpcError is Map) {
      ok = false;
      error = rpcError['message']?.toString();
    } else {
      var result = response?['result'];
      if (result is Map && result['isError'] == true) {
        ok = false;
        var content = result['content'];
        if (content is List && content.isNotEmpty && content.first is Map) {
          error = (content.first as Map)['text']?.toString();
        }
      }
    }

    unawaited(log.record(
      tool: tool,
      arguments: args,
      client: req.connectionInfo?.remoteAddress.address ?? '-',
      userAgent: req.headers.value(HttpHeaders.userAgentHeader),
      elapsed: elapsed,
      ok: ok,
      error: error,
    ));
  }

  /// LAN 模式下校验 Bearer token；不通过时直接写 401 并返回 false。
  /// 使用常量时间比较，避免按字符提前返回造成时序侧信道。
  bool _authorized(HttpRequest req) {
    if (token == null) return true;
    var got = req.headers.value(HttpHeaders.authorizationHeader);
    if (bearerTokenMatches(got, token!)) return true;
    req.response.statusCode = HttpStatus.unauthorized;
    req.response.headers.set(HttpHeaders.wwwAuthenticateHeader, 'Bearer');
    unawaited(req.response.close());
    return false;
  }

  /// 下发一键配置脚本。endpoint 取自请求 Host 头，保证脚本里的地址就是电脑访问手机的地址。
  Future<void> _handleSetupScript(HttpRequest req) async {
    // LAN 模式同样要求 Bearer token，避免脚本和服务地址被局域网内他人随意拉取。
    if (!_authorized(req)) return;
    // Host 头由客户端按实际访问地址（手机 LAN IP:端口）发送，curl/irm 一定会携带。
    // 回退到绑定地址可能拼出电脑不可达的地址（如 0.0.0.0 / 回环），因此缺失/非法时直接 400；
    // 同时只允许主机名/IP 与端口字符，防止 Host 注入到下发的脚本里。
    var host = req.headers.host;
    if (host == null || !RegExp(r"^[A-Za-z0-9._\-]+(:\d+)?$|^\[[0-9a-fA-F:]+\](:\d+)?$").hasMatch(host)) {
      req.response.statusCode = HttpStatus.badRequest;
      req.response.write('Missing or invalid Host header');
      await req.response.close();
      return;
    }
    if (!host.contains(':')) {
      host = '$host:${_server?.port ?? ''}';
    }
    var endpoint = 'http://$host$path';
    var isShell = req.uri.path.endsWith('.sh');
    var script = isShell
        ? McpSetupScript.shell(endpoint: endpoint, token: token ?? '')
        : McpSetupScript.powershell(endpoint: endpoint, token: token ?? '');
    req.response.statusCode = HttpStatus.ok;
    // 显式 utf-8 charset，并直接写字节：HttpResponse.write 默认按 Latin-1 编码，
    // 脚本中一旦出现非 ASCII 字符（注释）会抛异常导致 500 空响应。
    req.response.headers.contentType = isShell
        ? ContentType('text', 'x-shellscript', charset: 'utf-8')
        : ContentType('text', 'plain', charset: 'utf-8');
    req.response.headers.set('Cache-Control', 'no-store');
    req.response.add(utf8.encode(script));
    await req.response.close();
  }

  /// 保持连接不关闭，持续下发抓包事件；15s 心跳防止中间设备断开。
  Future<void> _streamEvents(HttpRequest req) async {
    var host = req.uri.queryParameters['host']?.toLowerCase();
    var method = req.uri.queryParameters['method']?.toUpperCase();
    var wanted = (req.uri.queryParameters['events'] ?? '')
        .split(',')
        .map((value) => value.trim())
        .where((value) => value.isNotEmpty)
        .toSet();

    req.response.statusCode = HttpStatus.ok;
    req.response.headers.contentType = ContentType('text', 'event-stream', charset: 'utf-8');
    req.response.headers.set('Cache-Control', 'no-cache');
    req.response.headers.set('Connection', 'keep-alive');
    req.response.headers.set('X-Accel-Buffering', 'no');
    req.response.bufferOutput = false;
    req.response.write(': subscribed\n\n');

    var closed = false;
    Timer? timer;
    StreamSubscription<Map<String, dynamic>>? subscription;

    Future<void> cleanup() async {
      if (closed) return;
      closed = true;
      timer?.cancel();
      await subscription?.cancel();
      try {
        await req.response.close();
      } catch (_) {}
    }

    bool matches(Map<String, dynamic> event) {
      if (wanted.isNotEmpty && !wanted.contains(event['event'])) return false;
      if (host != null && host.isNotEmpty) {
        var url = (event['url'] as String?)?.toLowerCase() ?? '';
        if (!url.contains(host)) return false;
      }
      if (method != null && method.isNotEmpty) {
        if ((event['method'] as String?)?.toUpperCase() != method) return false;
      }
      return true;
    }

    subscription = FlowBroadcaster.instance.stream.listen((event) {
      if (closed || !matches(event)) return;
      try {
        req.response.write('event: ${event['event']}\ndata: ${jsonEncode(event)}\n\n');
      } catch (_) {
        cleanup();
      }
    }, onError: (_) => cleanup());

    timer = Timer.periodic(const Duration(seconds: 15), (_) {
      if (closed) return;
      try {
        req.response.write(': keepalive\n\n');
      } catch (_) {
        cleanup();
      }
    });

    unawaited(req.response.done.whenComplete(cleanup));
  }

  Future<void> _writeJson(HttpRequest req, Map<String, dynamic> payload, int status) async {
    req.response.statusCode = status;
    req.response.headers.contentType = ContentType.json;
    req.response.headers.set('MCP-Protocol-Version', McpServer.protocolVersion);
    req.response.write(jsonEncode(payload));
    await req.response.close();
  }

  Future<void> _writeSse(HttpRequest req, Map<String, dynamic> payload) async {
    req.response.statusCode = HttpStatus.ok;
    req.response.headers.contentType = ContentType.parse('text/event-stream');
    req.response.headers.set('Cache-Control', 'no-cache');
    req.response.write('event: message\ndata: ${jsonEncode(payload)}\n\n');
    await req.response.close();
  }
}
