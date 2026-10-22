import 'dart:async';
import 'dart:convert';

import 'package:proxypin/network/components/interceptor.dart';
import 'package:proxypin/network/components/manager/environment_manager.dart';
import 'package:proxypin/network/components/manager/request_breakpoint_manager.dart';
import 'package:proxypin/network/http/http.dart';
import 'package:proxypin/network/util/cache.dart';
import 'package:proxypin/network/util/logger.dart';
import 'package:proxypin/ui/component/multi_window.dart';

import '../http/http_headers.dart';

/// 外部断点处理器（如 MCP 交互式拦截）。
///
/// 与 UI 编辑窗口竞速：外部先返回则 UI 窗口的[Completer]被代为完成，
/// UI 先完成则调用 [cancel] 清理外部挂起项。返回 null 表示丢弃该请求/响应。
abstract class BreakpointExternalHandler {
  Future<HttpRequest?> onRequestPaused(String requestId, HttpRequest request);

  Future<HttpResponse?> onResponsePaused(String requestId, HttpRequest request, HttpResponse response);

  void cancel(String requestId, {required bool response});
}

class RequestBreakpointInterceptor extends Interceptor {
  static RequestBreakpointInterceptor instance = RequestBreakpointInterceptor._();

  /// 由 MCP 服务启停时注册/注销；为空时保持原有 UI-only 行为
  static BreakpointExternalHandler? externalHandler;

  final manager = RequestBreakpointManager.instance;

  final ExpiringCache<String, Completer<HttpRequest?>> _pausedRequests = ExpiringCache(Duration(minutes: 10));
  final ExpiringCache<String, Completer<HttpResponse?>> _pausedResponses = ExpiringCache(Duration(minutes: 10));

  RequestBreakpointInterceptor._();

  /// 用环境变量渲染 {{name}}。若 EnvironmentManager 未加载或未启用,返回原字符串。
  static String? _renderEnv(String? input) => EnvironmentManager.tryRender(input);

  /// 渲染 headers 里所有值中的 {{var}}。多值 header(如 Set-Cookie)每个值独立渲染,不丢值。
  static void _renderHeadersInPlace(HttpHeaders headers) {
    if (EnvironmentManager.instanceOrNull?.enabled != true) return;
    // 先收集需要重写的 (name, renderedList),避免边遍历边改
    final rewrites = <String, List<String>>{};
    headers.forEach((name, values) {
      if (!values.any((v) => v.contains('{{'))) return;
      rewrites[name] = values.map((v) => _renderEnv(v) ?? v).toList();
    });
    // 用 remove + add 重建每个多值列表,保留全部值
    rewrites.forEach((name, values) {
      headers.remove(name);
      for (final v in values) {
        headers.add(name, v);
      }
    });
  }

  /// 渲染 body 里的 {{var}}。仅在 body 看起来是"较小的文本"时才尝试解码替换,
  /// 二进制/大 body/无变量占位时保持原字节不动,避免破坏和无谓的 decode 开销。
  static const int _renderBodyMaxSize = 512 * 1024; // 512KB 以上跳过

  /// 已知的二进制/非文本 MIME 前缀,遇到直接跳过 render
  static const List<String> _binaryContentTypes = [
    'image/',
    'video/',
    'audio/',
    'application/octet-stream',
    'application/zip',
    'application/x-protobuf',
    'application/x-msgpack',
    'application/pdf',
    'font/',
  ];

  static bool _looksBinary(String? contentType) {
    if (contentType == null || contentType.isEmpty) return false;
    final ct = contentType.toLowerCase();
    return _binaryContentTypes.any(ct.startsWith);
  }

  static List<int>? _renderBody(List<int>? body, String? charset, {String? contentType}) {
    if (body == null || body.isEmpty) return body;
    if (EnvironmentManager.instanceOrNull?.enabled != true) return body;
    if (body.length > _renderBodyMaxSize) return body;
    if (_looksBinary(contentType)) return body;
    try {
      final text = (charset == 'utf-8' || charset == 'utf8' || charset == null)
          ? utf8.decode(body)
          : String.fromCharCodes(body);
      if (!text.contains('{{')) return body;
      final rendered = _renderEnv(text) ?? text;
      return (charset == 'utf-8' || charset == 'utf8' || charset == null)
          ? utf8.encode(rendered)
          : rendered.codeUnits;
    } catch (_) {
      return body; // 非法文本,原样返回
    }
  }

  @override
  Future<HttpRequest?> onRequest(HttpRequest request) async {
    RequestBreakpointManager requestBreakpointManager = await manager;
    if (!requestBreakpointManager.enabled) return request;

    var url = request.requestUrl;
    for (var rule in requestBreakpointManager.list) {
      if (rule.match(url, method: request.method) && rule.interceptRequest) {
        Completer<HttpRequest?> completer = Completer();
        _pausedRequests[request.requestId] = completer;

        // Open Breakpoint Executor Window
        MultiWindow.openWindow("Breakpoint - Request", 'BreakpointExecutor',
            args: {'type': 'request', 'request': request.toJson(), 'requestId': request.requestId});

        return _awaitExternalRequest(request.requestId, request, completer).then((req) {
          if (req == null) {
            logger.d('Request ${request.requestId} was resumed null, aborting request');
            return null;
          }

          request.method = req.method;
          // 先渲染 URI 中的 {{var}}(如 host / path / query 里可能用到)
          final renderedUri = _renderEnv(req.uri) ?? req.uri;
          Uri uri = Uri.parse(renderedUri);
          if (uri.isScheme('https')) {
            request.uri = uri.path + (uri.hasQuery ? "?${uri.query}" : "");
          } else {
            request.uri = uri.toString();
          }

          request.headers.clear();
          request.headers.addAll(req.headers);
          _renderHeadersInPlace(request.headers);
          request.headers.remove(HttpHeaders.CONTENT_ENCODING);

          request.body = _renderBody(req.body, request.charset, contentType: request.headers.contentType);
          logger.d('Resuming request ${request.requestId} with modified request');
          return request;
        });
      }
    }
    return request;
  }

  @override
  Future<HttpResponse?> onResponse(HttpRequest request, HttpResponse response) async {
    RequestBreakpointManager requestBreakpointManager = await manager;
    if (!requestBreakpointManager.enabled) return response;

    var url = request.requestUrl;
    for (var rule in requestBreakpointManager.list) {
      if (rule.match(url, method: request.method) && rule.interceptResponse) {
        Completer<HttpResponse?> completer = Completer();
        _pausedResponses[request.requestId] = completer;

        // Open Breakpoint Executor Window
        MultiWindow.openWindow("Breakpoint - Response", 'BreakpointExecutor', args: {
          'type': 'response',
          'request': request.toJson(),
          'response': response.toJson(),
          'requestId': request.requestId
        });

        return _awaitExternalResponse(request.requestId, request, response, completer).then((res) {
          if (res == null) {
            return null;
          }

          response.status = res.status;
          response.headers.clear();
          response.headers.addAll(res.headers);
          _renderHeadersInPlace(response.headers);
          response.headers.remove(HttpHeaders.CONTENT_ENCODING);

          response.body = _renderBody(res.body, response.charset, contentType: response.headers.contentType);

          logger.d('Resuming response for request ${request.requestId} with modified response');
          return response;
        });
      }
    }
    return response;
  }

  /// 等待 UI 或外部处理器中的任意一方先给出结果。
  /// 外部处理器异常时按原样放行，不能让断点钩子把业务请求打断。
  Future<HttpRequest?> _awaitExternalRequest(
      String requestId, HttpRequest request, Completer<HttpRequest?> uiCompleter) async {
    var handler = externalHandler;
    if (handler == null) return uiCompleter.future;

    HttpRequest? result;
    try {
      result = await Future.any<HttpRequest?>([
        uiCompleter.future,
        handler.onRequestPaused(requestId, request).catchError((Object e, StackTrace st) {
          logger.e('External breakpoint handler failed for request $requestId', error: e, stackTrace: st);
          return request.copy();
        }),
      ]);
    } finally {
      _pausedRequests.remove(requestId);
      if (uiCompleter.isCompleted) {
        handler.cancel(requestId, response: false);
      } else {
        // 外部先处置：代为完成 UI completer，避免窗口/等待协程悬挂
        uiCompleter.complete(result);
      }
    }
    return result;
  }

  Future<HttpResponse?> _awaitExternalResponse(String requestId, HttpRequest request, HttpResponse response,
      Completer<HttpResponse?> uiCompleter) async {
    var handler = externalHandler;
    if (handler == null) return uiCompleter.future;

    HttpResponse? result;
    try {
      result = await Future.any<HttpResponse?>([
        uiCompleter.future,
        handler.onResponsePaused(requestId, request, response).catchError((Object e, StackTrace st) {
          logger.e('External breakpoint handler failed for response $requestId', error: e, stackTrace: st);
          return response.copy();
        }),
      ]);
    } finally {
      _pausedResponses.remove(requestId);
      if (uiCompleter.isCompleted) {
        handler.cancel(requestId, response: true);
      } else {
        uiCompleter.complete(result);
      }
    }
    return result;
  }

  void resumeRequest(String requestId, HttpRequest? request) {
    var completer = _pausedRequests.remove(requestId);
    if (completer != null && !completer.isCompleted) {
      completer.complete(request);
    }
  }

  void resumeResponse(String requestId, HttpResponse? response) {
    var completer = _pausedResponses.remove(requestId);
    if (completer != null && !completer.isCompleted) {
      completer.complete(response);
    }
  }
}
