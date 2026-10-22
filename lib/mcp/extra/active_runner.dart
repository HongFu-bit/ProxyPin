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
import 'dart:math';

import 'package:proxypin/network/bin/server.dart';
import 'package:proxypin/network/channel/host_port.dart';
import 'package:proxypin/network/http/http.dart';
import 'package:proxypin/network/http/http_client.dart';

/// 主动测试基础设施：发包、限速、参数变异。
///
/// 所有请求都走当前运行中的代理（未运行时直连），因此会被自带的断点/重写规则处理，
/// 与 `replay_flow` 行为一致。
class ActiveRunner {
  ActiveRunner._();

  static const int previewChars = 200;

  /// 发送一条请求；网络错误不抛出，作为 [ActiveResult.error] 返回，便于批量比较。
  static Future<ActiveResult> send(
    HttpRequest request, {
    Duration timeout = const Duration(seconds: 30),
  }) async {
    ProxyInfo? proxyInfo;
    var server = ProxyServer.current;
    if (server != null && server.isRunning) {
      proxyInfo = ProxyInfo.of('127.0.0.1', server.port);
    }

    var watch = Stopwatch()..start();
    try {
      var response =
          await HttpClients.proxyRequest(request, proxyInfo: proxyInfo).timeout(timeout);
      watch.stop();
      var text = _bodyText(response);
      return ActiveResult(
        status: response.status.code,
        statusText: response.status.reasonPhrase,
        size: response.body?.length ?? 0,
        elapsedMs: watch.elapsedMilliseconds,
        preview: _preview(text),
      );
    } catch (e) {
      watch.stop();
      return ActiveResult(
        size: 0,
        elapsedMs: watch.elapsedMilliseconds,
        preview: '',
        error: e.toString(),
      );
    }
  }

  static String _bodyText(HttpResponse response) {
    try {
      return response.getBodyString();
    } catch (_) {
      return '';
    }
  }

  static String _preview(String text) {
    if (text.isEmpty) return '';
    if (text.length <= previewChars) return text;
    return text.substring(0, previewChars);
  }
}

class ActiveResult {
  final int? status;
  final String? statusText;
  final int size;
  final int elapsedMs;
  final String preview;
  final String? error;

  const ActiveResult({
    this.status,
    this.statusText,
    required this.size,
    required this.elapsedMs,
    required this.preview,
    this.error,
  });

  bool get isSuccess => status != null && status! >= 200 && status! < 300;
}

/// 简单令牌桶：保证请求间隔不小于 [interval]，避免把目标打挂。
class RateGate {
  final Duration interval;
  DateTime _next = DateTime.fromMillisecondsSinceEpoch(0);

  RateGate(int maxQps) : interval = Duration(microseconds: (1000000 / max(1, maxQps)).round());

  Future<void> acquire() async {
    var now = DateTime.now();
    var at = _next.isAfter(now) ? _next : now;
    _next = at.add(interval);
    var wait = at.difference(now);
    if (wait > Duration.zero) await Future<void>.delayed(wait);
  }
}

class MutationResult {
  final HttpRequest request;
  final String location;
  final String oldValue;
  final String param;

  const MutationResult(this.request, this.location, this.param, this.oldValue);
}

/// 把某个参数替换成 payload，支持 query / JSON body / form body / header。
class RequestMutator {
  static const List<String> locations = ['auto', 'query', 'json', 'form', 'header'];

  static MutationResult? apply(
    HttpRequest base,
    String param,
    String payload, {
    String location = 'auto',
  }) {
    if (param.isEmpty) return null;
    if (location == 'query' || location == 'auto') {
      var result = _query(base, param, payload);
      if (result != null || location == 'query') return result;
    }
    if (location == 'json' || location == 'auto') {
      var result = _json(base, param, payload);
      if (result != null || location == 'json') return result;
    }
    if (location == 'form' || location == 'auto') {
      var result = _form(base, param, payload);
      if (result != null || location == 'form') return result;
    }
    if (location == 'header' || location == 'auto') {
      return _header(base, param, payload);
    }
    return null;
  }

  static MutationResult? _query(HttpRequest base, String param, String payload) {
    var uri = base.requestUri;
    if (uri == null || !uri.queryParameters.containsKey(param)) return null;
    var oldValue = uri.queryParameters[param] ?? '';
    var query = Map<String, String>.from(uri.queryParameters)..[param] = payload;
    var target = uri.replace(queryParameters: query);
    var copy = base.copy(uri: target.toString());
    copy.hostAndPort = HostAndPort.of(target.toString());
    return MutationResult(copy, 'query', param, oldValue);
  }

  static MutationResult? _json(HttpRequest base, String param, String payload) {
    var contentType = base.headers.get('content-type')?.toLowerCase() ?? '';
    var text = _bodyText(base);
    var trimmed = text.trimLeft();
    var looksJson = contentType.contains('json') || trimmed.startsWith('{') || trimmed.startsWith('[');
    if (!looksJson || trimmed.isEmpty) return null;

    dynamic decoded;
    try {
      decoded = jsonDecode(text);
    } catch (_) {
      return null;
    }
    if (decoded is! Map) return null;

    var path = param.split('.');
    var old = _getPath(decoded, path);
    if (identical(old, _missing)) return null;
    _setPath(decoded, path, payload);

    var copy = base.copy();
    copy.body = utf8.encode(jsonEncode(decoded));
    return MutationResult(copy, 'json', param, old?.toString() ?? '');
  }

  static MutationResult? _form(HttpRequest base, String param, String payload) {
    var contentType = base.headers.get('content-type')?.toLowerCase() ?? '';
    if (!contentType.contains('x-www-form-urlencoded')) return null;

    var text = _bodyText(base);
    if (text.isEmpty) return null;

    String? oldValue;
    var pairs = text.split('&').map((pair) {
      var index = pair.indexOf('=');
      var rawKey = index < 0 ? pair : pair.substring(0, index);
      String key;
      try {
        key = Uri.decodeQueryComponent(rawKey);
      } catch (_) {
        key = rawKey;
      }
      if (key != param) return pair;
      oldValue = index < 0 ? '' : Uri.decodeQueryComponent(pair.substring(index + 1));
      return '${Uri.encodeQueryComponent(key)}=${Uri.encodeQueryComponent(payload)}';
    }).toList();

    if (oldValue == null) return null;
    var copy = base.copy();
    copy.body = utf8.encode(pairs.join('&'));
    return MutationResult(copy, 'form', param, oldValue!);
  }

  static MutationResult? _header(HttpRequest base, String param, String payload) {
    var oldValue = base.headers.get(param);
    if (oldValue == null) return null;
    var copy = base.copy();
    copy.headers.set(param, payload);
    return MutationResult(copy, 'header', param, oldValue);
  }

  static const Object _missing = Object();

  static Object? _getPath(dynamic node, List<String> path) {
    var current = node;
    for (var key in path) {
      if (current is! Map || !current.containsKey(key)) return _missing;
      current = current[key];
    }
    return current;
  }

  static void _setPath(dynamic node, List<String> path, String payload) {
    var current = node;
    for (var i = 0; i < path.length - 1; i++) {
      current = current[path[i]];
    }
    var key = path.last;
    current[key] = _coerce(payload, current[key]);
  }

  /// payload 是用户给的字符串，按原字段类型还原，避免把数字写成 "123"。
  static dynamic _coerce(String payload, dynamic original) {
    if (original is bool && (payload == 'true' || payload == 'false')) {
      return payload == 'true';
    }
    if (original is int) {
      var value = num.tryParse(payload);
      if (value != null) return value == value.truncateToDouble() ? value.toInt() : value;
    }
    if (original is double) {
      var value = num.tryParse(payload);
      if (value != null) return value.toDouble();
    }
    return payload;
  }

  static String _bodyText(HttpRequest request) {
    try {
      return request.getBodyString();
    } catch (_) {
      return '';
    }
  }
}

/// 结果统计：把一批响应压成状态分布 + 异常项，不直接下漏洞结论。
class ResponseStats {
  ResponseStats._();

  static Map<String, dynamic> summarize(
    List<ActiveResult> results, {
    required double skewMs,
    required int maxSkewMs,
  }) {
    var distribution = <String, int>{};
    for (var result in results) {
      var key = result.status?.toString() ?? 'error';
      distribution[key] = (distribution[key] ?? 0) + 1;
    }
    var modeStatus = distribution.entries.reduce((a, b) => b.value > a.value ? b : a).key;

    var sizes = results.where((r) => r.status != null).map((r) => r.size).toList()..sort();
    var medianSize = sizes.isEmpty ? 0 : sizes[sizes.length ~/ 2];

    var anomalies = <Map<String, dynamic>>[];
    for (var i = 0; i < results.length; i++) {
      var result = results[i];
      String? note;
      if (result.error != null) {
        note = 'request failed: ${result.error}';
      } else if ('${result.status}' != modeStatus) {
        note = 'status ${result.status} differs from the most common ($modeStatus)';
      } else if (result.isSuccess && medianSize > 0 && (result.size - medianSize).abs() > medianSize ~/ 2) {
        note = 'body size deviates from median ($medianSize) by more than 50%';
      }
      if (note != null) {
        anomalies.add({
          'index': i,
          'status': result.status,
          'size': result.size,
          'elapsedMs': result.elapsedMs,
          'note': note,
        });
      }
    }

    var verdict = skewMs > maxSkewMs * 2
        ? 'inconclusive'
        : (anomalies.isEmpty ? 'uniform' : 'suspect');
    return {
      'sent': results.length,
      'actualSkewMs': double.parse(skewMs.toStringAsFixed(2)),
      'statusDistribution': distribution,
      'medianSize': medianSize,
      'anomalies': anomalies,
      'verdict': verdict,
      'note': 'Deviations are hints, not proof of a race condition. Re-run with a larger sample before concluding.',
    };
  }
}
