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

import 'dart:convert';

import 'package:proxypin/network/http/http.dart';

/// 字段级数据流追踪：找出「某个响应里的值」后来出现在哪些请求里。
///
/// 典型用途是鉴权链分析：/login 返回 token → 后续请求的 Authorization/Cookie。
/// 纯只读，不修改任何流量；值只输出掩码片段。
///
/// @author wanghongen
class FieldFlowTracker {
  FieldFlowTracker._();

  static const int maxFlows = 300;
  static const int maxCandidates = 400;
  static const int maxEdges = 300;
  static const int maxValueLength = 512;
  static const int maxBodyBytes = 256 * 1024;
  static const int maxDepth = 3;

  static const Set<String> _ignoredResponseHeaders = {
    'content-type',
    'content-length',
    'content-encoding',
    'date',
    'server',
    'connection',
    'transfer-encoding',
    'keep-alive',
    'vary',
    'cache-control',
    'expires',
    'pragma',
    'via',
  };

  static const Set<String> _cookieAttributes = {
    'path',
    'domain',
    'expires',
    'max-age',
    'samesite',
    'secure',
    'httponly',
  };

  static const Set<String> _ignoredRequestHeaders = {
    'content-type',
    'content-length',
    'accept',
    'accept-encoding',
    'accept-language',
    'user-agent',
    'connection',
    'host',
    'content-encoding',
    'cache-control',
    'pragma',
    'upgrade-insecure-requests',
    'transfer-encoding',
  };

  static final RegExp _digits = RegExp(r'^\d+$');
  static final RegExp _trivial = RegExp(r'^(0|1|-1|true|false|null|none|ok)$', caseSensitive: false);
  static final RegExp _identityField =
      RegExp(r'(authorization|cookie|token|auth|session|uid|userid|user_id)', caseSensitive: false);
  static final RegExp _base64Chars = RegExp(r'^[A-Za-z0-9+/=_-]+$');

  /// 分析一组流量。[flows] 顺序不敏感，内部按请求时间升序处理。
  static Map<String, dynamic> trace(
    List<HttpRequest> flows, {
    int sessionLimit = 200,
    int minValueLen = 8,
  }) {
    var ordered = List<HttpRequest>.from(flows)
      ..sort((a, b) => a.requestTime.compareTo(b.requestTime));
    var total = ordered.length;
    if (ordered.length > sessionLimit) {
      ordered = ordered.sublist(ordered.length - sessionLimit);
    }

    var producers = <String, _Producer>{};
    var truncated = false;
    for (var index = 0; index < ordered.length; index++) {
      var candidates = <_Candidate>[];
      _collectResponseValues(ordered[index], candidates, minValueLen);
      for (var candidate in candidates) {
        if (producers.containsKey(candidate.value)) continue;
        if (producers.length >= maxCandidates) {
          truncated = true;
          break;
        }
        producers[candidate.value] = _Producer(index, candidate.field, candidate.value);
      }
    }

    var orderedCandidates = producers.values.toList()
      ..sort((a, b) => b.value.length.compareTo(a.value.length));

    var nodes = <String, Map<String, dynamic>>{};
    var edges = <String, Map<String, dynamic>>{};
    var consumerCache = <int, List<_ConsumerField>>{};

    for (var producer in orderedCandidates) {
      if (edges.length >= maxEdges) {
        truncated = true;
        break;
      }
      var sourceFlow = ordered[producer.flowIndex];
      var fromId = '${sourceFlow.requestId}:${producer.field}';

      for (var index = producer.flowIndex + 1; index < ordered.length; index++) {
        if (edges.length >= maxEdges) {
          truncated = true;
          break;
        }
        var consumerFlow = ordered[index];
        var fields = consumerCache.putIfAbsent(index, () => _requestFields(consumerFlow));
        for (var field in fields) {
          var match = _match(producer.value, field.value);
          if (match == null) continue;

          var toId = '${consumerFlow.requestId}:${field.name}';
          nodes.putIfAbsent(fromId, () => _producerNode(fromId, sourceFlow, producer));
          nodes.putIfAbsent(toId, () => _consumerNode(toId, consumerFlow, field));
          edges.putIfAbsent('$fromId>$toId', () => {
                'from': fromId,
                'to': toId,
                'confidence': match.confidence,
                'match': match.kind,
              });
          // 每个后续请求只记一条边，避免输出爆炸
          break;
        }
      }
    }

    var edgeList = edges.values.toList()
      ..sort((a, b) => (b['confidence'] as num).compareTo(a['confidence'] as num));
    var identitySeeds =
        edgeList.where((edge) => _identityField.hasMatch(edge['to'] as String)).toList();

    var entryPointIds = <String>{};
    for (var seed in identitySeeds) {
      var node = nodes[seed['from']];
      if (node != null) entryPointIds.add(node['flow'] as String);
    }

    return {
      'flowsAnalyzed': ordered.length,
      'totalFlows': total,
      'minValueLen': minValueLen,
      'candidateValues': producers.length,
      'nodes': nodes.values.toList(),
      'edges': edgeList,
      'identitySeeds': identitySeeds.take(50).toList(),
      'entryPoints': entryPointIds.toList(),
      'truncated': truncated,
      'note': 'An edge means a response value was found in a later request. '
          'Authorization/Cookie/token targets are in identitySeeds; '
          'contains matches on short values may be coincidental.',
    };
  }

  // ---------------------------------------------------------------- producers

  static void _collectResponseValues(
      HttpRequest flow, List<_Candidate> out, int minValueLen) {
    var response = flow.response;
    if (response == null) return;

    var body = _bodyText(response);
    if (body.isNotEmpty) {
      dynamic decoded;
      try {
        decoded = jsonDecode(body);
      } catch (_) {
        decoded = null;
      }
      if (decoded is Map || decoded is List) {
        _collectProducerLeaves(decoded, 'body', out, 0, minValueLen);
      }
    }

    response.headers.forEach((name, values) {
      var lower = name.toLowerCase();
      if (_ignoredResponseHeaders.contains(lower)) return;
      for (var value in values) {
        for (var part in _splitHeader(lower, value)) {
          _addCandidate(part, 'header.$name', out, minValueLen);
        }
      }
    });
  }

  static void _collectProducerLeaves(
      dynamic value, String prefix, List<_Candidate> out, int depth, int minValueLen) {
    if (depth > maxDepth) return;
    if (value is Map) {
      value.forEach((rawKey, child) {
        var key = prefix.isEmpty ? rawKey.toString() : '$prefix.$rawKey';
        _collectProducerLeaves(child, key, out, depth + 1, minValueLen);
      });
    } else if (value is List) {
      for (var item in value.take(10)) {
        _collectProducerLeaves(item, '$prefix[]', out, depth + 1, minValueLen);
      }
    } else if (value is String) {
      _addCandidate(value, prefix, out, minValueLen);
    } else if (value is num) {
      var text = value.toString();
      if (text.length >= 4) {
        _addCandidate(text, prefix, out, minValueLen, allowShortNumeric: true);
      }
    }
  }

  /// Set-Cookie 一条 header 里可能有多个属性，拆出 `name=value` 便于与请求 Cookie 匹配。
  static List<String> _splitHeader(String lowerName, String value) {
    if (lowerName != 'set-cookie') return [value];
    return value
        .split(';')
        .map((part) => part.trim())
        .where((part) => part.isNotEmpty && part.contains('='))
        .where((part) => !_cookieAttributes.contains(part.split('=').first.trim().toLowerCase()))
        .toList();
  }

  static void _addCandidate(String value, String field, List<_Candidate> out, int minValueLen,
      {bool allowShortNumeric = false}) {
    var trimmed = value.trim();
    if (trimmed.isEmpty || trimmed.length > maxValueLength) return;
    if (_trivial.hasMatch(trimmed)) return;
    var interesting =
        trimmed.length >= minValueLen || (allowShortNumeric && _digits.hasMatch(trimmed));
    if (!interesting) return;
    out.add(_Candidate(field, trimmed));
  }

  // ---------------------------------------------------------------- consumers

  static List<_ConsumerField> _requestFields(HttpRequest flow) {
    var fields = <_ConsumerField>[];
    flow.headers.forEach((name, values) {
      if (_ignoredRequestHeaders.contains(name.toLowerCase())) return;
      fields.add(_ConsumerField('header.$name', values.join(', ')));
    });
    flow.requestUri?.queryParameters.forEach((name, value) {
      fields.add(_ConsumerField('query.$name', value));
    });

    var body = _bodyText(flow);
    if (body.isNotEmpty) {
      dynamic decoded;
      try {
        decoded = jsonDecode(body);
      } catch (_) {
        decoded = null;
      }
      if (decoded is Map || decoded is List) {
        _collectConsumerLeaves(decoded, 'body', fields, 0);
      } else {
        fields.add(_ConsumerField('body', body));
      }
    }
    return fields;
  }

  static void _collectConsumerLeaves(
      dynamic value, String prefix, List<_ConsumerField> out, int depth) {
    if (depth > maxDepth) return;
    if (value is Map) {
      value.forEach((rawKey, child) {
        var key = prefix.isEmpty ? rawKey.toString() : '$prefix.$rawKey';
        _collectConsumerLeaves(child, key, out, depth + 1);
      });
    } else if (value is List) {
      for (var item in value.take(10)) {
        _collectConsumerLeaves(item, '$prefix[]', out, depth + 1);
      }
    } else if (value != null) {
      out.add(_ConsumerField(prefix.isEmpty ? 'body' : prefix, value.toString()));
    }
  }

  // ---------------------------------------------------------------- matching

  static _Match? _match(String candidate, String value) {
    if (value == candidate) return const _Match('exact', 1.0);
    if (value.contains(candidate)) return const _Match('contains', 0.85);
    if (value.length > maxValueLength * 2) return null;

    if (value.contains('%')) {
      try {
        if (Uri.decodeComponent(value) == candidate) return const _Match('urlencoded', 0.95);
      } catch (_) {
        // 非法百分号序列忽略
      }
    }

    if (value.length >= 16 && value.length % 4 == 0 && _base64Chars.hasMatch(value)) {
      try {
        var decoded = utf8.decode(base64.decode(value.replaceAll('-', '+').replaceAll('_', '/')));
        if (decoded == candidate) return const _Match('base64', 0.9);
      } catch (_) {
        // 不是 base64，忽略
      }
    }
    return null;
  }

  // ---------------------------------------------------------------- output

  static Map<String, dynamic> _producerNode(String id, HttpRequest flow, _Producer producer) => {
        'id': id,
        'flow': flow.requestId,
        'path': flow.path,
        'role': 'producer',
        'field': producer.field,
        'sample': _mask(producer.value),
        'valueLength': producer.value.length,
        'time': flow.requestTime.toUtc().toIso8601String(),
      };

  static Map<String, dynamic> _consumerNode(
          String id, HttpRequest flow, _ConsumerField field) =>
      {
        'id': id,
        'flow': flow.requestId,
        'path': flow.path,
        'role': 'consumer',
        'method': flow.method.name.toUpperCase(),
        'field': field.name,
        'sample': _mask(field.value),
        'time': flow.requestTime.toUtc().toIso8601String(),
      };

  static String _mask(String value) {
    if (value.length <= 8) return value;
    return '${value.substring(0, 4)}…${value.substring(value.length - 4)}';
  }

  static String _bodyText(HttpMessage message) {
    var body = message.body;
    if (body == null || body.isEmpty || body.length > maxBodyBytes) return '';
    try {
      return message.getBodyString();
    } catch (_) {
      return '';
    }
  }
}

class _Candidate {
  final String field;
  final String value;

  _Candidate(this.field, this.value);
}

class _Producer {
  final int flowIndex;
  final String field;
  final String value;

  _Producer(this.flowIndex, this.field, this.value);
}

class _ConsumerField {
  final String name;
  final String value;

  _ConsumerField(this.name, this.value);
}

class _Match {
  final String kind;
  final double confidence;

  const _Match(this.kind, this.confidence);
}
