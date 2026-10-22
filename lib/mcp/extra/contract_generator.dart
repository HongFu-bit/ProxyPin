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

import 'package:proxypin/mcp/capture/curl_builder.dart';
import 'package:proxypin/network/http/http.dart';

/// 从已抓流量生成接口契约（OpenAPI 3.0 / TypeScript 接口 / cURL 集合）。
///
/// 纯只读推断：相同 method + 归一化 path 归为一个端点；字段类型按样本统计，
/// 所有样本都出现的字段标为 required；只输出结构，不输出参数值。
///
/// @author wanghongen
class ContractGenerator {
  ContractGenerator._();

  static const int maxEndpoints = 50;
  static const int maxBodyBytes = 256 * 1024;
  static const List<String> formats = ['openapi', 'typescript', 'curl'];

  static final RegExp _numericSegment = RegExp(r'^\d+$');
  static final RegExp _uuidSegment = RegExp(
      r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$');
  static final RegExp _longHexSegment = RegExp(r'^[0-9a-fA-F]{16,}$');
  static final RegExp _pathParam = RegExp(r'\{([^}]+)\}');

  /// 生成契约。[flows] 可来自实时缓冲或历史会话，顺序不敏感。
  static Map<String, dynamic> generate(
    List<HttpRequest> flows, {
    String host = '',
    int minSamples = 2,
    String format = 'openapi',
    bool redact = true,
  }) {
    var groups = <String, List<HttpRequest>>{};
    for (var flow in flows) {
      var path = _normalizePath(flow.path);
      var key = '${flow.method.name.toUpperCase()} $path';
      (groups[key] ??= <HttpRequest>[]).add(flow);
    }

    var endpoints = <_Endpoint>[];
    var skipped = 0;
    for (var entry in groups.entries) {
      if (endpoints.length >= maxEndpoints) break;
      var samples = entry.value;
      if (samples.length < minSamples) {
        skipped++;
        continue;
      }
      var space = entry.key.indexOf(' ');
      endpoints.add(_Endpoint(
        method: entry.key.substring(0, space),
        path: entry.key.substring(space + 1),
        samples: samples,
      ));
    }

    var summaries = <Map<String, dynamic>>[];
    var pathItems = <String, Map<String, dynamic>>{};
    var typescript = StringBuffer();
    var curls = <String>[];

    for (var endpoint in endpoints) {
      var stats = _analyze(endpoint);
      summaries.add(stats.summary);

      switch (format) {
        case 'typescript':
          typescript.writeln(_typescript(endpoint, stats));
          break;
        case 'curl':
          var newest =
              endpoint.samples.reduce((a, b) => a.requestTime.isAfter(b.requestTime) ? a : b);
          curls.add(CurlBuilder.build(newest, redact: redact));
          break;
        default:
          var operation = _openApiOperation(endpoint, stats);
          (pathItems[endpoint.path] ??= <String, dynamic>{})[endpoint.method.toLowerCase()] =
              operation;
          break;
      }
    }

    dynamic contract;
    if (format == 'openapi') {
      var serverUrl = _serverUrl(flows);
      contract = {
        'openapi': '3.0.3',
        'info': {'title': host.isEmpty ? 'captured-traffic' : host, 'version': '1.0.0'},
        if (serverUrl != null) 'servers': [{'url': serverUrl}],
        'paths': pathItems,
      };
    } else if (format == 'typescript') {
      contract = typescript.toString();
    } else {
      contract = curls.join('\n\n');
    }

    return {
      'host': host,
      'format': format,
      'samples': flows.length,
      'endpointCount': endpoints.length,
      if (skipped > 0) 'skippedLowSample': skipped,
      'endpoints': summaries,
      'contract': contract,
      'note': 'required means present in every sample; parameter values are omitted on purpose. '
          'Fields named sign/hash may be signatures — use analyze_signature on those endpoints.',
    };
  }

  // ---------------------------------------------------------------- stats

  static _EndpointStats _analyze(_Endpoint endpoint) {
    var sampleCount = endpoint.samples.length;
    var query = <String, _FieldAcc>{};
    var body = <String, _FieldAcc>{};
    var responseFields = <String, _FieldAcc>{};
    var statusCodes = <int>{};
    var responseSamples = 0;
    String? mime;
    var formEncoded = false;
    var jsonBody = false;

    for (var sample in endpoint.samples) {
      sample.requestUri?.queryParameters.forEach((name, value) {
        query.putIfAbsent(name, () => _FieldAcc()).addPrimitive(value);
      });

      var bodyText = _bodyText(sample);
      if (bodyText.isNotEmpty) {
        dynamic decoded;
        try {
          decoded = jsonDecode(bodyText);
          jsonBody = true;
        } catch (_) {
          decoded = null;
        }
        if (decoded == null &&
            (sample.headers.contentType.toLowerCase().contains('x-www-form-urlencoded') ||
                _looksForm(bodyText))) {
          try {
            decoded = Uri.splitQueryString(bodyText);
            formEncoded = true;
          } catch (_) {
            decoded = null;
          }
        }
        if (decoded is Map) _collectFields(decoded, '', body, 0);
      }

      var response = sample.response;
      if (response == null) continue;
      statusCodes.add(response.status.code);
      if (mime == null) {
        var contentType = response.headers.contentType;
        if (contentType.isNotEmpty) mime = contentType.split(';').first.trim();
      }
      var responseText = _bodyText(response);
      if (responseText.isEmpty) continue;
      try {
        var decoded = jsonDecode(responseText);
        if (decoded is Map) {
          responseSamples++;
          _collectFields(decoded, '', responseFields, 0);
        }
      } catch (_) {
        // 非 JSON 响应没有可推断的结构
      }
    }

    return _EndpointStats(
      sampleCount: sampleCount,
      query: query,
      body: body,
      response: responseFields,
      responseSamples: responseSamples,
      statusCodes: statusCodes.toList()..sort(),
      mime: mime,
      formEncoded: formEncoded,
      jsonBody: jsonBody,
      summary: {
        'method': endpoint.method,
        'path': endpoint.path,
        'samples': sampleCount,
        'statusCodes': statusCodes.toList()..sort(),
        'queryFields': query.length,
        'bodyFields': body.length,
        'responseFields': responseFields.length,
      },
    );
  }

  // ---------------------------------------------------------------- openapi

  static Map<String, dynamic> _openApiOperation(_Endpoint endpoint, _EndpointStats stats) {
    var parameters = <Map<String, dynamic>>[];
    for (var name in _pathParam.allMatches(endpoint.path).map((m) => m.group(1)!)) {
      parameters.add({
        'name': name,
        'in': 'path',
        'required': true,
        'schema': {'type': 'string'},
      });
    }
    stats.query.forEach((name, acc) {
      parameters.add({
        'name': name,
        'in': 'query',
        'required': acc.count >= stats.sampleCount,
        'schema': _scalarSchema(acc),
      });
    });

    Map<String, dynamic>? responseSchema;
    if (stats.response.isNotEmpty) {
      responseSchema =
          _schemaObject(_buildTree(stats.response, stats.responseSamples), stats.responseSamples);
    }

    var responses = <String, dynamic>{};
    for (var code in stats.statusCodes) {
      responses['$code'] = {
        'description': _statusText(code),
        if (responseSchema != null)
          'content': {
            (stats.mime ?? 'application/json'): {'schema': responseSchema},
          },
      };
    }
    if (responses.isEmpty) {
      responses['default'] = {'description': 'No response captured'};
    }

    return {
      'operationId': _operationId(endpoint.method, endpoint.path),
      'summary': 'Observed ${stats.sampleCount} time(s) in captured traffic',
      if (parameters.isNotEmpty) 'parameters': parameters,
      if (stats.body.isNotEmpty)
        'requestBody': {
          'required': true,
          'content': {
            (stats.formEncoded && !stats.jsonBody
                ? 'application/x-www-form-urlencoded'
                : 'application/json'): {
              'schema': _schemaObject(_buildTree(stats.body, stats.sampleCount), stats.sampleCount),
            },
          },
        },
      'responses': responses,
    };
  }

  // ---------------------------------------------------------------- typescript

  static String _typescript(_Endpoint endpoint, _EndpointStats stats) {
    var base = _pascal('${endpoint.method} ${endpoint.path}');
    var buffer = StringBuffer();
    buffer.writeln('// ${endpoint.method} ${endpoint.path} — ${stats.sampleCount} sample(s)');
    if (stats.query.isNotEmpty) {
      buffer.writeln(_tsInterface('${base}Query', stats.query, stats.sampleCount));
    }
    if (stats.body.isNotEmpty) {
      buffer.writeln(_tsInterface('${base}Request', stats.body, stats.sampleCount));
    }
    if (stats.response.isNotEmpty) {
      buffer.writeln(_tsInterface('${base}Response', stats.response, stats.responseSamples));
    }
    return buffer.toString();
  }

  static String _tsInterface(String name, Map<String, _FieldAcc> fields, int sampleCount) {
    var root = _buildTree(fields, sampleCount);
    var buffer = StringBuffer('export interface $name {\n');
    root.children.forEach((key, child) {
      var optional = sampleCount > 0 && child.count < sampleCount ? '?' : '';
      buffer.writeln('  ${_tsKey(key)}$optional: ${_tsType(child, sampleCount)};');
    });
    buffer.write('}');
    return buffer.toString();
  }

  static String _tsType(_SchemaNode node, int sampleCount) {
    if (node.array) {
      if (node.children.isEmpty) {
        var itemType = node.itemTypes.length == 1 ? node.itemTypes.first : 'string';
        return '${_tsScalar(itemType)}[]';
      }
      return '${_tsInline(node, sampleCount)}[]';
    }
    if (node.children.isNotEmpty) return _tsInline(node, sampleCount);
    var enumValues = node.enumValues;
    if (enumValues != null && node.scalarType == 'string') {
      return enumValues.map((value) => "'${value.replaceAll("'", "\\'")}'").join(' | ');
    }
    return _tsScalar(node.scalarType ?? 'string');
  }

  static String _tsInline(_SchemaNode node, int sampleCount) {
    var buffer = StringBuffer('{\n');
    node.children.forEach((key, child) {
      var optional = sampleCount > 0 && child.count < sampleCount ? '?' : '';
      buffer.writeln('    ${_tsKey(key)}$optional: ${_tsType(child, sampleCount)};');
    });
    buffer.write('  }');
    return buffer.toString();
  }

  static String _tsScalar(String? type) {
    switch (type) {
      case 'integer':
      case 'number':
        return 'number';
      case 'boolean':
        return 'boolean';
      default:
        return 'string';
    }
  }

  static String _tsKey(String name) =>
      RegExp(r'^[A-Za-z_$][A-Za-z0-9_$]*$').hasMatch(name) ? name : jsonEncode(name);

  // ---------------------------------------------------------------- schema

  static void _collectFields(
      dynamic value, String prefix, Map<String, _FieldAcc> acc, int depth) {
    if (depth > 3 || value is! Map) return;
    value.forEach((rawKey, fieldValue) {
      var key = prefix.isEmpty ? rawKey.toString() : '$prefix.$rawKey';
      var field = acc.putIfAbsent(key, () => _FieldAcc());
      field.count++;
      if (fieldValue is Map) {
        field.object = true;
        _collectFields(fieldValue, key, acc, depth + 1);
      } else if (fieldValue is List) {
        field.array = true;
        for (var item in fieldValue.take(10)) {
          field.itemTypes.add(_valueType(item));
          if (item is Map) {
            field.object = true;
            _collectFields(item, '$key[]', acc, depth + 1);
          }
        }
      } else {
        field.primitives.add(fieldValue);
      }
    });
  }

  static _SchemaNode _buildTree(Map<String, _FieldAcc> fields, int sampleCount) {
    var root = _SchemaNode();
    fields.forEach((path, acc) {
      var node = root;
      for (var segment in path.split('.')) {
        var isArray = segment.endsWith('[]');
        var name = isArray ? segment.substring(0, segment.length - 2) : segment;
        if (name.isEmpty) continue;
        var child = node.children.putIfAbsent(name, () => _SchemaNode());
        if (isArray) child.array = true;
        node = child;
      }
      node.count = acc.count;
      node.object = node.object || acc.object;
      node.array = node.array || acc.array;
      node.scalarType = _inferType(acc);
      node.enumValues = _enumOf(acc);
      node.itemTypes = acc.itemTypes;
    });
    return root;
  }

  static Map<String, dynamic> _schemaObject(_SchemaNode node, int sampleCount) {
    var properties = <String, dynamic>{};
    var required = <String>[];
    node.children.forEach((name, child) {
      properties[name] = _schema(child, sampleCount);
      if (sampleCount > 0 && child.count >= sampleCount) required.add(name);
    });
    return {
      'type': 'object',
      'properties': properties,
      if (required.isNotEmpty) 'required': required,
    };
  }

  static Map<String, dynamic> _schema(_SchemaNode node, int sampleCount) {
    if (node.array) {
      Map<String, dynamic> items;
      if (node.children.isNotEmpty) {
        items = _schemaObject(node, sampleCount);
      } else {
        items = {'type': node.itemTypes.length == 1 ? node.itemTypes.first : 'string'};
      }
      return {'type': 'array', 'items': items};
    }
    if (node.children.isNotEmpty) return _schemaObject(node, sampleCount);
    var schema = <String, dynamic>{'type': node.scalarType ?? 'string'};
    if (node.enumValues != null && node.scalarType != 'boolean') {
      schema['enum'] = node.enumValues;
    }
    return schema;
  }

  static Map<String, dynamic> _scalarSchema(_FieldAcc acc) {
    var schema = <String, dynamic>{'type': _inferType(acc)};
    var enumValues = _enumOf(acc);
    if (enumValues != null) schema['enum'] = enumValues;
    return schema;
  }

  static String _inferType(_FieldAcc acc) {
    if (acc.array) return 'array';
    if (acc.object) return 'object';
    var values = acc.primitives.where((value) => value != null).toList();
    if (values.isEmpty) return 'string';
    if (values.every((value) => value is bool || _isBoolString(value))) return 'boolean';
    if (values.every((value) => value is int || _isIntString(value))) return 'integer';
    if (values.every((value) => value is num || _isNumberString(value))) return 'number';
    return 'string';
  }

  static List<String>? _enumOf(_FieldAcc acc) {
    var distinct = <String>{};
    for (var value in acc.primitives) {
      if (value == null) continue;
      distinct.add(value.toString());
      if (distinct.length > 5) return null;
    }
    if (distinct.isEmpty) return null;
    return distinct.toList()..sort();
  }

  static String _valueType(dynamic value) {
    if (value is bool) return 'boolean';
    if (value is int) return 'integer';
    if (value is num) return 'number';
    if (value is Map) return 'object';
    if (value is List) return 'array';
    return 'string';
  }

  static bool _isBoolString(dynamic value) =>
      value is String && (value == 'true' || value == 'false');

  static bool _isIntString(dynamic value) => value is String && int.tryParse(value) != null;

  static bool _isNumberString(dynamic value) => value is String && num.tryParse(value) != null;

  // ---------------------------------------------------------------- misc

  static String _normalizePath(String path) {
    if (path.isEmpty) return '/';
    var segments = path.split('/');
    var idCount = 0;
    for (var i = 0; i < segments.length; i++) {
      if (!_isIdSegment(segments[i])) continue;
      idCount++;
      segments[i] = idCount == 1 ? '{id}' : '{id$idCount}';
    }
    return segments.join('/');
  }

  static bool _isIdSegment(String segment) =>
      segment.isNotEmpty &&
      (_numericSegment.hasMatch(segment) ||
          _uuidSegment.hasMatch(segment) ||
          _longHexSegment.hasMatch(segment));

  static String _operationId(String method, String path) {
    var cleaned = path.replaceAll(_pathParam, ' id ').replaceAll(RegExp(r'[^A-Za-z0-9]+'), ' ');
    var parts = [method.toLowerCase(), ...cleaned.split(' ').where((part) => part.isNotEmpty)];
    var name = parts.first + parts.skip(1).map(_capitalize).join();
    return RegExp(r'^[A-Za-z_]').hasMatch(name) ? name : 'op$name';
  }

  static String _pascal(String input) {
    var parts = input.split(RegExp(r'[^A-Za-z0-9]+')).where((part) => part.isNotEmpty);
    var name = parts.map(_capitalize).join();
    if (name.isEmpty) return 'Endpoint';
    return RegExp(r'^[A-Za-z_]').hasMatch(name) ? name : 'E$name';
  }

  static String _capitalize(String value) =>
      value.isEmpty ? value : value[0].toUpperCase() + value.substring(1).toLowerCase();

  static String _statusText(int code) {
    switch (code) {
      case 200:
        return 'OK';
      case 201:
        return 'Created';
      case 204:
        return 'No Content';
      case 301:
        return 'Moved Permanently';
      case 302:
        return 'Found';
      case 400:
        return 'Bad Request';
      case 401:
        return 'Unauthorized';
      case 403:
        return 'Forbidden';
      case 404:
        return 'Not Found';
      case 429:
        return 'Too Many Requests';
      case 500:
        return 'Internal Server Error';
      case 502:
        return 'Bad Gateway';
      case 503:
        return 'Service Unavailable';
      default:
        return 'HTTP $code';
    }
  }

  static String? _serverUrl(List<HttpRequest> flows) {
    for (var flow in flows) {
      var uri = flow.requestUri;
      if (uri != null && uri.host.isNotEmpty) {
        return '${uri.scheme}://${uri.host}${uri.hasPort ? ':${uri.port}' : ''}';
      }
    }
    return null;
  }

  static bool _looksForm(String text) {
    var trimmed = text.trim();
    return trimmed.contains('=') && !trimmed.startsWith('{') && !trimmed.startsWith('[');
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

class _Endpoint {
  final String method;
  final String path;
  final List<HttpRequest> samples;

  _Endpoint({required this.method, required this.path, required this.samples});
}

class _EndpointStats {
  final int sampleCount;
  final Map<String, _FieldAcc> query;
  final Map<String, _FieldAcc> body;
  final Map<String, _FieldAcc> response;
  final int responseSamples;
  final List<int> statusCodes;
  final String? mime;
  final bool formEncoded;
  final bool jsonBody;
  final Map<String, dynamic> summary;

  _EndpointStats({
    required this.sampleCount,
    required this.query,
    required this.body,
    required this.response,
    required this.responseSamples,
    required this.statusCodes,
    required this.mime,
    required this.formEncoded,
    required this.jsonBody,
    required this.summary,
  });
}

class _FieldAcc {
  int count = 0;
  bool object = false;
  bool array = false;
  final List<dynamic> primitives = [];
  final Set<String> itemTypes = {};

  void addPrimitive(dynamic value) {
    count++;
    primitives.add(value);
  }
}

class _SchemaNode {
  final Map<String, _SchemaNode> children = {};
  int count = 0;
  bool object = false;
  bool array = false;
  String? scalarType;
  List<String>? enumValues;
  Set<String> itemTypes = {};
}
