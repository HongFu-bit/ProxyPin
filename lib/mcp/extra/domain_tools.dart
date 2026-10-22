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
import 'dart:typed_data';

import 'package:pointycastle/export.dart' show Digest, HMac, KeyParameter;

import 'package:proxypin/mcp/capture/sensitive_data.dart';
import 'package:proxypin/mcp/protocol/mcp_tool.dart';
import 'package:proxypin/network/bin/server.dart';
import 'package:proxypin/network/channel/host_port.dart';
import 'package:proxypin/network/components/crypto_transparent.dart';
import 'package:proxypin/network/http/http.dart';
import 'package:proxypin/network/http/http_client.dart';
import 'package:proxypin/network/util/crypto.dart';

import 'signature_analyzer.dart';

/// 按域名生成「语义工具」：把抓到的端点变成可直接调用的 MCP 工具。
///
/// 每个工具复用一条样板的 URL / 头 / body 结构，调用参数覆盖其中的 query 或
/// JSON/form 字段，然后真的发一次请求并返回解析后的响应。签名只在能可靠复算时
/// 才做（`signatureProfile: "auto"` 的推断结果），其余情况原样复用样板签名。
///
/// 关键限制（会写进工具描述与返回的 warnings）：
/// - 生成的工具会发送真实流量；
/// - 样板里的 Cookie / Authorization 原样复用，所以只能操作同一账号；
/// - 签名算法未知时，改参数后服务端大概率拒绝；
/// - 透明加密档只用于解密响应，是否加密请求由该档自身的 applyTo 决定。
class DomainToolGenerator {
  DomainToolGenerator._();

  static const int defaultMaxTools = 40;
  static const int maxSamplesPerEndpoint = 20;
  static const int maxResponseChars = 20000;
  static const int signatureSampleLimit = 10;

  static final RegExp _numeric = RegExp(r'^\d{1,18}$');
  static final RegExp _uuid = RegExp(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$');
  static final RegExp _longHex = RegExp(r'^[0-9a-fA-F]{16,}$');
  static final RegExp _placeholder = RegExp(r'\{([^}]+)\}');
  static final RegExp _nonSlug = RegExp(r'[^a-z0-9]+');

  static const Set<String> _ignoredSegments = {
    'api', 'rest', 'rpc', 'gateway', 'internal', 'openapi', 'web', 'service', 'services'
  };

  static const Set<String> _sensitiveQuery = {
    'token',
    'access_token',
    'refresh_token',
    'auth',
    'authorization',
    'sign',
    'signature',
    'key',
    'apikey',
    'api_key',
    'secret',
    'password',
    'passwd',
    'pwd',
  };

  /// 生成工具；调用方负责把 [DomainToolsResult.tools] 注册进 MCP server。
  static Future<DomainToolsResult> build(
    List<HttpRequest> flows, {
    required String host,
    String? registerAs,
    String? cryptoProfile,
    Object? signatureProfile,
    Set<String>? methods,
    int maxTools = defaultMaxTools,
  }) async {
    await CryptoProfileStore.instance.ensureLoaded();
    var warnings = <String>[];
    var endpoints = _endpoints(flows, methods: methods, warnings: warnings);
    if (endpoints.isEmpty) {
      return DomainToolsResult(
        tools: const [],
        endpoints: const [],
        warnings: [...warnings, 'no suitable captured endpoints for "$host"'],
        prefix: _prefix(host, registerAs),
      );
    }

    endpoints.sort((a, b) {
      var bySamples = b.samples.length.compareTo(a.samples.length);
      return bySamples != 0 ? bySamples : a.pattern.compareTo(b.pattern);
    });
    if (endpoints.length > maxTools) {
      warnings.add('${endpoints.length - maxTools} endpoints skipped (limit $maxTools)');
      endpoints = endpoints.sublist(0, maxTools);
    }

    var prefix = _prefix(host, registerAs);
    var crypto = _resolveCrypto(cryptoProfile, warnings);
    var explicitSignature = _parseSignatureProfile(signatureProfile, warnings);

    var usedNames = <String>{};
    var tools = <McpTool>[];
    var summaries = <Map<String, dynamic>>[];

    for (var endpoint in endpoints) {
      var name = _uniqueName(prefix, endpoint, usedNames);
      _SignatureRecipe? recipe;
      if (explicitSignature != null) {
        recipe = explicitSignature;
      } else if (signatureProfile?.toString() == 'auto') {
        recipe = _inferSignature(endpoint, warnings);
      }
      if (recipe != null && recipe.input != 'sorted-pairs' && recipe.input != 'sorted-concat') {
        warnings.add('$name: signature recipe "${recipe.input}" is reconstructed best-effort; '
            'verify a real call before trusting it');
      }

      var handler = _buildHandler(
        name: name,
        endpoint: endpoint,
        signature: recipe,
        crypto: crypto,
      );
      tools.add(McpTool(
        name: name,
        description: _description(endpoint, recipe, crypto),
        inputSchema: _schema(endpoint),
        handler: handler,
      ));
      summaries.add({
        'name': name,
        'method': endpoint.method,
        'path': endpoint.pattern,
        'samples': endpoint.samples.length,
        'params': endpoint.params.map((p) => p.toJson()).toList(),
        if (recipe != null) 'signature': recipe.toJson(),
      });
    }

    return DomainToolsResult(
      tools: tools,
      endpoints: summaries,
      warnings: warnings,
      prefix: prefix,
    );
  }

  // ------------------------------------------------------------- endpoints

  static List<_Endpoint> _endpoints(List<HttpRequest> flows, {Set<String>? methods, required List<String> warnings}) {
    var groups = <String, List<HttpRequest>>{};
    for (var flow in flows) {
      if (flow.method == HttpMethod.connect) continue;
      if (flow.isWebSocket) continue;
      if (flow.protocolVersion == 'MQTT') continue;
      var path = flow.requestUri?.path ?? '';
      if (path.isEmpty) continue;
      var method = flow.method.name.toUpperCase();
      if (methods != null && methods.isNotEmpty && !methods.contains(method)) continue;
      var pattern = _normalizePath(path);
      if (pattern.isEmpty) continue;
      (groups['$method $pattern'] ??= <HttpRequest>[]).add(flow);
    }

    var endpoints = <_Endpoint>[];
    for (var entry in groups.entries) {
      var space = entry.key.indexOf(' ');
      var method = entry.key.substring(0, space);
      var pattern = entry.key.substring(space + 1);
      var samples = entry.value.toList()..sort((a, b) => b.requestTime.compareTo(a.requestTime));
      if (samples.length > maxSamplesPerEndpoint) samples = samples.sublist(0, maxSamplesPerEndpoint);
      try {
        endpoints.add(_Endpoint(method: method, pattern: pattern, samples: samples));
      } catch (e) {
        warnings.add('skip $method $pattern: $e');
      }
    }
    return endpoints;
  }

  static String _normalizePath(String path) {
    var parts = path.split('/');
    var seen = <String, int>{};
    for (var i = 0; i < parts.length; i++) {
      var segment = parts[i];
      String? name;
      if (_numeric.hasMatch(segment)) {
        name = 'id';
      } else if (_uuid.hasMatch(segment)) {
        name = 'uuid';
      } else if (_longHex.hasMatch(segment)) {
        name = 'hash';
      }
      if (name == null) continue;
      var count = seen[name] ?? 0;
      seen[name] = count + 1;
      parts[i] = '{${count == 0 ? name : '$name${count + 1}'}}';
    }
    return parts.join('/');
  }

  static String _prefix(String host, String? registerAs) {
    var raw = registerAs?.trim();
    if (raw != null && raw.isNotEmpty) return _sanitizePrefix(raw);
    var labels = host
        .toLowerCase()
        .split('.')
        .where((e) => e.isNotEmpty && !RegExp(r'^\d+$').hasMatch(e))
        .toList();
    if (labels.length >= 2) {
      const generic = {'api', 'www', 'm', 'mobile', 'open', 'gateway', 'app'};
      return _sanitizePrefix(generic.contains(labels.first) ? labels[1] : labels.first);
    }
    if (labels.isNotEmpty) return _sanitizePrefix(labels.first);
    return 'api';
  }

  static String _sanitizePrefix(String value) {
    var slug = value.toLowerCase().replaceAll(_nonSlug, '_').replaceAll(RegExp(r'^_+|_+$'), '');
    if (slug.isEmpty) slug = 'api';
    if (!RegExp(r'^[a-z]').hasMatch(slug)) slug = 'api_$slug';
    return slug.length > 24 ? slug.substring(0, 24).replaceAll(RegExp(r'_+$'), '') : slug;
  }

  static String _uniqueName(String prefix, _Endpoint endpoint, Set<String> used) {
    var base = '${prefix}_${_slug(endpoint)}';
    var name = base;
    var index = 2;
    while (used.contains(name)) {
      name = '${base}_$index';
      index++;
    }
    used.add(name);
    return name;
  }

  static String _slug(_Endpoint endpoint) {
    var parts = <String>[];
    for (var segment in endpoint.pattern.split('/')) {
      if (segment.isEmpty) continue;
      if (segment.startsWith('{')) {
        parts.add('by_${segment.substring(1, segment.length - 1)}');
        continue;
      }
      var lower = segment.toLowerCase();
      if (_ignoredSegments.contains(lower) || RegExp(r'^v\d+$').hasMatch(lower)) continue;
      parts.add(lower);
    }
    var slug = parts.take(4).join('_').replaceAll(_nonSlug, '_').replaceAll(RegExp(r'_+'), '_');
    slug = slug.replaceAll(RegExp(r'^_+|_+$'), '');
    if (slug.isEmpty) slug = endpoint.method.toLowerCase();
    if (!RegExp(r'^[a-z]').hasMatch(slug)) slug = 'ep_$slug';
    if (slug.length > 52) slug = slug.substring(0, 52).replaceAll(RegExp(r'_+$'), '');
    return slug;
  }

  // ---------------------------------------------------------------- schema

  static Map<String, dynamic> _schema(_Endpoint endpoint) {
    var properties = <String, dynamic>{};
    for (var param in endpoint.params) {
      var sensitive = _sensitiveName(param.name);
      properties[param.name] = {
        'type': param.type,
        'description': sensitive
            ? '${param.source.label}; captured value redacted'
            : '${param.source.label}; captured default: ${_short(param.defaultValue)}',
        if (!param.required && !sensitive && _jsonSafe(param.defaultValue)) 'default': param.defaultValue,
      };
    }
    var required = endpoint.params.where((p) => p.required).map((p) => p.name).toList();
    return {
      'type': 'object',
      'properties': properties,
      if (required.isNotEmpty) 'required': required,
    };
  }

  static String _description(_Endpoint endpoint, _SignatureRecipe? signature, CryptoProfile? crypto) {
    var scope = [
      'Generated from ${endpoint.samples.length} captured ${endpoint.method} ${endpoint.pattern} flow(s).',
      'Sends a real request using the captured headers (auth/cookies included).',
      signature == null
          ? 'No signature recomputation: captured signature values are reused, so changing signed fields may fail.'
          : 'Recomputes "${signature.field}" with ${signature.algorithm}(${signature.input}) best-effort.',
      if (crypto != null) 'Decrypts the response with crypto profile "${crypto.name}" when possible.',
    ];
    return scope.join(' ');
  }

  // --------------------------------------------------------------- handler

  static Future<dynamic> Function(Map<String, dynamic>) _buildHandler({
    required String name,
    required _Endpoint endpoint,
    required _SignatureRecipe? signature,
    required CryptoProfile? crypto,
  }) {
    return (args) async {
      var watch = Stopwatch()..start();
      try {
        return await _invoke(name, endpoint, signature, crypto, args, watch);
      } catch (e) {
        watch.stop();
        return {
          'tool': name,
          'error': '$e',
          'elapsedMs': watch.elapsedMilliseconds,
        };
      }
    };
  }

  /// 构造一条待发送请求；与网络分离，便于测试签名与参数替换。
  static _Prepared _prepare(_Endpoint endpoint, _SignatureRecipe? signature, Map<String, dynamic> args) {
    var sample = endpoint.samples.first;
    var request = sample.copy()..streamId = null;
    var originalPath = sample.requestUri?.path ?? '';
    var originalQuery = sample.requestUri?.query ?? '';

    var query = <String, String>{};
    sample.requestUri?.queryParameters.forEach((k, v) => query[k] = v);
    var bodyChanged = false;
    var queryChanged = false;

    Map<String, dynamic>? json;
    Map<String, String>? form;
    String? rawBody;
    var bodyText = _bodyText(sample);

    if (endpoint.jsonBody && bodyText.isNotEmpty) {
      try {
        var decoded = jsonDecode(bodyText);
        if (decoded is Map) json = decoded.map((k, v) => MapEntry(k.toString(), v));
      } catch (_) {
        // 抓到的 body 不是合法 JSON：按原文透传，参数覆盖失效
      }
      rawBody = bodyText;
    } else if (endpoint.formBody && bodyText.isNotEmpty) {
      try {
        form = Uri.splitQueryString(bodyText);
      } catch (_) {
        rawBody = bodyText;
      }
    } else {
      rawBody = bodyText;
    }

    for (var param in endpoint.params) {
      if (!args.containsKey(param.name)) continue;
      switch (param.source) {
        case _ParamSource.query:
          query[param.name] = _stringify(args[param.name]);
          queryChanged = true;
        case _ParamSource.body:
          if (json != null && json.containsKey(param.name)) {
            json[param.name] = _coerce(args[param.name], param.type);
            bodyChanged = true;
          } else if (form != null && form.containsKey(param.name)) {
            form[param.name] = _stringify(args[param.name]);
            bodyChanged = true;
          }
        case _ParamSource.path:
          break;
        case _ParamSource.form:
          if (form != null) {
            form[param.name] = _stringify(args[param.name]);
            bodyChanged = true;
          }
      }
    }

    var path = endpoint.pattern;
    for (var param in endpoint.params.where((p) => p.source == _ParamSource.path)) {
      var value = args.containsKey(param.name) ? args[param.name] : param.defaultValue;
      path = path.replaceAll('{${param.name}}', Uri.encodeComponent(_stringify(value)));
    }

    var signatureInfo = <String, dynamic>{};
    if (signature != null) {
      var scalars = <String, String>{...query};
      if (json != null) {
        json.forEach((k, v) {
          if (_scalar(v)) scalars[k] = _stringify(v);
        });
      }
      if (form != null) scalars.addAll(form);
      // 未改 body 时用抓包原文参与签名，避免 jsonEncode 重排键影响未知签名。
      var bodyForSign = !bodyChanged
          ? bodyText
          : json != null
              ? jsonEncode(json)
              : form != null
                  ? _encodeForm(form)
                  : rawBody ?? '';
      var input = _signatureInput(signature, scalars, bodyForSign, _queryString(query), path);
      var digest = _digest(signature, input);
      var placed = false;
      if (json != null && json.containsKey(signature.field)) {
        json[signature.field] = digest;
        placed = true;
        bodyChanged = true;
      } else if (form != null && form.containsKey(signature.field)) {
        form[signature.field] = digest;
        placed = true;
        bodyChanged = true;
      } else if (query.containsKey(signature.field)) {
        query[signature.field] = digest;
        placed = true;
        queryChanged = true;
      } else if (rawBody == null || rawBody.isEmpty) {
        query[signature.field] = digest;
        placed = true;
        queryChanged = true;
      }
      signatureInfo = {
        'field': signature.field,
        'algorithm': signature.algorithm,
        'input': signature.input,
        if (!placed) 'error': 'signature field not found in request; digest was not applied',
      };
    }

    if (args.containsKey('body')) {
      rawBody = _stringify(args['body']);
      bodyChanged = true;
    } else if (bodyChanged) {
      rawBody = json != null
          ? jsonEncode(json)
          : form != null
              ? _encodeForm(form)
              : rawBody;
    }
    if (bodyChanged) _removeBodyEncoding(request);

    var queryString = _queryString(query);
    if (path != originalPath || queryString != originalQuery || queryChanged) {
      request.uri = path + (queryString.isEmpty ? '' : '?$queryString');
    }
    if (bodyChanged) {
      var bytes = rawBody == null ? Uint8List(0) : Uint8List.fromList(utf8.encode(rawBody));
      request.body = bytes;
      request.headers.contentLength = bytes.length;
    }

    return _Prepared(request: request, signatureInfo: signatureInfo);
  }

  /// 测试用：不发送请求，只返回第一条端点的最终 URL/body 与签名结果。
  static Map<String, dynamic> prepareForTest(
    List<HttpRequest> flows, {
    required String host,
    Object? signatureProfile,
    Map<String, dynamic> args = const {},
    Set<String>? methods,
  }) {
    var endpoints = _endpoints(flows, methods: methods, warnings: []);
    if (endpoints.isEmpty) throw StateError('no endpoints');
    var recipe = signatureProfile?.toString() == 'auto'
        ? _inferSignature(endpoints.first, [])
        : _parseSignatureProfile(signatureProfile, []);
    var prepared = _prepare(endpoints.first, recipe, args);
    return {
      'url': prepared.request.requestUrl,
      'body': prepared.request.getBodyString(),
      'signature': prepared.signatureInfo,
      'method': prepared.request.method.name.toUpperCase(),
    };
  }

  static Future<Map<String, dynamic>> _invoke(
    String name,
    _Endpoint endpoint,
    _SignatureRecipe? signature,
    CryptoProfile? crypto,
    Map<String, dynamic> args,
    Stopwatch watch,
  ) async {
    var prepared = _prepare(endpoint, signature, args);
    var request = prepared.request;
    var signatureInfo = prepared.signatureInfo;

    ProxyInfo? proxyInfo;

    var server = ProxyServer.current;
    if (server != null && server.isRunning) {
      proxyInfo = ProxyInfo.of('127.0.0.1', server.port);
    }

    HttpResponse response;
    try {
      response = await HttpClients.proxyRequest(request, proxyInfo: proxyInfo)
          .timeout(const Duration(seconds: 30));
    } catch (e) {
      watch.stop();
      return {
        'tool': name,
        'request': {'method': endpoint.method, 'url': _maskUrl(request.requestUrl)},
        if (signatureInfo.isNotEmpty) 'signature': signatureInfo,
        'error': 'request failed: $e',
        'elapsedMs': watch.elapsedMilliseconds,
      };
    }
    watch.stop();

    var decrypted = false;
    List<int>? raw = response.body;
    if (crypto != null && raw != null && raw.isNotEmpty) {
      try {
        raw = crypto.decryptBody(Uint8List.fromList(raw));
        decrypted = true;
      } catch (_) {
        // 不是该档位加密的响应：保持原样
      }
    }

    String text;
    if (decrypted) {
      text = utf8.decode(raw!, allowMalformed: true);
    } else {
      try {
        text = response.getBodyString();
      } catch (_) {
        text = '';
      }
    }

    dynamic decodedBody;
    if (text.isNotEmpty) {
      try {
        decodedBody = jsonDecode(text);
      } catch (_) {
        decodedBody = null;
      }
    }
    var truncated = text.length > maxResponseChars;

    return {
      'tool': name,
      'request': {'method': endpoint.method, 'url': _maskUrl(request.requestUrl)},
      if (signatureInfo.isNotEmpty) 'signature': signatureInfo,
      'status': response.status.code,
      'statusText': response.status.reasonPhrase,
      'headers': _redactHeaders(response.headers.toMap()),
      'bodySize': response.body?.length ?? 0,
      if (crypto != null) 'decrypted': decrypted,
      'body': decodedBody ?? (truncated ? text.substring(0, maxResponseChars) : text),
      if (truncated) 'bodyTruncated': true,
      'elapsedMs': watch.elapsedMilliseconds,
    };
  }

  static void _removeBodyEncoding(HttpRequest request) {
    request.headers.remove('content-encoding');
    request.headers.remove('transfer-encoding');
  }

  // -------------------------------------------------------------- signature

  static _SignatureRecipe? _inferSignature(_Endpoint endpoint, List<String> warnings) {
    if (endpoint.samples.length < 2) return null;
    try {
      var analysis = SignatureAnalyzer.analyze(
        endpoint.samples,
        sampleLimit: signatureSampleLimit,
      );
      var brute = analysis['bruteForce'];
      var matched = brute is Map ? brute['matched'] : null;
      if (matched is! Map) return null;
      var field = matched['field']?.toString();
      var algorithm = matched['algorithm']?.toString();
      var input = matched['input']?.toString();
      if (field == null || algorithm == null || input == null) return null;
      return _SignatureRecipe(
        field: field,
        algorithm: algorithm,
        input: input,
        secret: matched['secret']?.toString(),
      );
    } catch (e) {
      warnings.add('${endpoint.method} ${endpoint.pattern}: signature analysis failed: $e');
      return null;
    }
  }

  static _SignatureRecipe? _parseSignatureProfile(Object? raw, List<String> warnings) {
    if (raw is! Map) return null;
    var field = raw['field']?.toString();
    var algorithm = raw['algorithm']?.toString();
    var input = raw['input']?.toString() ?? 'sorted-pairs';
    if (field == null || field.isEmpty || algorithm == null || algorithm.isEmpty) {
      warnings.add('signatureProfile object needs "field" and "algorithm"');
      return null;
    }
    const supportedInputs = {
      'sorted-pairs',
      'sorted-concat',
      'raw-body',
      'query',
      'path',
      'sorted-pairs+secret',
      'secret+sorted-pairs',
      'raw-body+secret',
    };
    if (!supportedInputs.contains(input)) {
      warnings.add('unsupported signatureProfile.input "$input"');
      return null;
    }
    var algorithmName = algorithm.toUpperCase();
    const supportedAlgorithms = {'MD5', 'SHA-1', 'SHA-256', 'HMAC-SHA256'};
    if (!supportedAlgorithms.contains(algorithmName)) {
      warnings.add('unsupported signatureProfile.algorithm "$algorithm"');
      return null;
    }
    return _SignatureRecipe(
      field: field,
      algorithm: algorithmName,
      input: input,
      secret: raw['secret']?.toString(),
    );
  }

  static String _signatureInput(
    _SignatureRecipe recipe,
    Map<String, String> params,
    String body,
    String query,
    String path,
  ) {
    var others = Map<String, String>.from(params)..remove(recipe.field);
    var keys = others.keys.toList()..sort();
    var pairs = keys.map((k) => '$k=${others[k]}').join('&');
    var concat = keys.map((k) => '$k${others[k]}').join();
    var secret = recipe.secret ?? '';
    return switch (recipe.input) {
      'sorted-pairs' => pairs,
      'sorted-concat' => concat,
      'raw-body' => body,
      'query' => query,
      'path' => path,
      'sorted-pairs+secret' => '$pairs$secret',
      'secret+sorted-pairs' => '$secret$pairs',
      'raw-body+secret' => '$body$secret',
      _ => throw ArgumentError('unsupported signature input "${recipe.input}"'),
    };
  }

  static String _digest(_SignatureRecipe recipe, String input) {
    if (recipe.algorithm == 'HMAC-SHA256') {
      var mac = HMac.withDigest(Digest('SHA-256'));
      mac.init(KeyParameter(utf8.encode(recipe.secret ?? '')));
      return _hex(mac.process(utf8.encode(input)));
    }
    var bytes = CryptoUtils.getHashPlain(
      Uint8List.fromList(utf8.encode(input)),
      algorithmName: recipe.algorithm,
    );
    return _hex(bytes);
  }

  static String _hex(List<int> bytes) =>
      bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

  static CryptoProfile? _resolveCrypto(String? name, List<String> warnings) {
    if (name == null || name.isEmpty) return null;
    var profile = CryptoProfileStore.instance.byName(name);
    if (profile == null) {
      warnings.add('crypto profile "$name" not found; responses will not be decrypted');
      return null;
    }
    if (!profile.enabled) {
      warnings.add('crypto profile "$name" is disabled; responses will not be decrypted');
    }
    return profile;
  }

  // ---------------------------------------------------------------- helpers

  static String _bodyText(HttpRequest request) {
    try {
      return request.getBodyString();
    } catch (_) {
      return '';
    }
  }

  static String _stringify(dynamic value) {
    if (value == null) return '';
    if (value is String) return value;
    return '$value';
  }

  static dynamic _coerce(dynamic value, String type) {
    return switch (type) {
      'integer' => value is num ? value.toInt() : int.tryParse('$value') ?? value,
      'number' => value is num ? value : num.tryParse('$value') ?? value,
      'boolean' => value == true || '$value'.toLowerCase() == 'true',
      _ => value is String ? value : _stringify(value),
    };
  }

  static bool _scalar(dynamic value) =>
      value == null || value is String || value is num || value is bool;

  static bool _jsonSafe(dynamic value) =>
      value == null || value is String || value is num || value is bool;

  static String _typeOf(dynamic value) {
    if (value is int) return 'integer';
    if (value is num) return 'number';
    if (value is bool) return 'boolean';
    return 'string';
  }

  static String _encodeForm(Map<String, String> form) => form.entries
      .map((e) => '${Uri.encodeQueryComponent(e.key)}=${Uri.encodeQueryComponent(e.value)}')
      .join('&');

  static String _queryString(Map<String, String> query) => query.entries
      .map((e) => '${Uri.encodeQueryComponent(e.key)}=${Uri.encodeQueryComponent(e.value)}')
      .join('&');

  static bool _sensitiveName(String name) {
    var lower = name.toLowerCase();
    if (_sensitiveQuery.contains(lower)) return true;
    return lower.contains('password') ||
        lower.contains('secret') ||
        lower.contains('token') ||
        lower.contains('signature') ||
        lower == 'sign' ||
        lower.endsWith('_sign') ||
        lower.endsWith('-sign');
  }

  static String _short(dynamic value) {
    var text = value == null ? 'null' : '$value';
    return text.length <= 40 ? text : '${text.substring(0, 40)}…';
  }

  static Map<String, dynamic> _redactHeaders(Map<String, dynamic> headers) {
    var out = <String, dynamic>{};
    headers.forEach((k, v) {
      out[k] = SensitiveData.isRedactedHeader(k) ? SensitiveData.placeholder : v;
    });
    return out;
  }

  static String _maskUrl(String url) {
    var uri = Uri.tryParse(url);
    if (uri == null || !uri.hasQuery) return url;
    try {
      var masked = uri.queryParameters.map((k, v) =>
          MapEntry(k, _sensitiveQuery.contains(k.toLowerCase()) ? SensitiveData.placeholder : v));
      return uri.replace(queryParameters: masked).toString();
    } catch (_) {
      return url;
    }
  }
}

class DomainToolsResult {
  final List<McpTool> tools;
  final List<Map<String, dynamic>> endpoints;
  final List<String> warnings;
  final String prefix;

  const DomainToolsResult({
    required this.tools,
    required this.endpoints,
    required this.warnings,
    required this.prefix,
  });
}

class _Endpoint {
  final String method;
  final String pattern;
  final List<HttpRequest> samples;
  final List<_Param> params;
  final bool jsonBody;
  final bool formBody;

  _Endpoint({required this.method, required this.pattern, required this.samples})
      : params = _extractParams(pattern, samples.first),
        jsonBody = _looksJson(samples.first),
        formBody = _looksForm(samples.first);

  static bool _looksJson(HttpRequest request) {
    var body = DomainToolGenerator._bodyText(request).trim();
    if (body.isEmpty) return false;
    var contentType = request.headers.contentType.toLowerCase();
    return contentType.contains('json') || (body.startsWith('{') && body.endsWith('}'));
  }

  static bool _looksForm(HttpRequest request) {
    var contentType = request.headers.contentType.toLowerCase();
    return contentType.contains('x-www-form-urlencoded');
  }

  static List<_Param> _extractParams(String pattern, HttpRequest sample) {
    var result = <_Param>[];
    var names = <String>{};

    var patternSegments = pattern.split('/');
    var sampleSegments = (sample.requestUri?.path ?? '').split('/');
    for (var i = 0; i < patternSegments.length; i++) {
      var match = DomainToolGenerator._placeholder.firstMatch(patternSegments[i]);
      if (match == null) continue;
      var name = match.group(1)!;
      var defaultValue = i < sampleSegments.length ? sampleSegments[i] : '';
      result.add(_Param(
        name: name,
        source: _ParamSource.path,
        type: DomainToolGenerator._typeOf(int.tryParse(defaultValue) ?? defaultValue),
        required: true,
        defaultValue: defaultValue,
      ));
      names.add(name);
    }

    sample.requestUri?.queryParameters.forEach((name, value) {
      if (name.isEmpty || names.contains(name)) return;
      names.add(name);
      result.add(_Param(
        name: name,
        source: _ParamSource.query,
        type: DomainToolGenerator._typeOf(int.tryParse(value) ?? value),
        required: false,
        defaultValue: value,
      ));
    });

    var body = DomainToolGenerator._bodyText(sample).trim();
    if (body.isEmpty) return result;

    if (_looksJsonBody(sample)) {
      try {
        var decoded = jsonDecode(body);
        if (decoded is Map) {
          decoded.forEach((key, value) {
            if (!DomainToolGenerator._scalar(value)) return;
            var name = key.toString();
            if (names.contains(name)) return;
            names.add(name);
            result.add(_Param(
              name: name,
              source: _ParamSource.body,
              type: DomainToolGenerator._typeOf(value),
              required: false,
              defaultValue: value,
            ));
          });
        }
      } catch (_) {
        // 非法 JSON 时退化为原始 body 覆盖
      }
    } else if (_looksFormBody(sample)) {
      try {
        Uri.splitQueryString(body).forEach((name, value) {
          if (names.contains(name)) return;
          names.add(name);
          result.add(_Param(
            name: name,
            source: _ParamSource.form,
            type: DomainToolGenerator._typeOf(int.tryParse(value) ?? value),
            required: false,
            defaultValue: value,
          ));
        });
      } catch (_) {
        // 非法表单时退化为原始 body 覆盖
      }
    }

    return result;
  }

  static bool _looksJsonBody(HttpRequest request) {
    var body = DomainToolGenerator._bodyText(request).trim();
    var contentType = request.headers.contentType.toLowerCase();
    return contentType.contains('json') || (body.startsWith('{') && body.endsWith('}'));
  }

  static bool _looksFormBody(HttpRequest request) =>
      request.headers.contentType.toLowerCase().contains('x-www-form-urlencoded');
}

enum _ParamSource {
  path('path parameter'),
  query('query parameter'),
  body('JSON body field'),
  form('form field');

  final String label;

  const _ParamSource(this.label);
}

class _Param {
  final String name;
  final _ParamSource source;
  final String type;
  final bool required;
  final dynamic defaultValue;

  const _Param({
    required this.name,
    required this.source,
    required this.type,
    required this.required,
    required this.defaultValue,
  });

  Map<String, dynamic> toJson() => {
        'name': name,
        'in': source.name,
        'type': type,
        'required': required,
      };
}

class _Prepared {
  final HttpRequest request;
  final Map<String, dynamic> signatureInfo;

  const _Prepared({required this.request, required this.signatureInfo});
}

class _SignatureRecipe {
  final String field;
  final String algorithm;
  final String input;
  final String? secret;

  const _SignatureRecipe({
    required this.field,
    required this.algorithm,
    required this.input,
    this.secret,
  });

  Map<String, dynamic> toJson() => {
        'field': field,
        'algorithm': algorithm,
        'input': input,
        if (secret != null) 'secret': '<provided>',
      };
}
