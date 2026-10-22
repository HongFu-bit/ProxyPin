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
import 'dart:typed_data';

import 'package:proxypin/network/http/http.dart';
import 'package:proxypin/network/util/crypto.dart';

/// 签名参数差量推断：从同一接口的多条抓包里找「哪个字段像签名、怎么算出来的」。
///
/// 只做只读统计与常见拼接/哈希尝试，返回候选而非断言。
/// 不做暴力破解密钥空间，也不修改任何流量。
///
/// @author wanghongen
class SignatureAnalyzer {
  SignatureAnalyzer._();

  static const int maxSamples = 50;
  static const int maxFields = 128;
  static const int maxBodyBytes = 256 * 1024;
  static const int maxCandidates = 5;
  static const int maxBruteForceSamples = 10;
  static const int maxTriedLabels = 80;

  static final RegExp _hexChars = RegExp(r'^[0-9a-fA-F]+$');
  static final RegExp _base64Chars = RegExp(r'^[A-Za-z0-9+/=_-]+$');
  static final RegExp _signatureName =
      RegExp(r'(^|_)(sign|signature|sig|hash|hmac|checksum|digest|mac)(_|$)', caseSensitive: false);

  static const List<String> _algorithms = ['MD5', 'SHA-1', 'SHA-256'];

  /// 分析一组同接口请求。[sampleLimit] 为参与统计的样本数上限。
  static Map<String, dynamic> analyze(List<HttpRequest> flows, {int sampleLimit = 20, String? secret}) {
    var samples = flows.take(sampleLimit.clamp(2, maxSamples)).toList(growable: false);
    var total = samples.length;

    var stats = <String, _FieldStats>{};
    for (var flow in samples) {
      var params = _params(flow);
      params.forEach((name, value) {
        if (stats.length >= maxFields && !stats.containsKey(name)) return;
        stats.putIfAbsent(name, () => _FieldStats()).values.add(value);
      });
    }

    var constantFields = <String>[];
    var varyingFields = <Map<String, dynamic>>[];
    var signatureCandidates = <Map<String, dynamic>>[];
    var candidateFields = <String>[];

    stats.forEach((name, field) {
      var presence = field.values.length / total;
      var unique = field.values.toSet();
      var uniqueRatio = unique.length / field.values.length;
      var likely = _likelyAlgorithm(field.values.first);
      var nameMatch = _signatureName.hasMatch(name);

      if (presence >= 1.0 && unique.length == 1) {
        constantFields.add(name);
      } else {
        varyingFields.add({
          'field': name,
          'presence': double.parse(presence.toStringAsFixed(2)),
          'type': _typeOf(field.values),
          'randomness': double.parse(uniqueRatio.toStringAsFixed(2)),
          'monotonic': field.values.length > 2 && _monotonic(field.values),
          'length': _lengthOf(field.values),
        });
      }

      if (field.values.length > 1 && (nameMatch || (likely != null && unique.length > 1))) {
        candidateFields.add(name);
        signatureCandidates.add({
          'field': name,
          'length': _lengthOf(field.values),
          'encoding': _encodingOf(field.values.first),
          if (likely != null) 'likely': likely,
          'confidence': nameMatch ? 0.9 : 0.6,
          'randomness': double.parse(uniqueRatio.toStringAsFixed(2)),
        });
      }
    });

    return {
      'samples': total,
      'host': samples.first.requestUri?.host ?? samples.first.remoteDomain(),
      'path': samples.first.path,
      'constantFields': constantFields,
      'varyingFields': varyingFields,
      'signatureCandidates': signatureCandidates,
      'bruteForce': _bruteForce(samples, candidateFields.take(maxCandidates).toList(), secret),
      if (signatureCandidates.isNotEmpty) 'hint': _hint(signatureCandidates.first),
    };
  }

  static Map<String, dynamic> _bruteForce(List<HttpRequest> samples, List<String> fields, String? secret) {
    var tried = <String>[];
    for (var field in fields) {
      for (var i = 0; i < samples.length && i < maxBruteForceSamples; i++) {
        var flow = samples[i];
        var params = _params(flow);
        var expected = params[field];
        if (expected == null || expected.isEmpty) continue;

        var inputs = _buildInputs(flow, params, field, secret);
        for (var entry in inputs.entries) {
          for (var algorithm in _algorithms) {
            var label = '$algorithm(${entry.key})';
            _addTried(tried, label);
            var digest = _hash(algorithm, entry.value);
            if (_matchesDigest(digest, expected)) {
              return {
                'tried': tried,
                'matched': {
                  'field': field,
                  'algorithm': algorithm,
                  'input': entry.key,
                  'sampleId': flow.requestId,
                },
              };
            }
          }

          if (secret != null && secret.isNotEmpty) {
            _addTried(tried, 'HMAC-SHA256(${entry.key},secret)');
            if (_matchesDigest(_hmacSha256(utf8.encode(secret), entry.value), expected)) {
              return {
                'tried': tried,
                'matched': {
                  'field': field,
                  'algorithm': 'HMAC-SHA256',
                  'input': entry.key,
                  'secret': secret,
                  'sampleId': flow.requestId,
                },
              };
            }
          }
        }
      }
    }
    return {'tried': tried, 'matched': null};
  }

  static Map<String, String> _buildInputs(
      HttpRequest flow, Map<String, String> params, String field, String? secret) {
    var others = Map<String, String>.from(params)..remove(field);
    var keys = others.keys.toList()..sort();
    var pairs = keys.map((k) => '$k=${others[k]}').join('&');
    var concat = keys.map((k) => '$k${others[k]}').join();
    var rawBody = _bodyText(flow);
    var query = flow.requestUri?.query ?? '';
    var path = flow.requestUri?.path ?? '';

    var inputs = <String, String>{
      'sorted-pairs': pairs,
      'sorted-concat': concat,
      'raw-body': rawBody,
      'query': query,
      'path': path,
    }..removeWhere((_, value) => value.isEmpty);

    if (secret != null && secret.isNotEmpty) {
      inputs['sorted-pairs+secret'] = '$pairs$secret';
      inputs['secret+sorted-pairs'] = '$secret$pairs';
      if (rawBody.isNotEmpty) inputs['raw-body+secret'] = '$rawBody$secret';
    }
    return inputs;
  }

  static Map<String, String> _params(HttpRequest flow) {
    var result = <String, String>{};
    flow.requestUri?.queryParameters.forEach((name, value) => result[name] = value);

    var body = _bodyText(flow);
    if (body.isEmpty || body.length > maxBodyBytes) return result;

    var contentType = flow.headers.contentType.toLowerCase();
    var trimmed = body.trim();
    if (contentType.contains('json') || (trimmed.startsWith('{') && trimmed.endsWith('}'))) {
      try {
        var decoded = jsonDecode(body);
        if (decoded is Map) {
          decoded.forEach((key, value) {
            if (value == null || value is Map || value is List) return;
            result[key.toString()] = value.toString();
          });
        }
      } catch (_) {
        // 非法 JSON 忽略，退回 query 参数
      }
    } else if (contentType.contains('x-www-form-urlencoded')) {
      try {
        result.addAll(Uri.splitQueryString(body));
      } catch (_) {
        // 非法表单忽略
      }
    }
    return result;
  }

  static String _bodyText(HttpRequest flow) {
    var body = flow.body;
    if (body == null || body.isEmpty || body.length > maxBodyBytes) return '';
    try {
      return flow.getBodyString();
    } catch (_) {
      return '';
    }
  }

  static String _typeOf(List<String> values) {
    var numbers = values.map(num.tryParse).toList();
    if (numbers.every((n) => n != null)) {
      var allInt = numbers.every((n) => n != null && (n is int || n == n.truncateToDouble()));
      return allInt ? 'int' : 'float';
    }
    if (values.every(_isHex)) return 'hex';
    return 'string';
  }

  static dynamic _lengthOf(List<String> values) {
    var lengths = values.map((v) => v.length).toSet();
    return lengths.length == 1 ? lengths.first : (lengths.toList()..sort());
  }

  static String _encodingOf(String value) {
    if (_isHex(value)) return 'hex';
    if (value.length >= 16 && _base64Chars.hasMatch(value)) return 'base64';
    return 'string';
  }

  static bool _isHex(String value) => value.isNotEmpty && value.length.isEven && _hexChars.hasMatch(value);

  static bool _monotonic(List<String> values) {
    var numbers = values.map(num.tryParse).toList();
    if (numbers.any((n) => n == null)) return false;
    var ascending = true;
    var descending = true;
    for (var i = 1; i < numbers.length; i++) {
      if (numbers[i]! < numbers[i - 1]!) ascending = false;
      if (numbers[i]! > numbers[i - 1]!) descending = false;
    }
    return ascending || descending;
  }

  static String? _likelyAlgorithm(String value) {
    if (_isHex(value)) {
      switch (value.length) {
        case 32:
          return 'MD5';
        case 40:
          return 'SHA1';
        case 64:
          return 'SHA256';
        case 96:
          return 'SHA384';
        case 128:
          return 'SHA512';
      }
    }
    if (value.length >= 16 && _base64Chars.hasMatch(value)) {
      switch (value.length) {
        case 24:
          return 'MD5(base64)';
        case 28:
          return 'SHA1(base64)';
        case 44:
          return 'SHA256(base64)';
        case 88:
          return 'SHA512(base64)';
      }
    }
    return null;
  }

  static String? _hint(Map<String, dynamic> candidate) {
    var field = candidate['field'];
    var likely = candidate['likely'];
    if (likely != null) {
      return 'Field $field has a $likely-shaped value; try hashing sorted key=value pairs '
          '(with and without a constant secret) before assuming a custom algorithm.';
    }
    return 'Field $field varies on every request; if it changes with the body, compare '
        'candidate concatenations (sorted k=v, sorted concat, raw body) first.';
  }

  static void _addTried(List<String> tried, String label) {
    if (tried.length < maxTriedLabels && !tried.contains(label)) tried.add(label);
  }

  static List<int> _hash(String algorithm, String input) =>
      CryptoUtils.getHashPlain(Uint8List.fromList(utf8.encode(input)), algorithmName: algorithm);

  static bool _matchesDigest(List<int> digest, String expected) {
    var value = expected.trim();
    if (value.isEmpty) return false;
    var hex = _hex(digest);
    var lower = value.toLowerCase();
    if (lower == hex) return true;

    // 截断哈希（如只取 MD5 前 16 位）；过短的值不参与匹配，避免 '0' 之类误命中
    if (lower.length >= 8 && _hexChars.hasMatch(value) && lower.length < hex.length && hex.startsWith(lower)) {
      return true;
    }

    var normalized = value.replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
    var encoded = base64Encode(digest).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
    return normalized == encoded;
  }

  static String _hex(List<int> bytes) =>
      bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

  /// HMAC-SHA256，用现有 pointycastle SHA-256 原语按 RFC 2104 实现，避免额外依赖。
  static List<int> _hmacSha256(List<int> key, String message) {
    var blockSize = 64;
    var normalizedKey = key.length > blockSize
        ? CryptoUtils.getHashPlain(Uint8List.fromList(key), algorithmName: 'SHA-256')
        : key;

    var padded = Uint8List(blockSize);
    padded.setRange(0, normalizedKey.length, normalizedKey);
    var messageBytes = utf8.encode(message);
    var inner = Uint8List(blockSize + messageBytes.length);
    var outer = Uint8List(blockSize + 32);
    for (var i = 0; i < blockSize; i++) {
      inner[i] = padded[i] ^ 0x36;
      outer[i] = padded[i] ^ 0x5c;
    }
    inner.setRange(blockSize, blockSize + messageBytes.length, messageBytes);

    var innerDigest = CryptoUtils.getHashPlain(inner, algorithmName: 'SHA-256');
    outer.setRange(blockSize, blockSize + innerDigest.length, innerDigest);
    return CryptoUtils.getHashPlain(outer, algorithmName: 'SHA-256');
  }
}

class _FieldStats {
  final List<String> values = [];
}
