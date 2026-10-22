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

/// 报文编码/加密特征识别。
///
/// 只做纯字符串推断，不联网、不做密钥尝试：把 body 里能可靠解开的常见编码
/// （JWT / Base64 / Hex / URL encode / protobuf Any）列成候选，供 AI 继续分析。
/// 返回的是「候选」而非断言，识别不出时返回空列表。
///
/// @author wanghongen
class CodecDetector {
  CodecDetector._();

  /// 超过该长度的文本不做识别，避免大 body 拖慢工具调用
  static const int maxInputLength = 64 * 1024;

  /// 单个解码结果的最大保留长度
  static const int maxDecodedLength = 16 * 1024;

  /// 一次识别最多返回的候选数
  static const int maxCandidates = 8;

  /// 递归解码层数（base64 -> json -> 内层 base64 等）
  static const int maxDepth = 2;

  static final RegExp _jwtPart = RegExp(r'^[A-Za-z0-9_-]+$');
  static final RegExp _base64Chars = RegExp(r'^[A-Za-z0-9+/=_-]+$');
  static final RegExp _hexChars = RegExp(r'^[0-9a-fA-F]+$');
  static final RegExp _percent = RegExp(r'%[0-9A-Fa-f]{2}');

  /// 识别文本中的编码层。返回按发现顺序排列的候选列表。
  static List<Map<String, dynamic>> detect(String? text) {
    var input = text?.trim();
    if (input == null || input.isEmpty || input.length > maxInputLength) {
      return const [];
    }
    var out = <Map<String, dynamic>>[];
    _scan(input, 0, null, out, <String>{});
    return out;
  }

  static void _scan(
      String text, int depth, String? parent, List<Map<String, dynamic>> out, Set<String> seen) {
    if (depth > maxDepth || out.length >= maxCandidates) return;
    var input = text.trim();
    if (input.isEmpty) return;

    var jwt = _tryJwt(input);
    if (jwt != null) {
      _add(out, seen, _item('jwt', jwt, 0.99, parent));
    }

    if (input.startsWith('type.googleapis.com/')) {
      _add(out, seen, _item('protobuf-any', input, 0.9, parent));
    }

    if (_percent.allMatches(input).length >= 3 && input.contains('=')) {
      try {
        var decoded = Uri.decodeComponent(input);
        if (decoded != input && decoded.isNotEmpty) {
          var added = _add(out, seen, _item('urlencoded', _clip(decoded), 0.8, parent));
          if (added) _scan(decoded, depth + 1, 'urlencoded', out, seen);
        }
      } catch (_) {
        // 非法百分号序列，忽略
      }
    }

    // 纯 hex 优先于 base64：两者字符集有重叠，先按更严格的 hex 判定
    if (input.length >= 16 && input.length.isEven && _hexChars.hasMatch(input)) {
      var decoded = _decodeBytes(_hexToBytes(input));
      if (decoded != null) {
        var added = _add(out, seen, _item('hex', _clip(decoded), 0.7, parent));
        if (added) _scan(decoded, depth + 1, 'hex', out, seen);
      }
    }

    if (input.length >= 16 && _base64Chars.hasMatch(input)) {
      var decoded = _tryBase64(input);
      if (decoded != null) {
        var confidence = _looksStructured(decoded) ? 0.95 : 0.7;
        var added = _add(out, seen, _item('base64', _clip(decoded), confidence, parent));
        if (added) _scan(decoded, depth + 1, 'base64', out, seen);
      }
    }
  }

  static Map<String, dynamic>? _tryJwt(String input) {
    var parts = input.split('.');
    if (parts.length != 3) return null;
    if (!_jwtPart.hasMatch(parts[0]) || !_jwtPart.hasMatch(parts[1])) return null;
    if (parts[0].length > maxInputLength || parts[1].length > maxInputLength) return null;

    var header = _decodeJsonSegment(parts[0]);
    var payload = _decodeJsonSegment(parts[1]);
    if (header == null || payload == null) return null;

    return {
      'header': header,
      'payload': payload,
      'signature': parts[2].isEmpty ? 'none' : '${parts[2].length} chars',
    };
  }

  static Map<String, dynamic>? _decodeJsonSegment(String segment) {
    var normalized = segment.replaceAll('-', '+').replaceAll('_', '/');
    while (normalized.length % 4 != 0) {
      normalized += '=';
    }
    try {
      var bytes = base64.decode(normalized);
      if (bytes.isEmpty || bytes.length > maxDecodedLength) return null;
      var decoded = jsonDecode(utf8.decode(bytes));
      return decoded is Map ? Map<String, dynamic>.from(decoded) : null;
    } catch (_) {
      return null;
    }
  }

  /// 尝试按 Base64/Base64Url 解码，并要求结果像可读文本。
  static String? _tryBase64(String input) {
    var normalized = input.replaceAll('-', '+').replaceAll('_', '/').replaceAll('=', '');
    if (normalized.length % 4 == 1) return null;
    while (normalized.length % 4 != 0) {
      normalized += '=';
    }

    List<int> bytes;
    try {
      bytes = base64.decode(normalized);
    } catch (_) {
      return null;
    }
    if (bytes.isEmpty || bytes.length > maxDecodedLength) return null;

    var decoded = _decodeBytes(bytes);
    if (decoded == null) return null;

    // 没有明显编码特征（+/=_-）时，只接受结构化结果，避免把普通长单词当成 base64
    var hasMarker = input.contains('+') ||
        input.contains('/') ||
        input.contains('=') ||
        input.contains('-') ||
        input.contains('_');
    if (!hasMarker && !_looksStructured(decoded)) return null;
    return decoded;
  }

  static String? _decodeBytes(List<int> bytes) {
    if (bytes.isEmpty) return null;
    try {
      var text = utf8.decode(bytes);
      if (text.length < 4 || !_isPrintable(text)) return null;
      return text;
    } catch (_) {
      return null;
    }
  }

  static bool _isPrintable(String text) {
    if (text.contains('�')) return false;
    var bad = 0;
    for (var code in text.codeUnits) {
      if (code == 0x09 || code == 0x0A || code == 0x0D) continue;
      if (code < 0x20 || code == 0x7F) bad++;
    }
    return bad / text.length < 0.05;
  }

  static bool _looksStructured(String text) {
    var trimmed = text.trimLeft();
    return trimmed.startsWith('{') ||
        trimmed.startsWith('[') ||
        trimmed.startsWith('<') ||
        text.contains('\n') ||
        text.contains('=') ||
        text.contains(':');
  }

  static List<int> _hexToBytes(String hex) {
    var bytes = List<int>.filled(hex.length ~/ 2, 0);
    for (var i = 0; i < bytes.length; i++) {
      bytes[i] = int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16);
    }
    return bytes;
  }

  static String _clip(String value) =>
      value.length <= maxDecodedLength ? value : value.substring(0, maxDecodedLength);

  static Map<String, dynamic> _item(
          String codec, dynamic result, double confidence, String? parent) =>
      {
        'codec': codec,
        'result': result,
        'confidence': confidence,
        if (parent != null) 'decodedFrom': parent,
      };

  static bool _add(List<Map<String, dynamic>> out, Set<String> seen, Map<String, dynamic> item) {
    var result = item['result'];
    var key = '${item['codec']}|${result is String ? result : jsonEncode(result)}';
    if (!seen.add(key)) return false;
    out.add(item);
    return true;
  }
}
