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
import 'dart:io';
import 'dart:typed_data';

import 'package:proxypin/network/http/http.dart';
import 'package:proxypin/network/util/compress.dart';

/// 无 schema 的 protobuf / gRPC 降级解码。
///
/// 只依赖 wire format：字段号、wire type 和原始值，不做任何 .proto 推断。
/// 长度分隔字段按「可打印 UTF-8 → 嵌套消息 → 原始字节」的顺序猜测，
/// 输出明确标记 degraded，不把猜测当作结构证明。
class ProtobufDecoder {
  static const int defaultMaxDepth = 8;
  static const int defaultMaxFields = 512;
  static const int defaultMaxBytes = 1024 * 1024;

  /// 从 [HttpMessage] 取 body，并按 Content-Encoding 解压。
  /// 返回 null 表示没有 body；[truncated] 在超过 [maxBytes] 时为 true。
  static Future<({Uint8List bytes, bool truncated})?> bodyBytes(
    HttpMessage message, {
    int maxBytes = defaultMaxBytes,
  }) async {
    var raw = message.body;
    if (raw == null || raw.isEmpty) return null;
    List<int> data = raw;
    try {
      if (message.headers.isGzip) {
        data = gzipDecode(raw);
      } else if (message.headers.contentEncoding == 'br') {
        data = brDecode(raw);
      } else if (message.headers.contentEncoding == 'deflate') {
        data = zlibDecode(raw);
      } else if (message.headers.contentEncoding == 'zstd') {
        data = await zstdDecode(raw) ?? raw;
      }
    } catch (_) {
      data = raw;
    }
    var truncated = data.length > maxBytes;
    var bytes = truncated ? Uint8List.fromList(data.sublist(0, maxBytes)) : Uint8List.fromList(data);
    return (bytes: bytes, truncated: truncated);
  }

  /// 解码单个 body。[grpc] 为 null 时按 Content-Type / gRPC 帧结构自动判断。
  static Map<String, dynamic> decodeBody(
    Uint8List bytes, {
    String? contentType,
    bool? grpc,
    int maxDepth = defaultMaxDepth,
    int maxFields = defaultMaxFields,
  }) {
    var isGrpc = grpc ?? (looksLikeGrpc(contentType) || _looksLikeGrpcFrames(bytes));
    if (isGrpc) return decodeGrpc(bytes, maxDepth: maxDepth, maxFields: maxFields);
    return decode(bytes, maxDepth: maxDepth, maxFields: maxFields);
  }

  static bool looksLikeGrpc(String? contentType) {
    var value = contentType?.toLowerCase().trim() ?? '';
    return value.startsWith('application/grpc');
  }

  /// 解析裸 protobuf（不含 gRPC 5 字节帧头）。
  static Map<String, dynamic> decode(
    Uint8List bytes, {
    int maxDepth = defaultMaxDepth,
    int maxFields = defaultMaxFields,
  }) {
    var result = _decodeMessage(bytes, 0, maxDepth, maxFields);
    return {
      'format': 'protobuf',
      'bytes': bytes.length,
      'fields': result.fields,
      'fieldCount': result.fields.length,
      if (result.error != null) 'parseError': result.error,
      if (result.truncated) 'truncated': true,
      'degraded': true,
      'note': 'Schema-less decode: varints are unsigned (64-bit values also report signed), '
          'length-delimited values are guessed as string / nested message / bytes.',
    };
  }

  /// 解析 gRPC 帧（flag + 4 字节大端长度 + payload），支持一帧或多帧。
  static Map<String, dynamic> decodeGrpc(
    Uint8List bytes, {
    int maxDepth = defaultMaxDepth,
    int maxFields = defaultMaxFields,
  }) {
    var frames = <Map<String, dynamic>>[];
    String? error;
    var pos = 0;
    while (pos < bytes.length) {
      if (pos + 5 > bytes.length) {
        error = 'truncated gRPC frame header at offset $pos';
        break;
      }
      var flag = bytes[pos];
      var length = ByteData.sublistView(bytes, pos + 1, pos + 5).getUint32(0);
      var start = pos + 5;
      if (start + length > bytes.length) {
        error = 'truncated gRPC frame body at offset $pos (need $length bytes)';
        break;
      }
      var payload = Uint8List.sublistView(bytes, start, start + length);
      var frame = <String, dynamic>{
        'index': frames.length,
        'compressed': flag == 1,
        'length': length,
        if (flag != 0 && flag != 1) 'flag': flag,
      };

      Uint8List? data = payload;
      if (flag == 1) {
        try {
          data = Uint8List.fromList(GZipCodec().decode(payload));
          frame['decompressed'] = true;
        } catch (e) {
          frame['decodeError'] = 'compressed frame could not be gunzipped: $e';
          data = null;
        }
      }
      if (data != null) {
        var decoded = _decodeMessage(data, 0, maxDepth, maxFields);
        frame['fields'] = decoded.fields;
        frame['fieldCount'] = decoded.fields.length;
        if (decoded.error != null) frame['parseError'] = decoded.error;
        if (decoded.truncated) frame['truncated'] = true;
      }
      frames.add(frame);
      pos = start + length;
    }

    return {
      'format': 'grpc',
      'bytes': bytes.length,
      'frames': frames,
      'frameCount': frames.length,
      if (error != null) 'parseError': error,
      'degraded': true,
      'note': 'gRPC frames are parsed without .proto or grpc-status metadata; '
          'compressed frames are attempted as gzip only.',
    };
  }

  /// 仅当整段字节恰好由一个或多个合法帧组成时返回 true，避免把普通 protobuf 误判成 gRPC。
  static bool _looksLikeGrpcFrames(Uint8List bytes) {
    if (bytes.length < 5) return false;
    var pos = 0;
    while (pos + 5 <= bytes.length) {
      var flag = bytes[pos];
      if (flag != 0 && flag != 1) return false;
      var length = ByteData.sublistView(bytes, pos + 1, pos + 5).getUint32(0);
      pos += 5 + length;
      if (pos > bytes.length) return false;
    }
    return pos == bytes.length && bytes.length > 5;
  }

  static _MessageResult _decodeMessage(Uint8List bytes, int depth, int maxDepth, int maxFields) {
    var fields = <Map<String, dynamic>>[];
    var pos = 0;
    String? error;
    var truncated = false;

    while (pos < bytes.length) {
      if (fields.length >= maxFields) {
        error = 'field limit ($maxFields) reached at offset $pos';
        truncated = true;
        break;
      }
      var key = _readVarint(bytes, pos);
      if (key == null) {
        error = 'truncated field key at offset $pos';
        break;
      }
      pos = key.next;
      var number = key.value >> 3;
      var wire = (key.value & BigInt.from(7)).toInt();
      if (number < BigInt.one || number > BigInt.from(536870911)) {
        error = 'invalid field number $number at offset ${key.next}';
        break;
      }

      var field = <String, dynamic>{'number': number.toInt(), 'wireType': wire};
      if (wire == 0) {
        var value = _readVarint(bytes, pos);
        if (value == null) {
          error = 'truncated varint for field ${number.toInt()} at offset $pos';
          break;
        }
        pos = value.next;
        field['value'] = _varintValue(value.value);
      } else if (wire == 1) {
        if (pos + 8 > bytes.length) {
          error = 'truncated fixed64 for field ${number.toInt()} at offset $pos';
          break;
        }
        field['type'] = 'fixed64';
        field['hex'] = _hex(bytes.sublist(pos, pos + 8));
        pos += 8;
      } else if (wire == 5) {
        if (pos + 4 > bytes.length) {
          error = 'truncated fixed32 for field ${number.toInt()} at offset $pos';
          break;
        }
        field['type'] = 'fixed32';
        field['hex'] = _hex(bytes.sublist(pos, pos + 4));
        pos += 4;
      } else if (wire == 2) {
        var lengthValue = _readVarint(bytes, pos);
        if (lengthValue == null) {
          error = 'truncated length for field ${number.toInt()} at offset $pos';
          break;
        }
        pos = lengthValue.next;
        if (lengthValue.value > BigInt.from(0x7fffffff)) {
          error = 'invalid length ${lengthValue.value} for field ${number.toInt()}';
          break;
        }
        var length = lengthValue.value.toInt();
        if (pos + length > bytes.length) {
          error = 'truncated bytes for field ${number.toInt()} at offset $pos (need $length)';
          break;
        }
        var payload = Uint8List.sublistView(bytes, pos, pos + length);
        pos += length;
        field.addAll(_classify(payload, depth, maxDepth, maxFields));
      } else {
        // 3/4 是已废弃的 group，6/7 非法；不猜测边界，直接停止。
        error = 'unsupported wire type $wire for field ${number.toInt()} at offset $pos';
        break;
      }
      fields.add(field);
    }

    return _MessageResult(fields, error, truncated);
  }

  static Map<String, dynamic> _classify(Uint8List payload, int depth, int maxDepth, int maxFields) {
    if (payload.isEmpty) {
      return {'type': 'bytes', 'length': 0, 'hex': ''};
    }
    var text = _printableUtf8(payload);
    if (text != null) {
      return {'type': 'string', 'value': text};
    }
    if (depth < maxDepth) {
      var nested = _decodeMessage(payload, depth + 1, maxDepth, maxFields);
      if (nested.error == null && nested.fields.isNotEmpty) {
        return {
          'type': 'message',
          'fields': nested.fields,
          'fieldCount': nested.fields.length,
        };
      }
    }
    return {
      'type': 'bytes',
      'length': payload.length,
      'hex': payload.length <= 64 ? _hex(payload) : '${_hex(payload.sublist(0, 64))}...',
    };
  }

  static String? _printableUtf8(Uint8List payload) {
    String text;
    try {
      text = utf8.decode(payload);
    } catch (_) {
      return null;
    }
    for (var rune in text.runes) {
      if (rune == 0x09 || rune == 0x0a || rune == 0x0d) continue;
      if (rune < 0x20 || rune == 0x7f) return null;
    }
    return text;
  }

  static _Varint? _readVarint(Uint8List bytes, int start) {
    var value = BigInt.zero;
    var shift = 0;
    var pos = start;
    while (pos < bytes.length && shift < 70) {
      var byte = bytes[pos++];
      value |= BigInt.from(byte & 0x7f) << shift;
      if ((byte & 0x80) == 0) return _Varint(value, pos);
      shift += 7;
    }
    return null;
  }

  static dynamic _varintValue(BigInt value) {
    if (value.bitLength <= 63) return value.toInt();
    if (value.bitLength <= 64) {
      return {'unsigned': value.toString(), 'signed': value.toSigned(64).toString()};
    }
    return value.toString();
  }

  static String _hex(List<int> bytes) =>
      bytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();
}

class _Varint {
  final BigInt value;
  final int next;

  _Varint(this.value, this.next);
}

class _MessageResult {
  final List<Map<String, dynamic>> fields;
  final String? error;
  final bool truncated;

  _MessageResult(this.fields, this.error, this.truncated);
}
