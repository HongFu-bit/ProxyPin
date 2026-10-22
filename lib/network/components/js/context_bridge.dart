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
import 'dart:math';
import 'dart:typed_data';

import 'package:flutter_js/flutter_js.dart';
import 'package:pointycastle/asn1/asn1_parser.dart';
import 'package:pointycastle/asn1/primitives/asn1_integer.dart';
import 'package:pointycastle/asn1/primitives/asn1_sequence.dart';
import 'package:pointycastle/export.dart';

import 'package:proxypin/mcp/mcp_service.dart';
import 'package:proxypin/network/util/crypto.dart';
import 'package:proxypin/utils/aes.dart';

/// 脚本上下文桥：`context.crypto` / `context.store` / `context.mcp`。
///
/// 所有值都走同一条 `sendMessage('proxypin_context', json)` 通道：
/// - 同步操作（hash/hmac/aes/base64/rsa）返回 JSON 字符串；
/// - [mcpCall] 返回 Future，flutter_js 会把它包装成 JS Promise。
///
/// 二进制输入支持字符串（默认 UTF-8）和 int 数组；输出默认 base64，
/// 调用方可用 `out: 'hex'|'bytes'|'utf8'` 指定。加解密只实现 AES-CBC/ECB +
/// PKCS7/ZeroPadding/NoPadding —— AesUtils 对其他 mode 名会静默按 ECB 处理，
/// 这里显式拒绝，避免用错算法却看不出错误。
class ContextBridge {
  static const String channel = 'proxypin_context';
  static const int maxMcpDepth = 5;
  static int _mcpDepth = 0;

  static const String _jsPrelude = r'''
function __proxypinUnwrap(res) {
  if (typeof res === 'string') return JSON.parse(res);
  return res;
}
function __proxypinCall(payload) {
  var res = __proxypinUnwrap(sendMessage('proxypin_context', JSON.stringify(payload)));
  if (!res || !res.ok) throw new Error((res && res.error) || 'proxypin bridge error');
  return res.value;
}
function __proxypinCallAsync(payload) {
  return sendMessage('proxypin_context', JSON.stringify(payload)).then(function (res) {
    res = __proxypinUnwrap(res);
    if (!res || !res.ok) throw new Error((res && res.error) || 'proxypin bridge error');
    return res.value;
  });
}
function __proxypinInitContext(ctx) {
  if (!ctx || ctx.__proxypin) return ctx;
  Object.defineProperty(ctx, '__proxypin', {value: true, enumerable: false});
  ctx.session = ctx.session || {};
  var crypto = {
    hash: function (algo, data, opts) {
      return __proxypinCall(Object.assign({op: 'hash', algo: algo, data: data}, opts || {}));
    },
    hmac: function (algo, key, data, opts) {
      return __proxypinCall(Object.assign({op: 'hmac', algo: algo, key: key, data: data}, opts || {}));
    },
    aesEncrypt: function (data, opts) {
      return __proxypinCall(Object.assign({op: 'aesEncrypt', data: data}, opts || {}));
    },
    aesDecrypt: function (data, opts) {
      return __proxypinCall(Object.assign({op: 'aesDecrypt', data: data}, opts || {}));
    },
    base64Encode: function (data, opts) {
      return __proxypinCall(Object.assign({op: 'base64Encode', data: data}, opts || {}));
    },
    base64Decode: function (data, opts) {
      return __proxypinCall(Object.assign({op: 'base64Decode', data: data}, opts || {}));
    },
    rsaSign: function (data, key, opts) {
      return __proxypinCall(Object.assign({op: 'rsaSign', data: data, key: key}, opts || {}));
    },
    rsaVerify: function (data, key, signature, opts) {
      return __proxypinCall(Object.assign({op: 'rsaVerify', data: data, key: key, signature: signature}, opts || {}));
    },
    randomBytes: function (n, opts) {
      return __proxypinCall(Object.assign({op: 'randomBytes', n: n}, opts || {}));
    }
  };
  var store = {
    get: function (key, defaultValue) {
      var v = ctx.session[key];
      return v === undefined ? defaultValue : v;
    },
    set: function (key, value) { ctx.session[key] = value; return value; },
    has: function (key) { return Object.prototype.hasOwnProperty.call(ctx.session, key); },
    remove: function (key) { delete ctx.session[key]; },
    keys: function () { return Object.keys(ctx.session); }
  };
  var mcp = {
    call: function (tool, args) {
      return __proxypinCallAsync({op: 'mcpCall', tool: tool, args: args || {}});
    }
  };
  // 枚举属性会被写回 scriptContext 并持久化，方法对象不落盘。
  Object.defineProperty(ctx, 'crypto', {value: crypto, enumerable: false, configurable: true});
  Object.defineProperty(ctx, 'store', {value: store, enumerable: false, configurable: true});
  Object.defineProperty(ctx, 'mcp', {value: mcp, enumerable: false, configurable: true});
  return ctx;
}
  ''';

  /// 注入 JS 全局函数并注册同步/异步回调。重复调用是幂等的。
  static void register(JavascriptRuntime flutterJs) {
    var channels = JavascriptRuntime.channelFunctionsRegistered[flutterJs.getEngineInstanceId()];
    if (channels != null && channels.containsKey(channel)) return;
    flutterJs.evaluate(_jsPrelude);
    flutterJs.onMessage(channel, handleRaw);
  }

  /// sendMessage 的原始回调；[raw] 通常是 JSON 字符串。
  static dynamic handleRaw(dynamic raw) {
    Map<String, dynamic> payload;
    try {
      if (raw is String) {
        payload = (jsonDecode(raw) as Map).cast<String, dynamic>();
      } else if (raw is Map) {
        payload = raw.cast<String, dynamic>();
      } else {
        return jsonEncode({'ok': false, 'error': 'unsupported bridge payload: ${raw.runtimeType}'});
      }
    } catch (e) {
      return jsonEncode({'ok': false, 'error': 'invalid bridge payload: $e'});
    }

    if (payload['op'] == 'mcpCall') {
      return _mcpCall(payload).then(jsonEncode, onError: (e) => jsonEncode({'ok': false, 'error': '$e'}));
    }
    try {
      return jsonEncode({'ok': true, 'value': handle(payload)});
    } catch (e) {
      return jsonEncode({'ok': false, 'error': '$e'});
    }
  }

  /// 同步操作入口；测试可直接调用。
  static dynamic handle(Map<String, dynamic> payload) {
    var op = payload['op']?.toString();
    switch (op) {
      case 'hash':
        return _hex(_digestBytes(_algo(payload['algo']), _toBytes(payload['data'], payload['in'])));
      case 'hmac':
        var mac = HMac.withDigest(_algo(payload['algo']));
        mac.init(KeyParameter(_keyBytes(payload['key'], payload['keyEncoding'])));
        return _hex(mac.process(_toBytes(payload['data'], payload['in'])));
      case 'aesEncrypt':
        return _aes(payload, encrypt: true);
      case 'aesDecrypt':
        return _aes(payload, encrypt: false);
      case 'base64Encode':
        return base64.encode(_toBytes(payload['data'], payload['in']));
      case 'base64Decode':
        return _emit(base64.decode(payload['data'].toString()), payload['out'] ?? 'utf8');
      case 'rsaSign':
        return _rsaSign(payload);
      case 'rsaVerify':
        return _rsaVerify(payload);
      case 'randomBytes':
        var n = (payload['n'] as num?)?.toInt() ?? 16;
        if (n < 0 || n > 4096) throw ArgumentError('n must be 0..4096');
        var random = Random.secure();
        return _emit(Uint8List.fromList(List.generate(n, (_) => random.nextInt(256))), payload['out'] ?? 'base64');
      default:
        throw ArgumentError('unknown op: $op');
    }
  }

  static Future<Map<String, dynamic>> _mcpCall(Map<String, dynamic> payload) async {
    var tool = payload['tool']?.toString();
    if (tool == null || tool.isEmpty) return {'ok': false, 'error': 'tool is required'};
    var server = McpService.instance.server;
    if (server == null || !McpService.instance.isRunning) {
      return {'ok': false, 'error': 'MCP service is not running'};
    }
    if (_mcpDepth >= maxMcpDepth) {
      return {'ok': false, 'error': 'context.mcp.call nested too deeply ($maxMcpDepth); possible recursion'};
    }
    _mcpDepth++;
    try {
      var args = (payload['args'] as Map?)?.cast<String, dynamic>() ?? <String, dynamic>{};
      var response = await server.handle({
        'jsonrpc': '2.0',
        'id': 1,
        'method': 'tools/call',
        'params': {'name': tool, 'arguments': args},
      });
      var error = response?['error'];
      if (error is Map) return {'ok': false, 'error': error['message']?.toString() ?? '$error'};
      var result = (response?['result'] as Map?)?.cast<String, dynamic>();
      var content = result?['content'];
      var text = '';
      if (content is List && content.isNotEmpty) {
        var first = content.first;
        if (first is Map) text = first['text']?.toString() ?? '';
      }
      if (result?['isError'] == true) return {'ok': false, 'error': text};
      dynamic value;
      try {
        value = jsonDecode(text);
      } catch (_) {
        value = text;
      }
      return {'ok': true, 'value': value};
    } catch (e) {
      return {'ok': false, 'error': '$e'};
    } finally {
      _mcpDepth--;
    }
  }

  // -------------------------------------------------------------- helpers

  static Digest _algo(dynamic name) {
    var algo = (name?.toString() ?? 'SHA-256').toUpperCase().replaceAll('_', '-');
    const supported = {'MD5', 'SHA-1', 'SHA-224', 'SHA-256', 'SHA-384', 'SHA-512'};
    if (!supported.contains(algo)) throw ArgumentError('unsupported digest: $name');
    return Digest(algo);
  }

  static Uint8List _digestBytes(Digest digest, Uint8List bytes) => digest.process(bytes);

  static Uint8List _keyBytes(dynamic key, dynamic encoding) {
    if (key is List) return _toBytes(key, 'bytes');
    var text = key?.toString() ?? '';
    var enc = encoding?.toString();
    if (enc == null) {
      if (text.startsWith('base64:')) {
        enc = 'base64';
        text = text.substring(7);
      } else if (text.startsWith('hex:')) {
        enc = 'hex';
        text = text.substring(4);
      }
    }
    return _toBytes(text, enc);
  }

  static dynamic _aes(Map<String, dynamic> payload, {required bool encrypt}) {
    var mode = (payload['mode']?.toString() ?? 'CBC').toUpperCase();
    if (mode != 'CBC' && mode != 'ECB') {
      throw ArgumentError('unsupported AES mode "$mode" (supported: CBC, ECB)');
    }
    var padding = (payload['padding']?.toString() ?? 'PKCS7');
    var normalPadding = switch (padding.toLowerCase()) {
      'pkcs7' || 'pkcs5' => 'PKCS7',
      'zero' || 'zeropadding' => 'ZeroPadding',
      'none' || 'nopadding' => 'NoPadding',
      _ => throw ArgumentError('unsupported padding "$padding" (supported: PKCS7, ZeroPadding, NoPadding)'),
    };

    var keyBytes = _keyBytes(payload['key'], payload['keyEncoding']);
    var keyLength = (payload['keyLength'] as num?)?.toInt() ?? keyBytes.length * 8;
    if (keyLength != 128 && keyLength != 192 && keyLength != 256) {
      throw ArgumentError('keyLength must be 128/192/256, got $keyLength');
    }
    var iv = payload['iv'] == null ? null : 'base64:${base64.encode(_keyBytes(payload['iv'], payload['ivEncoding']))}';
    if (mode == 'CBC' && iv == null) throw ArgumentError('iv is required for CBC mode');

    var input = _toBytes(payload['data'], payload['in']);
    var key = 'base64:${base64.encode(keyBytes)}';
    var output = encrypt
        ? AesUtils.encrypt(input, key: key, keyLength: keyLength, mode: mode, padding: normalPadding, iv: iv)
        : AesUtils.decrypt(input, key: key, keyLength: keyLength, mode: mode, padding: normalPadding, iv: iv);
    return _emit(output, payload['out'] ?? (encrypt ? 'base64' : 'utf8'));
  }

  static String _rsaSign(Map<String, dynamic> payload) {
    var privateKey = _privateKey(payload['key']?.toString() ?? '');
    var digest = _algo(payload['algo']);
    var signer = RSASigner(digest, _oid(digest.algorithmName));
    signer.init(true, PrivateKeyParameter<RSAPrivateKey>(privateKey));
    var signature = signer.generateSignature(_toBytes(payload['data'], payload['in']));
    return base64.encode(signature.bytes);
  }

  static bool _rsaVerify(Map<String, dynamic> payload) {
    var publicKey = CryptoUtils.rsaPublicKeyFromPem(payload['key']?.toString() ?? '');
    var signature = base64.decode(payload['signature']?.toString() ?? '');
    var digest = _algo(payload['algo']);
    var signer = RSASigner(digest, _oid(digest.algorithmName));
    signer.init(false, PublicKeyParameter<RSAPublicKey>(publicKey));
    return signer.verifySignature(_toBytes(payload['data'], payload['in']), RSASignature(signature));
  }

  static RSAPrivateKey _privateKey(String pem) {
    var bytes = CryptoUtils.getBytesFromPEMString(pem);
    if (!pem.contains('BEGIN RSA PRIVATE KEY')) return CryptoUtils.rsaPrivateKeyFromPem(pem);
    // PKCS#1：顶层 SEQUENCE 直接是 version/modulus/...，与 CryptoUtils 的 PKCS#8 解析不同。
    var seq = ASN1Parser(bytes).nextObject() as ASN1Sequence;
    var elements = seq.elements!;
    return RSAPrivateKey(
      (elements[1] as ASN1Integer).integer!,
      (elements[3] as ASN1Integer).integer!,
      (elements[4] as ASN1Integer).integer,
      (elements[5] as ASN1Integer).integer,
    );
  }

  static String _oid(String digestName) {
    const oids = {
      'MD5': '06082a864886f70d0205',
      'SHA-1': '06052b0e03021a',
      'SHA-224': '0609608648016503040204',
      'SHA-256': '0609608648016503040201',
      'SHA-384': '0609608648016503040202',
      'SHA-512': '0609608648016503040203',
    };
    var oid = oids[digestName];
    if (oid == null) throw ArgumentError('RSA signing does not support $digestName');
    return oid;
  }

  static Uint8List _toBytes(dynamic data, [dynamic encoding]) {
    if (data is List) {
      return Uint8List.fromList(data.map((e) => (e as num).toInt() & 0xff).toList());
    }
    var text = data?.toString() ?? '';
    switch ((encoding?.toString() ?? '').toLowerCase()) {
      case 'base64':
        return base64.decode(text);
      case 'hex':
        return _fromHex(text);
      case 'bytes':
        return Uint8List.fromList(text.codeUnits.map((e) => e & 0xff).toList());
      default:
        return Uint8List.fromList(utf8.encode(text));
    }
  }

  static dynamic _emit(Uint8List bytes, String out) {
    switch (out.toLowerCase()) {
      case 'hex':
        return _hex(bytes);
      case 'bytes':
        return bytes.toList();
      case 'utf8':
        return utf8.decode(bytes);
      default:
        return base64.encode(bytes);
    }
  }

  static String _hex(Uint8List bytes) =>
      bytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();

  static Uint8List _fromHex(String text) {
    var clean = text.replaceAll(RegExp(r'[^0-9a-fA-F]'), '');
    if (clean.length.isOdd) throw ArgumentError('hex string has odd length');
    var out = Uint8List(clean.length ~/ 2);
    for (var i = 0; i < out.length; i++) {
      out[i] = int.parse(clean.substring(i * 2, i * 2 + 2), radix: 16);
    }
    return out;
  }
}
