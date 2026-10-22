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
import 'dart:io' hide HttpHeaders;
import 'dart:typed_data';

import 'package:proxypin/network/components/interceptor.dart';
import 'package:proxypin/network/http/http.dart';
import 'package:proxypin/network/http/http_headers.dart';
import 'package:proxypin/storage/path.dart';
import 'package:proxypin/utils/aes.dart';

/// 一条透明加密档：把线上密文与本地明文互相转换。
///
/// 档位只描述「body 怎么解/怎么加」，是否命中由 [applyTo] 决定。密文在 body 里的
/// 表示形式由 [encoding] 指定（raw / base64 / hex），加解密算法当前支持
/// AES-CBC / AES-ECB + PKCS7 / ZeroPadding / NoPadding。
class CryptoProfile {
  String name;
  String alg;
  String key;
  String keyEncoding;
  String? iv;
  String ivEncoding;
  String encoding;
  bool enabled;
  CryptoApply applyTo;

  CryptoProfile({
    required this.name,
    this.alg = 'AES/CBC/PKCS7',
    required this.key,
    this.keyEncoding = 'hex',
    this.iv,
    this.ivEncoding = 'hex',
    this.encoding = 'raw',
    this.enabled = true,
    this.applyTo = const CryptoApply(),
  });

  String get mode => _algParts.$1;
  String get padding => _algParts.$2;

  (String, String) get _algParts {
    var parts = alg.toUpperCase().split('/');
    if (parts.first != 'AES') throw ArgumentError('unsupported algorithm "$alg" (only AES)');
    var mode = parts.length > 1 ? parts[1] : 'CBC';
    var padding = parts.length > 2 ? parts[2] : 'PKCS7';
    if (mode != 'CBC' && mode != 'ECB') {
      throw ArgumentError('unsupported AES mode "$mode" (CBC/ECB)');
    }
    var normalizedPadding = switch (padding) {
      'PKCS5' => 'PKCS7',
      'ZERO' || 'ZEROPADDING' => 'ZeroPadding',
      'NONE' || 'NOPADDING' => 'NoPadding',
      _ => padding,
    };
    if (!{'PKCS7', 'ZeroPadding', 'NoPadding'}.contains(normalizedPadding)) {
      throw ArgumentError('unsupported padding "$padding" (PKCS7/ZeroPadding/NoPadding)');
    }
    return (mode, normalizedPadding);
  }

  Uint8List get keyBytes => _decodeBytes(key, keyEncoding);
  Uint8List? get ivBytes => iv == null ? null : _decodeBytes(iv!, ivEncoding);

  bool matches(HttpRequest? request, HttpHeaders headers) {
    if (request == null) return false;
    if (!applyTo.matchesHost(request.requestUri?.host ?? request.hostAndPort?.host ?? '')) return false;
    if (!applyTo.matchesPath(request.requestUri?.path ?? request.path)) return false;
    if (!applyTo.matchesHeaders(headers)) return false;
    return true;
  }

  /// 把 body 的线上字节解成明文；格式/填充不对会抛异常，由调用方兜底。
  Uint8List decryptBody(Uint8List wire) {
    var cipher = _decodeBody(wire, encoding);
    var keyLength = keyBytes.length * 8;
    return AesUtils.decrypt(cipher,
        key: _pemKey(keyBytes), keyLength: keyLength, mode: mode, padding: padding, iv: _ivArgument);
  }

  Uint8List encryptBody(Uint8List plaintext) {
    var cipher = AesUtils.encrypt(plaintext,
        key: _pemKey(keyBytes), keyLength: keyBytes.length * 8, mode: mode, padding: padding, iv: _ivArgument);
    return _encodeBody(cipher, encoding);
  }

  String get _ivArgument {
    var bytes = ivBytes;
    return bytes == null ? '' : 'base64:${base64.encode(bytes)}';
  }

  static String _pemKey(Uint8List bytes) => 'base64:${base64.encode(bytes)}';

  Map<String, dynamic> toJson() => {
        'name': name,
        'alg': alg,
        'key': key,
        'keyEncoding': keyEncoding,
        if (iv != null) 'iv': iv,
        if (iv != null) 'ivEncoding': ivEncoding,
        'encoding': encoding,
        'enabled': enabled,
        'applyTo': applyTo.toJson(),
      };

  factory CryptoProfile.fromJson(Map<String, dynamic> json) => CryptoProfile(
        name: json['name']?.toString() ?? '',
        alg: json['alg']?.toString() ?? 'AES/CBC/PKCS7',
        key: json['key']?.toString() ?? '',
        keyEncoding: json['keyEncoding']?.toString() ?? 'hex',
        iv: json['iv']?.toString(),
        ivEncoding: json['ivEncoding']?.toString() ?? 'hex',
        encoding: json['encoding']?.toString() ?? 'raw',
        enabled: json['enabled'] != false,
        applyTo: CryptoApply.fromJson((json['applyTo'] as Map?)?.cast<String, dynamic>() ?? const {}),
      );

  /// 对外展示时隐藏密钥内容，只给长度和编码。
  Map<String, dynamic> toPublicJson() {
    var keySize = keyBytes.length;
    return {
      'name': name,
      'alg': alg,
      'keyEncoding': keyEncoding,
      'keyBytes': keySize,
      'hasIv': iv != null,
      'encoding': encoding,
      'enabled': enabled,
      'applyTo': applyTo.toJson(),
    };
  }

  static Uint8List _decodeBytes(String value, String encoding) {
    switch (encoding.toLowerCase()) {
      case 'base64':
        return base64.decode(value);
      case 'utf8':
      case 'text':
        return Uint8List.fromList(utf8.encode(value));
      default:
        var clean = value.replaceAll(RegExp(r'[^0-9a-fA-F]'), '');
        if (clean.length.isOdd) throw ArgumentError('hex value has odd length');
        var out = Uint8List(clean.length ~/ 2);
        for (var i = 0; i < out.length; i++) {
          out[i] = int.parse(clean.substring(i * 2, i * 2 + 2), radix: 16);
        }
        return out;
    }
  }

  static Uint8List _decodeBody(Uint8List bytes, String encoding) {
    switch (encoding.toLowerCase()) {
      case 'base64':
        return base64.decode(ascii.decode(bytes, allowInvalid: true).replaceAll(RegExp(r'\s'), ''));
      case 'hex':
        return _decodeBytes(ascii.decode(bytes, allowInvalid: true), 'hex');
      default:
        return bytes;
    }
  }

  static Uint8List _encodeBody(Uint8List cipher, String encoding) {
    switch (encoding.toLowerCase()) {
      case 'base64':
        return Uint8List.fromList(ascii.encode(base64.encode(cipher)));
      case 'hex':
        return Uint8List.fromList(ascii.encode(cipher.map((b) => b.toRadixString(16).padLeft(2, '0')).join()));
      default:
        return cipher;
    }
  }
}

/// 命中条件；全部为空会被注册工具拒绝，避免误伤所有流量。
class CryptoApply {
  final String hostPattern;
  final String pathPattern;
  final List<String> contentTypes;
  final String? headerHint;

  const CryptoApply({
    this.hostPattern = '',
    this.pathPattern = '',
    this.contentTypes = const [],
    this.headerHint,
  });

  bool matchesHost(String host) => hostPattern.isEmpty || _glob(hostPattern, host, ignoreCase: true);

  bool matchesPath(String path) => pathPattern.isEmpty || _glob(pathPattern, path);

  bool matchesHeaders(HttpHeaders headers) {
    if (contentTypes.isNotEmpty) {
      var contentType = headers.get('content-type')?.split(';').first.trim().toLowerCase();
      if (contentType == null || !contentTypes.any((type) => type.toLowerCase() == contentType)) return false;
    }
    var hint = headerHint;
    if (hint != null && hint.trim().isNotEmpty) {
      var index = hint.indexOf(':');
      if (index <= 0) return false;
      var name = hint.substring(0, index).trim();
      var value = hint.substring(index + 1).trim();
      var actual = headers.get(name);
      if (actual == null) return false;
      if (value.isNotEmpty && actual.trim() != value) return false;
    }
    return true;
  }

  Map<String, dynamic> toJson() => {
        if (hostPattern.isNotEmpty) 'hostPattern': hostPattern,
        if (pathPattern.isNotEmpty) 'pathPattern': pathPattern,
        if (contentTypes.isNotEmpty) 'contentTypes': contentTypes,
        if (headerHint != null && headerHint!.isNotEmpty) 'headerHint': headerHint,
      };

  factory CryptoApply.fromJson(Map<String, dynamic> json) => CryptoApply(
        hostPattern: json['hostPattern']?.toString() ?? '',
        pathPattern: json['pathPattern']?.toString() ?? '',
        contentTypes: (json['contentTypes'] as List?)
                ?.map((e) => e.toString().toLowerCase())
                .where((e) => e.isNotEmpty)
                .toList() ??
            const [],
        headerHint: json['headerHint']?.toString(),
      );

  /// 只支持 `*` 通配（与 ProxyPin 的 URL 规则一致的用法）。
  static bool _glob(String pattern, String value, {bool ignoreCase = false}) {
    var source = pattern.split('*').map(RegExp.escape).join('.*');
    return RegExp('^$source\$', caseSensitive: !ignoreCase).hasMatch(value);
  }
}

/// 加密档的进程内注册表 + 磁盘持久化（应用支持目录 `crypto_profiles.json`）。
class CryptoProfileStore {
  static final CryptoProfileStore instance = CryptoProfileStore._();

  CryptoProfileStore._();

  final List<CryptoProfile> profiles = [];
  Future<void>? _loading;

  /// 测试可注入临时文件；生产环境使用应用支持目录。
  Future<File> Function()? fileProvider;

  Future<File> _file() => fileProvider?.call() ?? Paths.getPath('crypto_profiles.json');

  Future<void> ensureLoaded() => _loading ??= _load();

  Future<void> _load() async {
    try {
      var file = await _file();
      if (!await file.exists()) return;
      var decoded = jsonDecode(await file.readAsString());
      var list = decoded is Map ? decoded['profiles'] : decoded;
      if (list is! List) return;
      profiles.clear();
      for (var item in list) {
        if (item is Map) {
          try {
            profiles.add(CryptoProfile.fromJson(item.cast<String, dynamic>()));
          } catch (_) {
            // 单条损坏不影响其余档位
          }
        }
      }
    } catch (_) {
      // 文件不可读时保持空表，工具仍可注册新档
    }
  }

  Future<void> save() async {
    var file = await _file();
    var tmp = File('${file.path}.tmp');
    await tmp.writeAsString(
        const JsonEncoder.withIndent('  ').convert({'version': 1, 'profiles': profiles.map((e) => e.toJson()).toList()}),
        flush: true);
    if (await file.exists()) await file.delete();
    await tmp.rename(file.path);
  }

  CryptoProfile? match(HttpRequest? request, HttpHeaders headers) {
    if (request == null) return null;
    for (var profile in profiles) {
      if (profile.enabled && profile.matches(request, headers)) return profile;
    }
    return null;
  }

  CryptoProfile? byName(String name) {
    for (var profile in profiles) {
      if (profile.name == name) return profile;
    }
    return null;
  }
}

/// 单条消息在「明文态 / 线上态」之间切换所需的状态。
class CryptoHandle {
  final CryptoProfile profile;

  /// 解密前线上字节；为 null 表示解密失败、把当前 body 当作明文（例如重放）。
  final Uint8List? originalWire;
  final Uint8List plaintext;
  final bool assumedPlaintext;

  /// 原始 body 的 Content-Encoding；把原密文写回线上时需要一并恢复。
  final String? contentEncoding;

  CryptoHandle({
    required this.profile,
    required this.originalWire,
    required this.plaintext,
    this.assumedPlaintext = false,
    this.contentEncoding,
  });
}

/// 透明解密拦截器：在其它拦截器（脚本、断点、重写）之前把 body 换成明文。
///
/// 明文只存在于内存对象里；真正写 socket 前由 [CryptoTransparent.writeRequest] /
/// [CryptoTransparent.writeResponse] 临时换回密文，写完再恢复明文。因此 MCP 与 UI
/// 看到的是明文，线上仍是原密文；断点/脚本改过的明文会被重新加密。
class CryptoInterceptor extends Interceptor {
  @override
  int get priority => -500;

  @override
  Future<HttpRequest?> onRequest(HttpRequest request) async {
    await CryptoTransparent.decryptRequest(request);
    return request;
  }

  @override
  Future<HttpResponse?> onResponse(HttpRequest request, HttpResponse response) async {
    await CryptoTransparent.decryptResponse(response);
    return response;
  }
}

class CryptoTransparent {
  static final CryptoProfileStore store = CryptoProfileStore.instance;
  static final Map<String, CryptoHandle> _requestHandles = {};
  static final Map<String, CryptoHandle> _responseHandles = {};
  static const int _maxHandles = 512;

  static Future<void> decryptRequest(HttpRequest request) async {
    await store.ensureLoaded();
    var body = request.body;
    if (body == null || body.isEmpty) return;
    var profile = store.match(request, request.headers);
    if (profile == null) return;

    var wire = Uint8List.fromList(body);
    var contentEncoding = request.headers.get('content-encoding');
    try {
      var plaintext = profile.decryptBody(wire);
      _putHandle(
          _requestHandles,
          request.requestId,
          CryptoHandle(
              profile: profile,
              originalWire: wire,
              plaintext: plaintext,
              contentEncoding: contentEncoding));
      _replaceBody(request, plaintext);
    } catch (e) {
      // 重放/手工构造的请求 body 已是明文：保留明文并记录为「待加密」。
      // 只在 body 看起来是文本时兜底，避免把别的二进制格式二次加密。
      if (_looksLikeText(wire)) {
        _putHandle(_requestHandles, request.requestId,
            CryptoHandle(profile: profile, originalWire: null, plaintext: wire, assumedPlaintext: true));
        request.attributes['cryptoAssumedPlaintext'] = true;
      } else {
        request.attributes['cryptoError'] = '$e';
      }
    }
  }

  static Future<void> decryptResponse(HttpResponse response) async {
    await store.ensureLoaded();
    var body = response.body;
    if (body == null || body.isEmpty) return;
    var request = response.request;
    var profile = store.match(request, response.headers);
    if (profile == null) return;

    var wire = Uint8List.fromList(body);
    var contentEncoding = response.headers.get('content-encoding');
    try {
      var plaintext = profile.decryptBody(wire);
      _putHandle(
          _responseHandles,
          _responseKey(response),
          CryptoHandle(
              profile: profile,
              originalWire: wire,
              plaintext: plaintext,
              contentEncoding: contentEncoding));
      _replaceBody(response, plaintext);
    } catch (_) {
      // 响应解密失败就保持原样；不对响应做「明文兜底」（服务端不会发明文）。
    }
  }

  /// 在真正写上游前把请求 body 换成密文，完成后恢复明文。
  ///
  /// [write] 内部必须同步完成编码（现有 Channel.write 会先 encode 再 await），
  /// 否则恢复明文可能早于编码。
  static Future<T> writeRequest<T>(HttpRequest request, Future<T> Function() write) async {
    var handle = _requestHandles[request.requestId];
    if (handle == null || request.body == null) return write();
    var plaintext = Uint8List.fromList(request.body!);
    var unchanged = handle.originalWire != null && _equal(plaintext, handle.plaintext);
    var wire = unchanged ? handle.originalWire! : handle.profile.encryptBody(plaintext);
    _replaceBody(request, wire, dropContentEncoding: !unchanged);
    if (unchanged && handle.contentEncoding != null) {
      request.headers.set('content-encoding', handle.contentEncoding!);
    }
    try {
      return await write();
    } finally {
      // 保留 handle：同一请求对象可能被重试/再次改写；表本身有 512 条上限。
      _replaceBody(request, plaintext);
    }
  }

  static Future<T> writeResponse<T>(HttpResponse response, Future<T> Function() write) async {
    var key = _responseKey(response);
    var handle = _responseHandles[key];
    if (handle == null || response.body == null) return write();
    var plaintext = Uint8List.fromList(response.body!);
    var unchanged = handle.originalWire != null && _equal(plaintext, handle.plaintext);
    var wire = unchanged ? handle.originalWire! : handle.profile.encryptBody(plaintext);
    _replaceBody(response, wire, dropContentEncoding: !unchanged);
    if (unchanged && handle.contentEncoding != null) {
      response.headers.set('content-encoding', handle.contentEncoding!);
    }
    try {
      return await write();
    } finally {
      _replaceBody(response, plaintext);
      _responseHandles.remove(key);
    }
  }

  /// 探测用：尝试按档位解密一段 body，失败返回 null（不改变任何状态）。
  static Uint8List? tryDecrypt(CryptoProfile profile, Uint8List body) {
    try {
      return profile.decryptBody(body);
    } catch (_) {
      return null;
    }
  }

  static String _responseKey(HttpResponse response) =>
      response.request?.requestId ?? response.requestId;

  static void _putHandle(Map<String, CryptoHandle> map, String key, CryptoHandle handle) {
    if (map.length >= _maxHandles) {
      map.remove(map.keys.first);
    }
    map[key] = handle;
  }

  static void _replaceBody(HttpMessage message, Uint8List body, {bool dropContentEncoding = true}) {
    message.body = body;
    message.headers.contentLength = body.length;
    message.headers.remove('transfer-encoding');
    if (dropContentEncoding) message.headers.remove('content-encoding');
  }

  static bool _equal(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }

  static bool _looksLikeText(Uint8List bytes) {
    if (bytes.isEmpty) return false;
    try {
      var text = utf8.decode(bytes);
      if (text.isEmpty) return false;
      var printable = text.runes.where((r) => r == 9 || r == 10 || r == 13 || (r >= 32 && r != 127)).length;
      return printable / text.runes.length > 0.9;
    } catch (_) {
      return false;
    }
  }
}

/// 密文特征检测：只根据样本分块/重复率/可打印性给出模式猜测。
///
/// 不产生密钥候选 —— 密钥在 so/dex 或运行时参数里，需由 r2/Unidbg 侧产出后
/// 再通过 register_crypto_profile 导入。
class CryptoDetector {
  static const int minSampleBytes = 32;

  static Map<String, dynamic> detect(
    List<HttpRequest> flows, {
    required String host,
    String? path,
    int maxSamples = 10,
  }) {
    var samples = <Map<String, dynamic>>[];
    for (var flow in flows) {
      if (flow.requestUri?.host != host && !flow.requestUrl.contains(host)) continue;
      if (path != null && path.isNotEmpty && !flow.path.startsWith(path)) continue;
      for (var entry in [
        ('request', flow as HttpMessage),
        ('response', flow.response as HttpMessage?),
      ]) {
        var message = entry.$2;
        if (message == null) continue;
        var body = message.body;
        if (body == null || body.length < minSampleBytes) continue;
        if (!_isBinaryLike(message, body)) continue;
        var shape = _shape(Uint8List.fromList(body));
        if (shape == null) continue;
        samples.add({'side': entry.$1, 'id': flow.requestId, ...shape});
        if (samples.length >= maxSamples) break;
      }
      if (samples.length >= maxSamples) break;
    }

    if (samples.isEmpty) {
      return {
        'host': host,
        if (path != null) 'path': path,
        'samples': 0,
        'blockSize': null,
        'mode': null,
        'padding': null,
        'keyCandidates': const [],
        'note': '没有找到可分析的二进制 body。先触发该接口，或确认加密档的 contentTypes 不是 text/json。',
      };
    }

    var blockVotes = <int, int>{};
    var modeVotes = <String, int>{};
    var encodingVotes = <String, int>{};
    var aligned = 0;
    var repeatedTotal = 0;
    for (var sample in samples) {
      var blockSize = sample['blockSize'] as int;
      blockVotes[blockSize] = (blockVotes[blockSize] ?? 0) + 1;
      var mode = sample['mode'] as String;
      modeVotes[mode] = (modeVotes[mode] ?? 0) + 1;
      var encoding = sample['encoding'] as String;
      encodingVotes[encoding] = (encodingVotes[encoding] ?? 0) + 1;
      if (sample['aligned'] == true) aligned++;
      repeatedTotal += sample['repeatedBlocks'] as int;
    }
    var blockSize = _topKey(blockVotes);
    var mode = _topKey(modeVotes);
    var encoding = _topKey(encodingVotes);
    var agreeing = ((blockVotes[blockSize] ?? 0) / samples.length).clamp(0.0, 1.0);
    var confidence = (0.35 + agreeing * 0.35 + (repeatedTotal > 0 ? 0.2 : 0.0)).clamp(0.0, 0.95);

    return {
      'host': host,
      if (path != null) 'path': path,
      'samples': samples.length,
      'blockSize': blockSize,
      'mode': mode,
      'padding': aligned == samples.length ? 'PKCS7' : 'unknown',
      'encoding': encoding,
      'repeatedBlocks': repeatedTotal,
      'confidence': double.parse(confidence.toStringAsFixed(2)),
      'keyCandidates': const [],
      'sampleShapes': samples.take(5).toList(),
      'note': 'Block size / mode / padding are inferred from ciphertext shape only. '
          'mode=ECB means repeated ciphertext blocks were observed; CBC is indistinguishable from random data. '
          'Key material must come from static analysis (r2/Unidbg) and be imported with register_crypto_profile.',
    };
  }

  static bool _isBinaryLike(HttpMessage message, List<int> body) {
    var contentType = message.headers.contentType.toLowerCase();
    if (contentType.contains('json') ||
        contentType.contains('text/') ||
        contentType.contains('xml') ||
        contentType.contains('x-www-form-urlencoded')) {
      return false;
    }
    var sample = body.length > 512 ? body.sublist(0, 512) : body;
    var printable = sample.where((b) => b == 9 || b == 10 || b == 13 || (b >= 32 && b != 127)).length;
    return printable / sample.length < 0.85;
  }

  static Map<String, dynamic>? _shape(Uint8List bytes) {
    Map<String, dynamic>? best;
    var bestScore = -1;
    for (var encoding in const ['raw', 'base64', 'hex']) {
      Uint8List decoded;
      try {
        decoded = switch (encoding) {
          'base64' => base64.decode(ascii.decode(bytes, allowInvalid: true).replaceAll(RegExp(r'\s'), '')),
          'hex' => _hex(ascii.decode(bytes, allowInvalid: true)),
          _ => bytes,
        };
      } catch (_) {
        continue;
      }
      if (decoded.length < minSampleBytes) continue;
      var block16 = decoded.length % 16 == 0;
      var block8 = decoded.length % 8 == 0;
      if (!block16 && !block8) continue;
      var blockSize = block16 ? 16 : 8;
      var repeats = _repeatedBlocks(decoded, blockSize);
      var printable = _printableRatio(decoded);
      var score = (block16 ? 2 : 1) + (repeats > 0 ? 2 : 0) + (printable < 0.3 ? 1 : 0);
      if (encoding != 'raw' && printable > 0.7) score -= 1;
      if (score > bestScore) {
        bestScore = score;
        best = {
          'encoding': encoding,
          'blockSize': blockSize,
          'mode': repeats > 0 ? 'ECB' : 'CBC/unknown',
          'aligned': block16,
          'repeatedBlocks': repeats,
          'bytes': decoded.length,
        };
      }
    }
    return best;
  }

  static int _repeatedBlocks(Uint8List bytes, int blockSize) {
    var seen = <String>{};
    var repeats = 0;
    for (var offset = 0; offset + blockSize <= bytes.length; offset += blockSize) {
      var block = base64.encode(bytes.sublist(offset, offset + blockSize));
      if (!seen.add(block)) repeats++;
    }
    return repeats;
  }

  static double _printableRatio(Uint8List bytes) {
    if (bytes.isEmpty) return 1;
    var printable = bytes.where((b) => b == 9 || b == 10 || b == 13 || (b >= 32 && b != 127)).length;
    return printable / bytes.length;
  }

  static Uint8List _hex(String text) {
    var clean = text.replaceAll(RegExp(r'[^0-9a-fA-F]'), '');
    if (clean.length.isOdd || clean.isEmpty) throw const FormatException('not hex');
    var out = Uint8List(clean.length ~/ 2);
    for (var i = 0; i < out.length; i++) {
      out[i] = int.parse(clean.substring(i * 2, i * 2 + 2), radix: 16);
    }
    return out;
  }

  static K _topKey<K>(Map<K, int> votes) => votes.entries.reduce((a, b) => a.value >= b.value ? a : b).key;
}
