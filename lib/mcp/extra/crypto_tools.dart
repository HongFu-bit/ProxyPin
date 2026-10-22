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

import 'package:proxypin/mcp/capture/flow_store.dart';
import 'package:proxypin/mcp/protocol/mcp_server.dart';
import 'package:proxypin/mcp/protocol/mcp_tool.dart';
import 'package:proxypin/network/components/crypto_transparent.dart';
import 'package:proxypin/network/http/http.dart';

/// 透明解密档的 MCP 工具面：注册 / 列表 / 启停 / 删除 / 密文特征探测。
class CryptoTools {
  final FlowStore store;

  CryptoTools(this.store);

  List<McpTool> tools() => [
        _register(),
        _list(),
        _remove(),
        _apply(),
        _detect(),
      ];

  McpTool _register() => McpTool(
        name: 'register_crypto_profile',
        description:
            'Register (or replace) a transparent crypto profile: while enabled, matching request/response bodies are '
            'decrypted for viewing/editing and re-encrypted just before they go on the wire. '
            'Ciphertext body format is set by `encoding` (raw/base64/hex). Algorithms: AES/CBC|ECB with '
            'PKCS7/ZeroPadding/NoPadding. At least one of applyTo.hostPattern / contentTypes / headerHint is required '
            'so a profile cannot silently hit all traffic. Use apply_crypto_profile to enable it.',
        inputSchema: {
          'type': 'object',
          'properties': {
            'name': {'type': 'string', 'description': 'Profile name, e.g. appA-body'},
            'alg': {'type': 'string', 'description': 'AES/CBC/PKCS7 (default), AES/ECB/PKCS7, AES/CBC/NoPadding …'},
            'keyHex': {'type': 'string'},
            'keyBase64': {'type': 'string'},
            'keyUtf8': {'type': 'string'},
            'key': {'type': 'string', 'description': 'Alternative to keyHex/keyBase64/keyUtf8'},
            'keyEncoding': {'type': 'string', 'description': 'hex (default) / base64 / utf8; used with key'},
            'ivHex': {'type': 'string'},
            'ivBase64': {'type': 'string'},
            'ivUtf8': {'type': 'string'},
            'iv': {'type': 'string', 'description': 'Alternative to ivHex/ivBase64/ivUtf8; required for CBC'},
            'ivEncoding': {'type': 'string', 'description': 'hex (default) / base64 / utf8; used with iv'},
            'encoding': {
              'type': 'string',
              'enum': ['raw', 'base64', 'hex'],
              'description': 'How ciphertext is stored in the HTTP body (default raw)',
            },
            'enabled': {'type': 'boolean', 'description': 'Default true'},
            'applyTo': {
              'type': 'object',
              'properties': {
                'hostPattern': {'type': 'string', 'description': 'Glob with *, e.g. *.example.com'},
                'pathPattern': {'type': 'string', 'description': 'Glob with *, e.g. /api/*'},
                'contentTypes': {
                  'type': 'array',
                  'items': {'type': 'string'},
                  'description': 'Exact media types before ";", e.g. application/octet-stream'
                },
                'headerHint': {'type': 'string', 'description': 'e.g. "X-Encrypted: 1" (name only also works)'},
              },
            },
          },
          'required': ['name'],
        },
        handler: (args) async {
          var name = args['name']?.toString().trim() ?? '';
          if (name.isEmpty) throw ToolException('name is required');

          var key = _pickEncoded(args, 'key', 'keyEncoding');
          if (key == null) throw ToolException('one of keyHex / keyBase64 / keyUtf8 (or key+keyEncoding) is required');
          var keyBytes = _decodeKey(key.value, key.encoding);
          if (![16, 24, 32].contains(keyBytes.length)) {
            throw ToolException('AES key must be 16/24/32 bytes after decoding, got ${keyBytes.length}');
          }

          var iv = _pickEncoded(args, 'iv', 'ivEncoding');
          var alg = args['alg']?.toString() ?? 'AES/CBC/PKCS7';
          var profile = CryptoProfile(
            name: name,
            alg: alg,
            key: key.value,
            keyEncoding: key.encoding,
            iv: iv?.value,
            ivEncoding: iv?.encoding ?? 'hex',
            encoding: args['encoding']?.toString() ?? 'raw',
            enabled: args['enabled'] != false,
            applyTo: CryptoApply.fromJson((args['applyTo'] as Map?)?.cast<String, dynamic>() ?? const {}),
          );
          // 访问派生属性会校验 alg/padding；提前失败，避免挂载后才报错。
          var mode = profile.mode;
          var padding = profile.padding;
          if (mode == 'CBC' && profile.iv == null) throw ToolException('iv is required for CBC mode');
          if (profile.iv != null) {
            var ivLength = _decodeKey(profile.iv!, profile.ivEncoding).length;
            if (ivLength != 16) throw ToolException('AES IV must be 16 bytes, got $ivLength');
          }
          if (!{'raw', 'base64', 'hex'}.contains(profile.encoding.toLowerCase())) {
            throw ToolException('encoding must be raw / base64 / hex');
          }
          if (profile.applyTo.hostPattern.isEmpty &&
              profile.applyTo.contentTypes.isEmpty &&
              (profile.applyTo.headerHint == null || profile.applyTo.headerHint!.isEmpty)) {
            throw ToolException('applyTo needs at least one of hostPattern / contentTypes / headerHint');
          }

          var store = CryptoProfileStore.instance;
          await store.ensureLoaded();
          var existing = store.byName(name);
          if (existing != null) {
            store.profiles.remove(existing);
          }
          store.profiles.add(profile);
          await store.save();

          return {
            'registered': true,
            'replaced': existing != null,
            'profile': profile.toPublicJson(),
            'algorithm': {'mode': mode, 'padding': padding},
            'note': 'Profile is ${profile.enabled ? 'enabled' : 'disabled'}. '
                'Transparent decryption runs in CryptoInterceptor (priority -500); wire bytes stay encrypted.',
          };
        },
      );

  McpTool _list() => McpTool(
        name: 'list_crypto_profiles',
        description: 'List registered transparent crypto profiles. Keys are masked; only encoding and byte length are shown.',
        inputSchema: {'type': 'object', 'properties': {}},
        handler: (_) async {
          var store = CryptoProfileStore.instance;
          await store.ensureLoaded();
          return {
            'count': store.profiles.length,
            'profiles': store.profiles.map((e) => e.toPublicJson()).toList(),
            'note': 'Key material is stored locally in crypto_profiles.json and never returned by this tool.',
          };
        },
      );

  McpTool _remove() => McpTool(
        name: 'remove_crypto_profile',
        description: 'Delete a transparent crypto profile by name. Matching traffic returns to untouched passthrough.',
        inputSchema: {
          'type': 'object',
          'properties': {
            'name': {'type': 'string'},
          },
          'required': ['name'],
        },
        handler: (args) async {
          var name = args['name']?.toString() ?? '';
          var store = CryptoProfileStore.instance;
          await store.ensureLoaded();
          var existing = store.byName(name);
          if (existing == null) throw ToolException('crypto profile not found: $name');
          store.profiles.remove(existing);
          await store.save();
          return {'removed': true, 'name': name, 'remaining': store.profiles.length};
        },
      );

  McpTool _apply() => McpTool(
        name: 'apply_crypto_profile',
        description:
            'Enable or disable a registered profile. mode=transparent turns on decrypt-on-read / encrypt-on-wire for '
            'matching traffic; mode=off restores passthrough. Takes effect immediately, no restart.',
        inputSchema: {
          'type': 'object',
          'properties': {
            'name': {'type': 'string'},
            'mode': {'type': 'string', 'enum': ['transparent', 'off'], 'description': 'Default transparent'},
          },
          'required': ['name'],
        },
        handler: (args) async {
          var name = args['name']?.toString() ?? '';
          var mode = (args['mode']?.toString() ?? 'transparent').toLowerCase();
          if (mode != 'transparent' && mode != 'off') {
            throw ToolException('mode must be transparent or off');
          }
          var store = CryptoProfileStore.instance;
          await store.ensureLoaded();
          var profile = store.byName(name);
          if (profile == null) throw ToolException('crypto profile not found: $name');
          profile.enabled = mode == 'transparent';
          await store.save();
          return {
            'name': name,
            'enabled': profile.enabled,
            'mode': mode,
            'interceptor': 'CryptoInterceptor(priority=-500)',
            'note': profile.enabled
                ? 'Matching bodies are shown/edited as plaintext and re-encrypted before write. '
                    'If decryption fails, a text body is treated as plaintext and encrypted on the wire.'
                : 'Profile disabled; traffic passes through untouched.',
          };
        },
      );

  McpTool _detect() => McpTool(
        name: 'detect_crypto_profile',
        description:
            'Inspect captured binary bodies for a host/path and guess block size, ECB-vs-CBC and padding from '
            'ciphertext shape. Produces no key material — import keys found by r2/Unidbg with register_crypto_profile. '
            'Decryption is not attempted, so output is a hint, not proof.',
        inputSchema: {
          'type': 'object',
          'properties': {
            'host': {'type': 'string', 'description': 'Required; substring or exact host'},
            'path': {'type': 'string', 'description': 'Optional path prefix filter'},
            'sampleLimit': {'type': 'integer', 'description': 'Max samples to inspect (default 10, cap 50)'},
            'history_id': {'type': 'integer', 'description': 'Saved history session id; omit for live capture'},
          },
          'required': ['host'],
        },
        handler: (args) async {
          var host = args['host']?.toString() ?? '';
          if (host.isEmpty) throw ToolException('host is required');
          var limit = (args['sampleLimit'] is num)
              ? (args['sampleLimit'] as num).toInt().clamp(1, 50)
              : 10;
          var historyId = args['history_id'] is num ? (args['history_id'] as num).toInt() : null;
          var flows = await _collectFlows(host: host, historyId: historyId, limit: 300);
          return CryptoDetector.detect(flows, host: host, path: args['path']?.toString(), maxSamples: limit);
        },
      );

  Future<List<HttpRequest>> _collectFlows({
    required String host,
    int? historyId,
    required int limit,
  }) async {
    const pageSize = 100;
    var result = <HttpRequest>[];
    var offset = 0;
    while (result.length < limit) {
      List<HttpRequest> page;
      if (historyId != null) {
        page = await store.historyQuery(historyId, limit: pageSize, offset: offset, host: host);
      } else {
        page = store.query(limit: pageSize, offset: offset, host: host);
      }
      result.addAll(page);
      if (page.length < pageSize) break;
      offset += page.length;
    }
    return result.length > limit ? result.sublist(0, limit) : result;
  }

  static ({String value, String encoding})? _pickEncoded(
      Map<String, dynamic> args, String base, String encodingField) {
    if (args['${base}Hex'] != null) return (value: args['${base}Hex'].toString(), encoding: 'hex');
    if (args['${base}Base64'] != null) return (value: args['${base}Base64'].toString(), encoding: 'base64');
    if (args['${base}Utf8'] != null) return (value: args['${base}Utf8'].toString(), encoding: 'utf8');
    var value = args[base]?.toString();
    if (value == null) return null;
    return (value: value, encoding: args[encodingField]?.toString() ?? (base == 'key' ? 'hex' : 'hex'));
  }

  static Uint8List _decodeKey(String value, String encoding) {
    switch (encoding.toLowerCase()) {
      case 'base64':
        return base64.decode(value);
      case 'utf8':
      case 'text':
        return Uint8List.fromList(utf8.encode(value));
      default:
        var clean = value.replaceAll(RegExp(r'[^0-9a-fA-F]'), '');
        if (clean.length.isOdd) throw ToolException('hex value has odd length');
        var out = Uint8List(clean.length ~/ 2);
        for (var i = 0; i < out.length; i++) {
          out[i] = int.parse(clean.substring(i * 2, i * 2 + 2), radix: 16);
        }
        return out;
    }
  }
}
