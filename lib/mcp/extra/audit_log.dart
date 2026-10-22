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
import 'dart:io';

import 'package:proxypin/storage/path.dart';

/// MCP 工具调用审计日志（opt-in）。
///
/// 只在设置里开启后写入；每次写入前对参数做一次脱敏，任何看起来像凭证的键
/// 都替换为 `<redacted>`。日志是 JSON Lines，超过 [maxBytes] 时从最旧的行开始丢弃，
/// 因此文件大小有界、不会因长时间运行无限增长。
class AuditLog {
  /// 文件大小上限，默认 256 KB。
  final int maxBytes;

  /// 裁剪后保留的近似大小：只保留能放进 [maxBytes] 一半的最新条目。
  int get _keepBytes => maxBytes ~/ 2;

  final bool Function() _enabled;
  final Future<File> Function() _fileProvider;

  /// 串行化写入，避免并发 append 交错；失败会被吞掉，不能影响 MCP 请求本身。
  Future<void> _queue = Future<void>.value();

  AuditLog({
    required bool Function() enabled,
    Future<File> Function()? fileProvider,
    this.maxBytes = 256 * 1024,
  })  : _enabled = enabled,
        _fileProvider = fileProvider ?? (() => Paths.getPath('mcp_audit.jsonl'));

  bool get isEnabled => _enabled();

  /// 记录一次 tools/call。未开启时直接返回，不产生 IO。
  Future<void> record({
    required String tool,
    Map<String, dynamic>? arguments,
    required String client,
    String? userAgent,
    required Duration elapsed,
    required bool ok,
    String? error,
  }) {
    if (!isEnabled) return Future<void>.value();
    var entry = <String, dynamic>{
      'ts': DateTime.now().toUtc().toIso8601String(),
      'tool': tool,
      'client': client,
      'ok': ok,
      'elapsedMs': elapsed.inMilliseconds,
      if (arguments != null && arguments.isNotEmpty) 'args': _summarize(arguments),
      if (userAgent != null && userAgent.isNotEmpty) 'ua': _truncate(userAgent, 80),
      if (error != null && error.isNotEmpty) 'error': _truncate(error, 300),
    };
    var line = jsonEncode(entry);
    return _enqueue(() => _append(line));
  }

  /// 读取最新 [limit] 条记录（按时间正序返回）。
  Future<List<Map<String, dynamic>>> read({int limit = 100}) async {
    // 等已排队的写入落盘，避免刚调用完工具就读不到自己的记录。
    await _queue;
    var file = await _fileProvider();
    if (!await file.exists()) return [];
    var lines = await file.readAsLines();
    var start = lines.length > limit ? lines.length - limit : 0;
    var entries = <Map<String, dynamic>>[];
    for (var line in lines.sublist(start)) {
      if (line.trim().isEmpty) continue;
      try {
        var decoded = jsonDecode(line);
        if (decoded is Map<String, dynamic>) entries.add(decoded);
      } catch (_) {
        // 手动编辑或写到一半的行直接跳过，不让一条坏行毁掉整个读取。
      }
    }
    return entries;
  }

  Future<void> _enqueue(Future<void> Function() action) {
    var next = _queue.then((_) => action()).catchError((_) {});
    _queue = next;
    return next;
  }

  Future<void> _append(String line) async {
    var file = await _fileProvider();
    var bytes = utf8.encode('$line\n');
    var length = await file.exists() ? await file.length() : 0;
    if (length + bytes.length > maxBytes) {
      await _trim(file, incomingBytes: bytes.length);
    }
    await file.writeAsString('$line\n', mode: FileMode.append, flush: true);
  }

  Future<void> _trim(File file, {required int incomingBytes}) async {
    if (!await file.exists()) return;
    var lines = await file.readAsLines();
    var total = incomingBytes;
    var start = lines.length;
    while (start > 0) {
      var lineBytes = utf8.encode(lines[start - 1]).length + 1;
      if (total + lineBytes > _keepBytes) break;
      start--;
      total += lineBytes;
    }
    var kept = lines.sublist(start);
    await file.writeAsString(kept.isEmpty ? '' : '${kept.join('\n')}\n');
  }

  static const List<String> _sensitiveHints = [
    'authorization',
    'cookie',
    'token',
    'secret',
    'password',
    'passwd',
    'pwd',
    'apikey',
    'api_key',
    'api-key',
    'access_key',
    'access-key',
    'private_key',
    'private-key',
    'credential',
    'session_id',
    'sessionid',
  ];

  /// 递归替换敏感键。深度限制避免异常嵌套把日志写出花来。
  static dynamic redactValue(dynamic value, {int depth = 0}) {
    if (depth > 4) return '...';
    if (value is Map) {
      var result = <String, dynamic>{};
      value.forEach((key, child) {
        var name = key.toString();
        var hint = name.toLowerCase();
        result[name] =
            _sensitiveHints.any((item) => hint.contains(item)) ? '<redacted>' : redactValue(child, depth: depth + 1);
      });
      return result;
    }
    if (value is List) {
      return [for (var child in value) redactValue(child, depth: depth + 1)];
    }
    if (value is String) return _truncate(value, 512);
    return value;
  }

  static dynamic _summarize(Map<String, dynamic> args) {
    try {
      var redacted = redactValue(args);
      var text = jsonEncode(redacted);
      if (text.length <= 1024) return redacted;
      return {'_truncated': true, 'preview': _truncate(text, 1024)};
    } catch (_) {
      return {'_error': '<unserializable arguments>'};
    }
  }

  static String _truncate(String value, int max) {
    if (value.length <= max) return value;
    return '${value.substring(0, max)}...(${value.length} chars)';
  }
}
