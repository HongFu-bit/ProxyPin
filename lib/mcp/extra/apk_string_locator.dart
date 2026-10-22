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

import 'package:archive/archive_io.dart';

/// 在 APK 的 `classes*.dex` / `.so` 中定位 URL 或路径字面量。
///
/// 这是字符串级证据：命中只说明该字面量存在于文件里，不证明哪段代码引用了它，
/// 也不做反编译或 xref。输出显式带 degraded 与限制说明。
class ApkStringLocator {
  static const int maxHitsDefault = 50;
  static const int maxHitsCap = 200;
  static const int maxEntryBytes = 128 * 1024 * 1024;
  static const int maxTotalBytes = 512 * 1024 * 1024;

  /// 把 URL 拆成可搜索的候选：完整 URL、path、较长的 path 段。
  /// 去掉纯数字段（id 通常是运行时拼进去的）。
  static List<String> candidates(String url) {
    var value = url.trim();
    if (value.isEmpty) return const [];
    var result = <String>{value};
    String path = '';
    try {
      var uri = Uri.parse(value);
      path = uri.path;
    } catch (_) {
      var index = value.indexOf('/');
      if (index >= 0) path = value.substring(index);
    }
    if (path.isNotEmpty && path != '/') {
      result.add(path);
      for (var segment in path.split('/')) {
        var clean = segment.split('?').first;
        if (clean.length >= 5 && !RegExp(r'^\d+$').hasMatch(clean)) {
          result.add(clean);
        }
      }
    }
    var list = result.where((item) => item.length >= 4).toList()
      ..sort((a, b) => b.length.compareTo(a.length));
    return list.take(8).toList();
  }

  /// 扫描 [apkPath]；[url] 用于生成候选字面量。
  /// 文件不是合法 zip 时由 [ZipDecoder] 抛异常，由调用方转成工具错误。
  static Future<Map<String, dynamic>> locate(
    String apkPath,
    String url, {
    int maxHits = maxHitsDefault,
  }) async {
    var limit = maxHits.clamp(1, maxHitsCap);
    var needles = candidates(url);
    var file = File(apkPath);
    var apkBytes = await file.length();
    await _ensureZip(file);

    var hits = <Map<String, dynamic>>[];
    var scannedEntries = <String>[];
    var entriesScanned = 0;
    var totalBytes = 0;
    var entryTooLarge = 0;
    var truncated = false;

    var input = InputFileStream(apkPath);
    try {
      var archive = ZipDecoder().decodeStream(input);
      for (var entry in archive) {
        if (!entry.isFile || !_isRelevant(entry.name)) continue;
        if (hits.length >= limit) {
          truncated = true;
          break;
        }
        if (entry.size > maxEntryBytes || totalBytes + entry.size > maxTotalBytes) {
          entryTooLarge++;
          truncated = true;
          continue;
        }
        Uint8List? bytes = entry.readBytes();
        if (bytes == null) continue;
        totalBytes += bytes.length;
        entriesScanned++;
        scannedEntries.add(entry.name);

        var kind = entry.name.toLowerCase().endsWith('.dex') ? 'dex' : 'so';
        var entryHits = <Map<String, dynamic>>[];
        var acceptedOffsets = <int>[];
        for (var needle in needles) {
          var needleBytes = utf8.encode(needle);
          var remaining = limit - hits.length;
          if (remaining <= 0) {
            truncated = true;
            break;
          }
          var offsets = _findAll(bytes, needleBytes, max: remaining);
          if (offsets.length >= remaining) truncated = true;
          for (var offset in offsets) {
            if (entryHits.length >= limit - hits.length) {
              truncated = true;
              break;
            }
            // 长候选（完整 URL）命中后，短候选在附近的同一区域不再重复上报。
            if (acceptedOffsets.any((value) => (value - offset).abs() <= needleBytes.length)) {
              continue;
            }
            acceptedOffsets.add(offset);
            entryHits.add({
              'entry': entry.name,
              'kind': kind,
              'offset': offset,
              'literal': needle,
              'contextHex': _contextHex(bytes, offset, needleBytes.length),
              if (kind == 'dex') 'classHint': _nearestClass(bytes, offset),
            });
          }
        }
        hits.addAll(entryHits);
      }
    } finally {
      await input.close();
    }

    return {
      'apk': apkPath,
      'apkBytes': apkBytes,
      'url': url,
      'candidates': needles,
      'entriesScanned': entriesScanned,
      'entries': scannedEntries,
      'hits': hits,
      'totalHits': hits.length,
      'truncated': truncated,
      if (entryTooLarge > 0) 'skippedLargeEntries': entryTooLarge,
      'degraded': true,
      'note': 'String-level evidence only: a hit proves the literal exists in the file, '
          'not which class/method references it. classHint (dex only) is the nearest preceding '
          'L...; descriptor within 4 KB and is a heuristic.',
    };
  }

  /// ZipDecoder 对非 zip 文件会静默返回空 archive，这里先校验本地文件头。
  static Future<void> _ensureZip(File file) async {
    var handle = await file.open();
    Uint8List header;
    try {
      header = await handle.read(4);
    } finally {
      await handle.close();
    }
    if (header.length < 4 || header[0] != 0x50 || header[1] != 0x4b) {
      throw const FormatException('not a zip/APK archive');
    }
    var signature = header[2] << 8 | header[3];
    if (signature != 0x0304 && signature != 0x0506 && signature != 0x0708) {
      throw const FormatException('not a zip/APK archive');
    }
  }

  static bool _isRelevant(String name) {
    var lower = name.toLowerCase();
    if (lower.endsWith('.so')) return true;
    if (!lower.endsWith('.dex')) return false;
    var base = lower.split('/').last;
    return base == 'classes.dex' || RegExp(r'^classes\d+\.dex$').hasMatch(base);
  }

  static List<int> _findAll(Uint8List haystack, List<int> needle, {required int max}) {
    var offsets = <int>[];
    if (needle.isEmpty || needle.length > haystack.length) return offsets;
    var last = haystack.length - needle.length;
    outer:
    for (var i = 0; i <= last; i++) {
      if (haystack[i] != needle[0]) continue;
      for (var j = 1; j < needle.length; j++) {
        if (haystack[i + j] != needle[j]) continue outer;
      }
      offsets.add(i);
      if (offsets.length >= max) break;
    }
    return offsets;
  }

  static String _contextHex(Uint8List bytes, int offset, int length) {
    var start = offset - 16;
    if (start < 0) start = 0;
    var end = offset + length + 16;
    if (end > bytes.length) end = bytes.length;
    return bytes
        .sublist(start, end)
        .map((byte) => byte.toRadixString(16).padLeft(2, '0'))
        .join();
  }

  /// 在命中点之前 4 KB 内找最后一个 `Lcom/example/Foo;` 形式的描述符。
  static String? _nearestClass(Uint8List bytes, int offset) {
    var start = offset - 4096;
    if (start < 0) start = 0;
    var window = latin1.decode(bytes.sublist(start, offset), allowInvalid: true);
    var matches = RegExp(r'L[A-Za-z0-9_$/]{2,200};').allMatches(window);
    if (matches.isEmpty) return null;
    return matches.last.group(0);
  }
}
