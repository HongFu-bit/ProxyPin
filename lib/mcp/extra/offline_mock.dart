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

import 'package:proxypin/mcp/capture/flow_view.dart';
import 'package:proxypin/network/http/http.dart';

/// 把已抓到的响应转成 map-local 规则草稿，用于离线 mock。
///
/// 纯计算，不落盘；真正创建规则由 MCP 工具完成，便于单测。
/// 同一 method+path 只取最新的一条成功响应。
class OfflineMockBuilder {
  OfflineMockBuilder._();

  static const int maxBodyBytes = 512 * 1024;
  static const int maxRules = 100;

  /// 这些响应头在 mock 时要么会与实际 body 冲突，要么已过期。
  static const Set<String> _skipHeaders = {
    'content-length',
    'content-encoding',
    'transfer-encoding',
    'connection',
    'keep-alive',
    'date',
    'server',
    'set-cookie',
  };

  static Future<MockBuildResult> build(List<HttpRequest> flows, {bool includeErrors = false}) async {
    var latest = <String, HttpRequest>{};
    var methodsByPath = <String, Set<String>>{};
    var duplicates = 0;
    var skippedNoResponse = 0;
    var skippedErrors = 0;
    var skippedBinary = 0;

    for (var flow in flows) {
      var response = flow.response;
      if (response == null) {
        skippedNoResponse++;
        continue;
      }
      if (!includeErrors && response.status.code >= 400) {
        skippedErrors++;
        continue;
      }

      var path = flow.requestUri?.path ?? flow.path;
      if (path.isEmpty) path = '/';
      var method = flow.method.name.toUpperCase();
      var key = '$method $path';
      methodsByPath.putIfAbsent(path, () => {}).add(method);

      var existing = latest[key];
      if (existing != null) {
        duplicates++;
        if (!flow.requestTime.isAfter(existing.requestTime)) continue;
      }
      latest[key] = flow;
    }

    var drafts = <MockRuleDraft>[];
    var skippedLarge = 0;
    for (var entry in latest.entries) {
      var flow = entry.value;
      var response = flow.response!;
      var body = '';
      if (response.body != null && response.body!.isNotEmpty) {
        if (FlowView.isBinary(response) || response.body!.length > maxBodyBytes) {
          skippedBinary++;
          continue;
        }
        try {
          body = await response.decodeBodyString();
        } catch (_) {
          skippedBinary++;
          continue;
        }
      }

      if (drafts.length >= maxRules) {
        skippedLarge++;
        continue;
      }

      var path = flow.requestUri?.path ?? flow.path;
      if (path.isEmpty) path = '/';
      var scheme = flow.requestUri?.scheme ?? 'http';
      var host = flow.requestUri?.host ?? flow.hostAndPort?.host ?? '';
      var port = flow.requestUri?.hasPort == true ? ':${flow.requestUri!.port}' : '';
      var origin = host.isEmpty ? '' : '$scheme://$host$port';

      drafts.add(MockRuleDraft(
        method: flow.method.name.toUpperCase(),
        path: path,
        pattern: '$origin$path*',
        name: 'mock ${flow.method.name.toUpperCase()} $path',
        statusCode: response.status.code,
        headers: _headers(response),
        body: body,
        requestId: flow.requestId,
        size: response.body?.length ?? 0,
      ));
    }

    var methodConflicts = methodsByPath.values.where((methods) => methods.length > 1).length;
    return MockBuildResult(
      rules: drafts,
      duplicates: duplicates,
      skippedNoResponse: skippedNoResponse,
      skippedErrors: skippedErrors,
      skippedBinary: skippedBinary,
      skippedOverLimit: skippedLarge,
      methodConflicts: methodConflicts,
    );
  }

  static Map<String, String> _headers(HttpResponse response) {
    var headers = <String, String>{};
    response.headers.forEach((name, values) {
      var lower = name.toLowerCase();
      if (_skipHeaders.contains(lower)) return;
      if (values.isEmpty) return;
      headers[name] = values.join(', ');
    });
    return headers;
  }
}

class MockRuleDraft {
  final String method;
  final String path;
  final String pattern;
  final String name;
  final int statusCode;
  final Map<String, String> headers;
  final String body;
  final String requestId;
  final int size;

  const MockRuleDraft({
    required this.method,
    required this.path,
    required this.pattern,
    required this.name,
    required this.statusCode,
    required this.headers,
    required this.body,
    required this.requestId,
    required this.size,
  });
}

class MockBuildResult {
  final List<MockRuleDraft> rules;
  final int duplicates;
  final int skippedNoResponse;
  final int skippedErrors;
  final int skippedBinary;
  final int skippedOverLimit;
  final int methodConflicts;

  const MockBuildResult({
    required this.rules,
    required this.duplicates,
    required this.skippedNoResponse,
    required this.skippedErrors,
    required this.skippedBinary,
    required this.skippedOverLimit,
    required this.methodConflicts,
  });

  int get endpoints => rules.length;
}
