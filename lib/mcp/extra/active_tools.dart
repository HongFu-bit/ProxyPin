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
import 'dart:math' as math;

import 'package:proxypin/mcp/capture/flow_store.dart';
import 'package:proxypin/mcp/protocol/mcp_server.dart';
import 'package:proxypin/mcp/protocol/mcp_tool.dart';
import 'package:proxypin/network/http/http.dart';

import 'active_runner.dart';

/// 主动测试工具：并发重放、参数 fuzz、越权 ID 扫描。
///
/// 这三个工具会真实向目标发包。内置限速（默认 3 QPS），并发重放除外——它本身就是
/// 测试竞态，必须同时下发。规则（断点/重写/脚本）照常生效。
class McpActiveTools {
  final FlowStore store;

  McpActiveTools({required this.store});

  List<McpTool> tools() => [_raceReplay(), _fuzzFlow(), _scanCrossUser()];

  McpTool _raceReplay() => McpTool(
        name: 'race_replay',
        description:
            'Replay one captured request N times at the same instant and compare responses, to probe for race '
            'conditions (duplicate coupon/order/balance). Reuses the exact captured bytes, including signatures. '
            'Returns status distribution, size stats, response skew and deviations — hints, not proof. '
            'Each copy is a real request: keep copies modest.',
        inputSchema: {
          'type': 'object',
          'properties': {
            'id': {'type': 'string', 'description': 'Flow id from list_flows'},
            'history_id': {'type': 'integer', 'description': 'Saved history session id; omit for live capture'},
            'copies': {'type': 'integer', 'description': 'How many concurrent copies, default 10, max 50'},
            'max_skew_ms': {
              'type': 'integer',
              'description': 'Acceptable dispatch skew in ms, default 20; larger skew marks the run inconclusive',
            },
          },
          'required': ['id'],
        },
        handler: (args) async {
          var flow = await _resolve(args['id']?.toString(), _intOrNull(args['history_id']));
          var copies = _intOr(args['copies'], 10).clamp(2, 50);
          var maxSkew = _intOr(args['max_skew_ms'], 20).clamp(0, 1000);

          var gate = Completer<void>();
          var starts = <int>[];
          var tasks = <Future<ActiveResult>>[];
          for (var i = 0; i < copies; i++) {
            tasks.add(() async {
              await gate.future;
              starts.add(DateTime.now().microsecondsSinceEpoch);
              var copy = flow.copy();
              copy.body = flow.body;
              return await ActiveRunner.send(copy, timeout: const Duration(seconds: 20));
            }());
          }
          gate.complete();
          var results = await Future.wait(tasks);

          var skewMs = 0.0;
          if (starts.length > 1) {
            var minStart = starts.reduce(math.min);
            var maxStart = starts.reduce(math.max);
            skewMs = (maxStart - minStart) / 1000.0;
          }

          var summary = ResponseStats.summarize(results, skewMs: skewMs, maxSkewMs: maxSkew);
          return {
            'id': flow.requestId,
            'url': flow.requestUrl,
            ...summary,
            'previews': results.take(3).map((r) => r.preview).toList(),
          };
        },
      );

  McpTool _fuzzFlow() => McpTool(
        name: 'fuzz_flow',
        description:
            'Replace one parameter in a captured request with each payload, send them sequentially at a bounded '
            'rate, and report the response matrix (status, size, size delta vs. an unmodified baseline). '
            'location=auto tries query, JSON body, form body, then header. Mutating a signed request usually '
            'invalidates the signature — recompute it first or treat rejections as expected.',
        inputSchema: {
          'type': 'object',
          'properties': {
            'id': {'type': 'string'},
            'history_id': {'type': 'integer'},
            'param': {'type': 'string', 'description': 'Parameter name; JSON bodies accept dot paths'},
            'payloads': {
              'type': 'array',
              'items': {'type': 'string'},
              'description': '1-50 replacement values',
            },
            'location': {
              'type': 'string',
              'enum': RequestMutator.locations,
              'description': 'Where to replace the parameter, default auto',
            },
            'max_qps': {'type': 'integer', 'description': 'Requests per second, default 3, max 20'},
          },
          'required': ['id', 'param', 'payloads'],
        },
        handler: (args) async {
          var flow = await _resolve(args['id']?.toString(), _intOrNull(args['history_id']));
          var param = args['param']?.toString() ?? '';
          if (param.isEmpty) throw ToolException('Missing required parameter: param');

          var location = args['location']?.toString() ?? 'auto';
          if (!RequestMutator.locations.contains(location)) {
            throw ToolException('location must be one of ${RequestMutator.locations.join(', ')}');
          }
          var payloads = _stringList(args['payloads']).take(50).toList();
          if (payloads.isEmpty) throw ToolException('payloads must contain at least one value');

          var qps = _intOr(args['max_qps'], 3).clamp(1, 20);
          var gate = RateGate(qps);

          await gate.acquire();
          var baseline = await ActiveRunner.send(flow.copy());

          var results = <Map<String, dynamic>>[];
          var interesting = <Map<String, dynamic>>[];
          for (var payload in payloads) {
            var mutation = RequestMutator.apply(flow, param, payload, location: location);
            if (mutation == null) {
              results.add({'payload': payload, 'error': 'parameter not found at location=$location'});
              continue;
            }
            await gate.acquire();
            var response = await ActiveRunner.send(mutation.request);
            var sizeDelta = response.size - baseline.size;
            var entry = <String, dynamic>{
              'payload': payload,
              'location': mutation.location,
              'oldValue': mutation.oldValue,
              'status': response.status,
              'size': response.size,
              'sizeDelta': sizeDelta,
              'elapsedMs': response.elapsedMs,
              if (response.error != null) 'error': response.error,
              if (response.error == null) 'bodyPreview': response.preview,
            };
            results.add(entry);

            var statusChanged = response.status != baseline.status;
            var bigSizeChange = response.isSuccess &&
                baseline.isSuccess &&
                sizeDelta.abs() > math.max(32, baseline.size ~/ 4);
            if (statusChanged || bigSizeChange || response.error != null) {
              interesting.add(entry);
            }
          }

          return {
            'id': flow.requestId,
            'param': param,
            'requestedLocation': location,
            'rateQps': qps,
            'baseline': {
              'status': baseline.status,
              'size': baseline.size,
              'elapsedMs': baseline.elapsedMs,
              if (baseline.error != null) 'error': baseline.error,
            },
            'payloadsTested': results.length,
            'results': results,
            'interesting': interesting,
            'note': 'Interesting entries differ from the baseline in status or body size. '
                'Inspect bodyPreview and confirm manually; signed endpoints may reject every mutation.',
          };
        },
      );

  McpTool _scanCrossUser() => McpTool(
        name: 'scan_cross_user',
        description:
            'IDOR/越权扫描: iterate an integer id parameter over a range, send each value at a bounded rate, and '
            'flag responses that look like another user\'s data (2xx, non-empty, similar size to the baseline). '
            'Heuristic only — confirm suspects manually. Range is capped at 100 values.',
        inputSchema: {
          'type': 'object',
          'properties': {
            'id': {'type': 'string'},
            'history_id': {'type': 'integer'},
            'param': {'type': 'string', 'description': 'Numeric id parameter, e.g. userId'},
            'from': {'type': 'integer', 'description': 'Range start, inclusive'},
            'to': {'type': 'integer', 'description': 'Range end, inclusive'},
            'location': {
              'type': 'string',
              'enum': RequestMutator.locations,
              'description': 'Where to replace the parameter, default auto',
            },
            'max_qps': {'type': 'integer', 'description': 'Requests per second, default 3, max 10'},
          },
          'required': ['id', 'param', 'from', 'to'],
        },
        handler: (args) async {
          var flow = await _resolve(args['id']?.toString(), _intOrNull(args['history_id']));
          var param = args['param']?.toString() ?? '';
          if (param.isEmpty) throw ToolException('Missing required parameter: param');

          var from = _intOrNull(args['from']);
          var to = _intOrNull(args['to']);
          if (from == null || to == null) throw ToolException('from and to are required integers');
          if (to < from) throw ToolException('to must be >= from');
          var span = to - from + 1;
          if (span > 100) throw ToolException('range is too large ($span); cap it at 100 values');

          var location = args['location']?.toString() ?? 'auto';
          if (!RequestMutator.locations.contains(location)) {
            throw ToolException('location must be one of ${RequestMutator.locations.join(', ')}');
          }

          var probe = RequestMutator.apply(flow, param, '', location: location);
          if (probe == null) {
            throw ToolException('parameter "$param" not found at location=$location');
          }
          var baselineValue = probe.oldValue;

          var qps = _intOr(args['max_qps'], 3).clamp(1, 10);
          var gate = RateGate(qps);

          await gate.acquire();
          var baseline = await ActiveRunner.send(flow.copy());

          var suspects = <Map<String, dynamic>>[];
          var denied = 0;
          var errors = 0;
          var tested = 0;
          for (var value = from; value <= to; value++) {
            var text = '$value';
            if (text == baselineValue) continue;
            var mutation = RequestMutator.apply(flow, param, text, location: location);
            if (mutation == null) {
              errors++;
              continue;
            }

            await gate.acquire();
            var response = await ActiveRunner.send(mutation.request);
            tested++;
            if (response.error != null) {
              errors++;
              continue;
            }
            var status = response.status ?? 0;
            if (status == 401 || status == 403 || status == 404) {
              denied++;
              continue;
            }
            if (!response.isSuccess || response.size == 0) continue;

            var ratioOk = baseline.size == 0 ||
                (response.size >= baseline.size ~/ 2 && response.size <= baseline.size * 2);
            if (ratioOk) {
              suspects.add({
                'value': value,
                'status': status,
                'size': response.size,
                'baselineSize': baseline.size,
                'bodyPreview': response.preview,
                'note': '2xx with a non-empty body similar in size to the baseline; confirm it belongs to another user',
              });
            }
          }

          return {
            'id': flow.requestId,
            'param': param,
            'location': probe.location,
            'range': {'from': from, 'to': to},
            'baselineValue': baselineValue,
            'baseline': {
              'status': baseline.status,
              'size': baseline.size,
              if (baseline.error != null) 'error': baseline.error,
            },
            'tested': tested,
            'denied': denied,
            'errors': errors,
            'suspectHits': suspects,
            'rateQps': qps,
            'note': 'suspectHits is a heuristic: 2xx + non-empty + size within 2x of the baseline. '
                'Verify ownership before treating it as an IDOR.',
          };
        },
      );

  Future<HttpRequest> _resolve(String? id, int? historyId) async {
    if (id == null || id.isEmpty) throw ToolException('Missing required parameter: id');
    if (historyId != null) {
      var histories = await store.listHistories();
      if (!histories.any((meta) => meta.id == historyId)) {
        throw ToolException('History not found: $historyId (call list_histories for valid ids)');
      }
      var flow = await store.historyGetById(historyId, id);
      if (flow == null) throw ToolException('Flow not found in history $historyId: $id');
      return flow;
    }
    var flow = store.getById(id);
    if (flow == null) throw ToolException('Flow not found or expired: $id');
    return flow;
  }

  static int _intOr(dynamic value, int fallback) => _intOrNull(value) ?? fallback;

  static int? _intOrNull(dynamic value) {
    if (value is int) return value;
    if (value is num) return value.toInt();
    if (value is String) return int.tryParse(value);
    return null;
  }

  static List<String> _stringList(dynamic value) {
    if (value is List) {
      return value.map((item) => item.toString()).toList();
    }
    return const [];
  }
}
