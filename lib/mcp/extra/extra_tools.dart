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
import 'dart:io' show File, Platform;

import 'package:proxypin/mcp/capture/flow_store.dart';
import 'package:proxypin/mcp/mcp_service.dart';
import 'package:proxypin/mcp/protocol/mcp_server.dart';
import 'package:proxypin/mcp/protocol/mcp_tool.dart';
import 'package:proxypin/native/installed_apps.dart';
import 'package:proxypin/network/components/manager/request_map_manager.dart';
import 'package:proxypin/network/components/request_breakpoint.dart';
import 'package:proxypin/network/http/http.dart';

import 'active_tools.dart';
import 'apk_string_locator.dart';
import 'audit_log.dart';
import 'contract_generator.dart';
import 'crypto_tools.dart';
import 'domain_tools.dart';
import 'field_flow_tracker.dart';
import 'intercept_queue.dart';
import 'offline_mock.dart';
import 'protobuf_decoder.dart';
import 'signature_analyzer.dart';
import 'ws_tools.dart';

/// Fork 专属增强工具：交互式断点、签名差量推断。
///
/// 刻意集中在新目录 `lib/mcp/extra/`，对上游文件只做「注册一行 + 断点钩子」的改动，
/// 便于后续 rebase。
///
/// @author wanghongen
class McpExtraTools {
  final FlowStore store;
  final bool Function() redactEnabled;

  /// 可选审计日志；未注入时 `get_audit_log` 返回不可用。
  final AuditLog? audit;

  McpExtraTools({required this.store, required this.redactEnabled, this.audit});

  late final BreakpointExternalHandler breakpointHandler = _McpBreakpointHandler();

  /// 每个 host 上一次生成的动态工具，重复生成时只替换自己的工具。
  final Map<String, _DomainToolRegistration> _domainTools = {};

  List<McpTool> tools() => [
        _getPendingIntercepts(),
        _resolveIntercept(),
        _analyzeSignature(),
        _generateContract(),
        _traceFieldFlow(),
        _buildOfflineMock(),
        _decodeProtobuf(),
        _locateApiInApk(),
        _getAuditLog(),
        _generateDomainTools(),
        _listDomainTools(),
        _removeDomainTools(),
        ...CryptoTools(store).tools(),
        ...WsTools().tools(),
        ...McpActiveTools(store: store).tools(),
      ];

  McpTool _decodeProtobuf() => McpTool(
        name: 'decode_protobuf',
        description: 'Best-effort schema-less decode of a captured request/response body as protobuf or gRPC. '
            'For gRPC, parses the 5-byte frame header (flag + big-endian length) and supports multiple frames; '
            'compressed frames are attempted as gzip. No .proto is used: varints are raw numbers and '
            'length-delimited payloads are guessed as string / nested message / bytes. Treat output as hints.',
        inputSchema: {
          'type': 'object',
          'properties': {
            'id': {'type': 'string', 'description': 'Flow id from list_flows'},
            'history_id': {'type': 'integer', 'description': 'Saved history session id; omit for live capture'},
            'side': {
              'type': 'string',
              'enum': ['request', 'response'],
              'description': 'Which body to decode, default response',
            },
            'format': {
              'type': 'string',
              'enum': ['auto', 'protobuf', 'grpc'],
              'description': 'auto (default) uses Content-Type and frame structure',
            },
          },
          'required': ['id'],
        },
        handler: (args) async {
          var id = args['id']?.toString();
          if (id == null || id.isEmpty) throw ToolException('Missing required parameter: id');
          var historyId = _intOrNull(args['history_id']);
          var flow = historyId != null ? await store.historyGetById(historyId, id) : store.getById(id);
          if (flow == null) {
            throw ToolException(historyId == null
                ? 'Flow not found in live capture: $id (pass history_id for saved sessions)'
                : 'Flow not found in history $historyId: $id');
          }

          var side = args['side']?.toString() ?? 'response';
          if (side != 'request' && side != 'response') {
            throw ToolException("side must be 'request' or 'response'");
          }
          var response = flow.response;
          if (side == 'response' && response == null) {
            throw ToolException('Flow has no captured response: $id');
          }
          HttpMessage message = side == 'request' ? flow : response!;

          var body = await ProtobufDecoder.bodyBytes(message);
          if (body == null) {
            return {
              'flowId': id,
              'side': side,
              'available': false,
              'reason': 'empty body',
            };
          }

          var format = args['format']?.toString() ?? 'auto';
          bool? grpc;
          if (format == 'grpc') grpc = true;
          if (format == 'protobuf') grpc = false;
          var decoded = ProtobufDecoder.decodeBody(
            body.bytes,
            contentType: message.headers.contentType,
            grpc: grpc,
          );
          return {
            'flowId': id,
            'url': flow.requestUrl,
            'side': side,
            'contentType': message.headers.contentType,
            'bodyBytes': message.body?.length ?? 0,
            'decodedBytes': body.bytes.length,
            if (body.truncated) 'truncatedBody': true,
            ...decoded,
          };
        },
      );

  McpTool _locateApiInApk() => McpTool(
        name: 'locate_api_in_apk',
        description: 'Search a local APK for a URL/path literal inside classes*.dex and .so entries. '
            'Reports zip entry, byte offset, hex context and the nearest dex class descriptor. '
            'This is string-level evidence only: it does not decompile or build a call graph, '
            'so a hit does not prove which code references the endpoint.',
        inputSchema: {
          'type': 'object',
          'properties': {
            'url': {'type': 'string', 'description': 'Full URL or path to look for'},
            'apk_path': {'type': 'string', 'description': 'Absolute path to the APK on this machine'},
            'package': {
              'type': 'string',
              'description': 'Android only: installed package name; resolves to its base APK when apk_path is omitted',
            },
            'max_hits': {'type': 'integer', 'description': 'Max hits, default 50, max 200'},
          },
          'required': ['url'],
        },
        handler: (args) async {
          var url = args['url']?.toString() ?? '';
          if (url.isEmpty) throw ToolException('Missing required parameter: url');

          var apkPath = args['apk_path']?.toString().trim() ?? '';
          var packageName = args['package']?.toString().trim() ?? '';
          if (apkPath.isEmpty && packageName.isNotEmpty) {
            if (!Platform.isAndroid) {
              throw ToolException('package is only supported on Android; pass apk_path instead');
            }
            apkPath = await InstalledApps.getApkPath(packageName) ?? '';
            if (apkPath.isEmpty) {
              throw ToolException('Package not found or its APK path is unavailable: $packageName. '
                  'Verify the package name, or pass apk_path directly.');
            }
          }
          if (apkPath.isEmpty) {
            throw ToolException('Missing required parameter: apk_path (or package on Android)');
          }
          if (!await File(apkPath).exists()) {
            throw ToolException('APK not found: "$apkPath". Pass an absolute path readable by the app '
                '(e.g. /sdcard/Download/app.apk), or pass package=<packageName> on Android.');
          }
          try {
            return await ApkStringLocator.locate(
              apkPath,
              url,
              maxHits: _intOr(args['max_hits'], ApkStringLocator.maxHitsDefault),
            );
          } catch (e) {
            throw ToolException('Failed to read APK as a zip: $e');
          }
        },
      );

  McpTool _getAuditLog() => McpTool(
        name: 'get_audit_log',
        description:
            'Read recent MCP tool-call audit entries (written only when audit logging is enabled in MCP settings). '
            'Entries contain timestamp, tool name, redacted arguments, client IP, elapsed time and ok/error. '
            'The log is a bounded local JSONL file (256 KB); oldest entries are dropped first.',
        inputSchema: {
          'type': 'object',
          'properties': {
            'limit': {'type': 'integer', 'description': 'Max entries, default 100, max 500'},
          },
        },
        handler: (args) async {
          var log = audit;
          if (log == null) throw ToolException('Audit log is unavailable in this build');
          var limit = _intOr(args['limit'], 100).clamp(1, 500);
          var entries = await log.read(limit: limit);
          return {
            'enabled': log.isEnabled,
            'count': entries.length,
            'entries': entries,
            if (!log.isEnabled)
              'note': 'Audit logging is currently disabled; these are previously recorded entries. '
                  'Enable it in ProxyPin → MCP settings to record new tool calls.',
          };
        },
      );

  McpTool _generateDomainTools() => McpTool(
        name: 'generate_domain_tools',
        description:
            'Turn captured endpoints for one host into semantic MCP tools (e.g. app_login, app_get_user_info). '
            'Each generated tool replays the captured URL/headers/body shape with overridable query or JSON/form '
            'fields, sends a real request, and returns the parsed response. signatureProfile="auto" recomputes a '
            'signature only when analyze_signature can prove the algorithm; otherwise captured signature values are '
            'reused. cryptoProfile decrypts the response body when it matches. Generated tools are in-memory and '
            'call the real service with the captured account credentials — regenerate after relevant captures change.',
        inputSchema: {
          'type': 'object',
          'properties': {
            'host': {'type': 'string', 'description': 'Host substring, same semantics as list_flows'},
            'history_id': {
              'type': 'integer',
              'description': 'Saved history session id from list_histories; omit for live capture',
            },
            'registerAs': {
              'type': 'string',
              'description': 'Tool name prefix, default derived from the host (e.g. "app" → app_login)',
            },
            'cryptoProfile': {
              'type': 'string',
              'description': 'Crypto profile name used to decrypt responses (see list_crypto_profiles)',
            },
            'signatureProfile': {
              'description':
                  '"auto" to infer signatures from captured samples, "none" to disable, or an explicit object '
                      '{field, algorithm: MD5|SHA-1|SHA-256|HMAC-SHA256, input: sorted-pairs|sorted-concat|raw-body|'
                      'query|path|sorted-pairs+secret|secret+sorted-pairs|raw-body+secret, secret?}',
              'oneOf': [
                {
                  'type': 'string',
                  'enum': ['auto', 'none']
                },
                {
                  'type': 'object',
                  'properties': {
                    'field': {'type': 'string'},
                    'algorithm': {'type': 'string'},
                    'input': {'type': 'string'},
                    'secret': {'type': 'string'},
                  },
                  'required': ['field', 'algorithm'],
                }
              ],
            },
            'methods': {
              'type': 'array',
              'items': {'type': 'string'},
              'description': 'Only generate tools for these methods, e.g. ["GET","POST"]',
            },
            'max_tools': {'type': 'integer', 'description': 'Max generated tools, default 40, max 80'},
          },
          'required': ['host'],
        },
        handler: (args) async {
          var host = args['host']?.toString().trim() ?? '';
          if (host.isEmpty) throw ToolException('host is required');
          var server = McpService.instance.server;
          if (server == null) throw ToolException('MCP server is not running');

          var flows = await _collectFlows(
            host: host,
            historyId: _intOrNull(args['history_id']),
            limit: 800,
          );
          if (flows.isEmpty) throw ToolException('no captured flows for host "$host"');

          var rawMethods = args['methods'];
          var methods = rawMethods is List
              ? rawMethods.map((e) => e.toString().toUpperCase()).where((e) => e.isNotEmpty).toSet()
              : null;
          var registerAs = args['registerAs']?.toString().trim();
          var maxTools = _intOr(args['max_tools'], DomainToolGenerator.defaultMaxTools).clamp(1, 80);

          var result = await DomainToolGenerator.build(
            flows,
            host: host,
            registerAs: registerAs == null || registerAs.isEmpty ? null : registerAs,
            cryptoProfile: args['cryptoProfile']?.toString(),
            signatureProfile: args['signatureProfile'],
            methods: methods,
            maxTools: maxTools,
          );

          var previous = _domainTools.remove(host);
          if (previous != null) {
            server.removeDynamicTools((tool) => previous.names.contains(tool.name));
          }
          var registered = server.registerTools(result.tools);
          _domainTools[host] = _DomainToolRegistration(
            host: host,
            prefix: result.prefix,
            names: result.tools.map((t) => t.name).toList(),
            createdAtMs: DateTime.now().millisecondsSinceEpoch,
          );

          return {
            'host': host,
            'prefix': result.prefix,
            'registered': registered,
            'replaced': previous?.names.length ?? 0,
            'persisted': false,
            'tools': result.endpoints,
            'warnings': result.warnings,
            'note': 'Generated tools send real requests with the captured headers and are kept in memory only '
                '(persisted=false): they disappear when the app restarts. Call tools/list again to see them; '
                'use list_domain_tools / remove_domain_tools to audit or unregister them.',
          };
        },
      );

  McpTool _listDomainTools() => McpTool(
        name: 'list_domain_tools',
        description: 'List the dynamic per-host tools registered by generate_domain_tools in this app session. '
            'Each entry has host, name prefix, createdAtMs and tool names. These tools are in-memory only '
            '(persisted=false) and disappear when the app restarts.',
        inputSchema: {
          'type': 'object',
          'properties': {
            'host': {'type': 'string', 'description': 'Optional exact host filter (as passed to generate_domain_tools)'},
            'prefix': {'type': 'string', 'description': 'Optional exact tool-name prefix filter'},
          },
        },
        handler: (args) async {
          var host = args['host']?.toString().trim();
          var prefix = args['prefix']?.toString().trim();
          var matched = _domainTools.values.where((registration) {
            if (host != null && host.isNotEmpty && registration.host != host) return false;
            if (prefix != null && prefix.isNotEmpty && registration.prefix != prefix) return false;
            return true;
          }).toList(growable: false)
            ..sort((a, b) => a.createdAtMs.compareTo(b.createdAtMs));

          return {
            'count': matched.length,
            'persisted': false,
            'tools': matched.map((registration) => registration.toJson()).toList(growable: false),
            if (matched.isEmpty)
              'note': 'No dynamic domain tools are registered in this session; call generate_domain_tools first.',
          };
        },
      );

  McpTool _removeDomainTools() => McpTool(
        name: 'remove_domain_tools',
        description: 'Unregister dynamic tools created by generate_domain_tools. Select by host or prefix, '
            'or pass all=true to remove every generated tool. Built-in tools are never affected. '
            'Generated tools are in-memory only, so this is the only way to remove them before an app restart.',
        inputSchema: {
          'type': 'object',
          'properties': {
            'host': {'type': 'string', 'description': 'Exact host used when the tools were generated'},
            'prefix': {'type': 'string', 'description': 'Exact tool-name prefix'},
            'all': {'type': 'boolean', 'description': 'Remove all generated domain tools'},
          },
        },
        handler: (args) async {
          var all = args['all'] == true || args['all']?.toString().toLowerCase() == 'true';
          var host = args['host']?.toString().trim();
          var prefix = args['prefix']?.toString().trim();
          if (!all && (host == null || host.isEmpty) && (prefix == null || prefix.isEmpty)) {
            throw ToolException('Specify host, prefix, or all=true');
          }

          var server = McpService.instance.server;
          if (server == null) throw ToolException('MCP server is not running');

          var selected = _domainTools.values.where((registration) {
            if (all) return true;
            return (host != null && host.isNotEmpty && registration.host == host) ||
                (prefix != null && prefix.isNotEmpty && registration.prefix == prefix);
          }).toList(growable: false);

          var removedTools = <String>[];
          for (var registration in selected) {
            server.removeDynamicTools((tool) => registration.names.contains(tool.name));
            _domainTools.remove(registration.host);
            removedTools.addAll(registration.names);
          }

          return {
            'removed': selected.length,
            'removedTools': removedTools.length,
            'hosts': selected.map((registration) => registration.host).toList(growable: false),
            'remaining': _domainTools.length,
            'persisted': false,
            if (selected.isEmpty) 'note': 'No generated domain tools matched the filter.',
          };
        },
      );

  McpTool _getPendingIntercepts() => McpTool(
        name: 'get_pending_intercepts',
        description: 'List requests/responses currently paused by breakpoint rules and waiting for a decision. '
            'Each item has an id; call resolve_intercept to continue (optionally modifying headers/body/statusCode) '
            'or drop it. Items auto-continue when expiresAtMs passes, so act before remainingMs runs out.',
        inputSchema: {
          'type': 'object',
          'properties': {
            'phase': {
              'type': 'string',
              'enum': ['request', 'response']
            },
            'limit': {'type': 'integer', 'description': 'Max items, default 20, max 50'},
          },
        },
        handler: (args) async {
          var phase = args['phase']?.toString();
          var limit = _intOr(args['limit'], 20).clamp(1, InterceptQueue.maxPending);
          var items = <Map<String, dynamic>>[];
          for (var item in InterceptQueue.instance.list(phase: phase, limit: limit)) {
            items.add(await item.toJson(redact: redactEnabled(), previewBytes: 8192));
          }
          return {
            'count': items.length,
            'pendingTotal': InterceptQueue.instance.count,
            'timeoutSeconds': InterceptQueue.instance.timeout.inSeconds,
            'items': items,
          };
        },
      );

  McpTool _resolveIntercept() => McpTool(
        name: 'resolve_intercept',
        description:
            'Resolve a paused breakpoint item. action=continue lets it proceed (headers are merged, body replaces the '
            'whole message text, statusCode only applies to response phase); action=drop aborts it. '
            'Each item can be resolved exactly once.',
        inputSchema: {
          'type': 'object',
          'properties': {
            'id': {'type': 'string', 'description': 'Item id from get_pending_intercepts'},
            'action': {
              'type': 'string',
              'enum': ['continue', 'drop'],
              'description': 'default continue'
            },
            'headers': {'type': 'object', 'description': 'Header values to merge (string or string array)'},
            'body': {'type': 'string', 'description': 'Replacement body text, UTF-8'},
            'statusCode': {'type': 'integer', 'description': 'Response phase only'},
          },
          'required': ['id'],
        },
        handler: (args) async {
          var id = args['id']?.toString();
          if (id == null || id.isEmpty) throw ToolException('Missing required parameter: id');

          var action = args['action']?.toString() ?? 'continue';
          if (action != 'continue' && action != 'drop') {
            throw ToolException("action must be 'continue' or 'drop'");
          }

          Map<String, String>? headers;
          var rawHeaders = args['headers'];
          if (rawHeaders is Map) {
            var merged = <String, String>{};
            rawHeaders.forEach((name, value) {
              merged[name.toString()] = value is List ? value.join(', ') : value.toString();
            });
            headers = merged;
          }

          var rawBody = args['body'];
          String? body;
          if (rawBody is String) {
            body = rawBody;
          } else if (rawBody != null) {
            body = jsonEncode(rawBody);
          }

          var decision = InterceptDecision(
            action: action,
            headers: headers,
            body: body,
            statusCode: _intOrNull(args['statusCode']),
          );
          if (!InterceptQueue.instance.resolve(id, decision)) {
            throw ToolException(
                'Intercept not found or already resolved: $id (call get_pending_intercepts for live ids)');
          }
          return {'resolved': true, 'id': id, 'action': action};
        },
      );

  McpTool _analyzeSignature() => McpTool(
        name: 'analyze_signature',
        description: 'Read-only heuristic over captured requests to the same endpoint: reports stable/varying fields, '
            'signature-shaped candidates, and tries common concatenations with MD5/SHA1/SHA256/HMAC-SHA256. '
            'Returns evidence and candidates, not a proof. Capture at least 2 requests to the endpoint first.',
        inputSchema: {
          'type': 'object',
          'properties': {
            'host': {'type': 'string', 'description': 'Host substring, same semantics as list_flows'},
            'path': {'type': 'string', 'description': 'Optional path exact/prefix filter'},
            'method': {'type': 'string', 'description': 'Optional HTTP method filter, e.g. POST'},
            'sample_limit': {'type': 'integer', 'description': 'Max samples, default 20, max 50'},
            'secret': {'type': 'string', 'description': 'Optional candidate secret for salted/HMAC attempts'},
            'history_id': {
              'type': 'integer',
              'description': 'Saved history session id from list_histories; omit for live capture',
            },
          },
          'required': ['host'],
        },
        handler: (args) async {
          var host = args['host']?.toString() ?? '';
          if (host.isEmpty) throw ToolException('Missing required parameter: host');
          var path = args['path']?.toString();
          var method = args['method']?.toString().trim().toUpperCase();
          var limit = _intOr(args['sample_limit'], 20).clamp(2, 50);
          var historyId = _intOrNull(args['history_id']);

          List<HttpRequest> flows;
          if (historyId != null) {
            flows = await store.historyQuery(historyId, limit: 100, host: host);
          } else {
            flows = store.query(limit: 100, host: host);
          }

          if (method != null && method.isNotEmpty) {
            flows = flows.where((flow) => flow.method.name == method).toList(growable: false);
          }

          if (path != null && path.isNotEmpty) {
            final prefix = path;
            flows = flows
                .where((flow) => flow.path == prefix || flow.pathAndQuery.startsWith(prefix))
                .toList(growable: false);
          }

          // 同一 host 下往往有多种接口；按 method+path 分组，只分析样本最多的那个端点，
          // 否则不同接口的字段会被混在一起，稳定/变化字段的结论不可用。
          var groups = <String, List<HttpRequest>>{};
          for (var flow in flows) {
            groups.putIfAbsent('${flow.method.name} ${flow.path}', () => []).add(flow);
          }
          var endpoints = groups.entries.toList()
            ..sort((a, b) => b.value.length.compareTo(a.value.length));

          if (endpoints.isEmpty || endpoints.first.value.length < 2) {
            return {
              'samples': endpoints.isEmpty ? 0 : endpoints.first.value.length,
              'endpoints': _signatureEndpoints(endpoints),
              'note': 'need at least 2 requests to the same method+path endpoint; '
                  'capture more traffic, or set method/path to the endpoint you want',
            };
          }

          var selected = endpoints.first;
          var result = SignatureAnalyzer.analyze(
            selected.value,
            sampleLimit: limit,
            secret: args['secret']?.toString(),
          );
          result['scope'] = {
            'method': selected.value.first.method.name,
            'path': selected.value.first.path,
            'sampleCount': selected.value.length,
            'totalMatched': flows.length,
            'endpointCount': endpoints.length,
            'excludedEndpoints': _signatureEndpoints(endpoints.skip(1).take(10)),
          };
          return result;
        },
      );

  List<Map<String, dynamic>> _signatureEndpoints(Iterable<MapEntry<String, List<HttpRequest>>> entries) {
    return entries
        .take(10)
        .map((entry) => {
              'method': entry.value.first.method.name,
              'path': entry.value.first.path,
              'samples': entry.value.length,
            })
        .toList(growable: false);
  }

  McpTool _generateContract() => McpTool(
        name: 'generate_api_contract',
        description: 'Read-only: group captured flows by method + normalized path and emit an API contract. '
            'format=openapi (default) returns an OpenAPI 3.0 document, typescript returns interfaces, '
            'curl returns replayable commands. Numeric path segments become {id}; required fields are '
            'those present in every sample. Parameter values are omitted.',
        inputSchema: {
          'type': 'object',
          'properties': {
            'host': {'type': 'string', 'description': 'Host substring, same semantics as list_flows'},
            'history_id': {
              'type': 'integer',
              'description': 'Saved history session id from list_histories; omit for live capture',
            },
            'min_samples': {
              'type': 'integer',
              'description': 'Skip endpoints with fewer samples, default 2, max 20',
            },
            'format': {
              'type': 'string',
              'enum': ['openapi', 'typescript', 'curl'],
              'description': 'Output format, default openapi',
            },
          },
          'required': ['host'],
        },
        handler: (args) async {
          var host = args['host']?.toString() ?? '';
          if (host.isEmpty) throw ToolException('Missing required parameter: host');
          var historyId = _intOrNull(args['history_id']);
          var minSamples = _intOr(args['min_samples'], 2).clamp(1, 20);
          var format = args['format']?.toString() ?? 'openapi';
          if (!ContractGenerator.formats.contains(format)) {
            throw ToolException('format must be one of ${ContractGenerator.formats.join(', ')}');
          }

          var flows = await _collectFlows(host: host, historyId: historyId, limit: 300);
          if (flows.length < 2) {
            return {
              'samples': flows.length,
              'note': 'need at least 2 captured flows for this host; widen the host filter or capture more traffic',
            };
          }
          return ContractGenerator.generate(
            flows,
            host: host,
            minSamples: minSamples,
            format: format,
            redact: redactEnabled(),
          );
        },
      );

  McpTool _traceFieldFlow() => McpTool(
        name: 'trace_field_flow',
        description: 'Read-only: find values produced by one response (tokens, ids, cookies) that reappear in later '
            'requests, and build a producer→consumer graph. identitySeeds lists edges whose target is an '
            'Authorization/Cookie/token field — useful for mapping the auth chain. Values are masked.',
        inputSchema: {
          'type': 'object',
          'properties': {
            'host': {'type': 'string', 'description': 'Host substring, same semantics as list_flows'},
            'history_id': {
              'type': 'integer',
              'description': 'Saved history session id from list_histories; omit for live capture',
            },
            'session_limit': {
              'type': 'integer',
              'description': 'Max flows to analyze, default 200, max ${FieldFlowTracker.maxFlows}',
            },
            'min_value_len': {
              'type': 'integer',
              'description': 'Minimum length of a tracked value, default 8, max 64',
            },
          },
          'required': ['host'],
        },
        handler: (args) async {
          var host = args['host']?.toString() ?? '';
          if (host.isEmpty) throw ToolException('Missing required parameter: host');
          var historyId = _intOrNull(args['history_id']);
          var sessionLimit = _intOr(args['session_limit'], 200).clamp(2, FieldFlowTracker.maxFlows);
          var minValueLen = _intOr(args['min_value_len'], 8).clamp(4, 64);
          var flows = await _collectFlows(host: host, historyId: historyId, limit: sessionLimit);
          if (flows.length < 2) {
            return {
              'flowsAnalyzed': flows.length,
              'note': 'need at least 2 captured flows for this host',
            };
          }
          return FieldFlowTracker.trace(flows, sessionLimit: sessionLimit, minValueLen: minValueLen);
        },
      );

  McpTool _buildOfflineMock() => McpTool(
        name: 'build_offline_mock',
        description:
            'Read-only on traffic, write on rules: turn captured responses for a host into map-local rules so the '
            'app keeps working offline or against a mock. One rule per method+path using the newest successful '
            'response; binary/oversized bodies are skipped. Generated rules are named "mock ..." and are replaced '
            'on the next call unless replace_existing=false. Map-local matches by URL only, so method conflicts '
            'are reported instead of silently merging.',
        inputSchema: {
          'type': 'object',
          'properties': {
            'host': {'type': 'string', 'description': 'Host substring, same semantics as list_flows'},
            'history_id': {'type': 'integer', 'description': 'Saved history session id; omit for live capture'},
            'include_errors': {
              'type': 'boolean',
              'description': 'Also mock 4xx/5xx responses, default false',
            },
            'replace_existing': {
              'type': 'boolean',
              'description': 'Delete previously generated "mock " rules first, default true',
            },
          },
          'required': ['host'],
        },
        handler: (args) async {
          var host = args['host']?.toString() ?? '';
          if (host.isEmpty) throw ToolException('Missing required parameter: host');
          var historyId = _intOrNull(args['history_id']);
          var includeErrors = args['include_errors'] == true;
          var replaceExisting = args['replace_existing'] != false;

          var flows = await _collectFlows(host: host, historyId: historyId, limit: 500);
          if (flows.isEmpty) {
            return {'rulesCreated': 0, 'note': 'no captured flows for this host'};
          }

          var build = await OfflineMockBuilder.build(flows, includeErrors: includeErrors);
          var manager = await RequestMapManager.instance;

          var removed = 0;
          if (replaceExisting) {
            for (var index = manager.rules.length - 1; index >= 0; index--) {
              var name = manager.rules[index].name ?? '';
              if (!name.startsWith('mock ')) continue;
              await manager.deleteRule(index);
              removed++;
            }
          }

          var created = 0;
          var ruleIds = <String>[];
          for (var draft in build.rules) {
            var rule = RequestMapRule(name: draft.name, url: draft.pattern, type: RequestMapType.local);
            var item = RequestMapItem(
              statusCode: draft.statusCode,
              headers: draft.headers,
              body: draft.body,
              bodyType: MapBodyType.text.name,
            );
            await manager.addRule(rule, item);
            ruleIds.add(rule.id);
            created++;
          }
          if (created > 0 || removed > 0) await manager.flushConfig();

          return {
            'rulesCreated': created,
            'ruleIds': ruleIds,
            'rulesRemoved': removed,
            'coverage': {
              'endpoints': build.endpoints,
              'methods': build.rules.map((draft) => draft.method).toSet().toList(),
              'host': host,
              'methodConflicts': build.methodConflicts,
            },
            'skipped': {
              'noResponse': build.skippedNoResponse,
              'errors': build.skippedErrors,
              'binaryOrLarge': build.skippedBinary,
              'overRuleLimit': build.skippedOverLimit,
            },
            'note': 'Rules take effect immediately; disable or delete them when you go back online. '
                'Method conflicts mean two methods share a path but map-local matches URLs only — '
                'the newest response wins.',
          };
        },
      );

  /// 分页拉取流量（实时缓冲或历史会话），最多 [limit] 条。
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

  static int _intOr(dynamic value, int fallback) => _intOrNull(value) ?? fallback;

  static int? _intOrNull(dynamic value) {
    if (value is int) return value;
    if (value is num) return value.toInt();
    if (value is String) return int.tryParse(value);
    return null;
  }
}

class _McpBreakpointHandler implements BreakpointExternalHandler {
  @override
  Future<HttpRequest?> onRequestPaused(String requestId, HttpRequest request) async {
    var item = InterceptQueue.instance.enqueueRequest(requestId, request);
    var decision = await item.future;
    return _applyRequest(request, decision);
  }

  @override
  Future<HttpResponse?> onResponsePaused(String requestId, HttpRequest request, HttpResponse response) async {
    var item = InterceptQueue.instance.enqueueResponse(requestId, request, response);
    var decision = await item.future;
    return _applyResponse(request, response, decision);
  }

  @override
  void cancel(String requestId, {required bool response}) {
    InterceptQueue.instance.cancel(requestId, response: response);
  }

  static HttpRequest? _applyRequest(HttpRequest original, InterceptDecision decision) {
    if (decision.shouldDrop) return null;
    // 保留 requestId，透明加密在写线上时按 id 找明文/密文句柄。
    var request = original.copy()..requestId = original.requestId;
    decision.headers?.forEach((name, value) {
      request.headers.remove(name);
      request.headers.set(name, value);
    });
    var body = decision.body;
    if (body != null) request.body = utf8.encode(body);
    return request;
  }

  static HttpResponse? _applyResponse(HttpRequest request, HttpResponse original, InterceptDecision decision) {
    if (decision.shouldDrop) return null;
    var response = original.copy();
    response.request = request;
    var statusCode = decision.statusCode;
    if (statusCode != null) response.status = HttpStatus.valueOf(statusCode);
    decision.headers?.forEach((name, value) {
      response.headers.remove(name);
      response.headers.set(name, value);
    });
    var body = decision.body;
    if (body != null) response.body = utf8.encode(body);
    return response;
  }
}

class _DomainToolRegistration {
  _DomainToolRegistration({
    required this.host,
    required this.prefix,
    required this.names,
    required this.createdAtMs,
  });

  final String host;
  final String prefix;
  final List<String> names;
  final int createdAtMs;

  Map<String, dynamic> toJson() => {
        'host': host,
        'prefix': prefix,
        'count': names.length,
        'tools': names,
        'createdAtMs': createdAtMs,
      };
}
