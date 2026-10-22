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

import 'package:proxypin/mcp/protocol/mcp_server.dart';
import 'package:proxypin/mcp/protocol/mcp_tool.dart';
import 'package:proxypin/network/components/ws_control.dart';

/// WebSocket 主动写入 / 双向改写工具。
class WsTools {
  List<McpTool> tools() => [
        _send(),
        _setRewrite(),
        _listRewrites(),
      ];

  McpTool _send() => McpTool(
        name: 'send_ws_message',
        description:
            'Push a frame into a live WebSocket session. `to=server` impersonates the client (masked frame), '
            '`to=client` impersonates the server (unmasked). The injected frame is also appended to the flow messages. '
            'Only works while the connection is open; history sessions have no live socket.',
        inputSchema: {
          'type': 'object',
          'properties': {
            'flowId': {'type': 'string', 'description': 'Live flow id (the WebSocket handshake request id)'},
            'payload': {'type': 'string'},
            'encoding': {'type': 'string', 'enum': ['utf8', 'base64'], 'description': 'Default utf8'},
            'opcode': {
              'type': 'string',
              'description': 'text (default) / binary; a raw number 1/2 is also accepted'
            },
            'to': {'type': 'string', 'enum': ['server', 'client'], 'description': 'Default server'},
          },
          'required': ['flowId', 'payload'],
        },
        handler: (args) async {
          var id = args['flowId']?.toString() ?? '';
          var session = WebSocketControl.instance.session(id);
          if (session == null || !session.isOpen) {
            throw ToolException('no open WebSocket session for flow $id; trigger the connection first');
          }
          var raw = args['payload']?.toString() ?? '';
          Uint8List payload;
          if (args['encoding']?.toString() == 'base64') {
            try {
              payload = base64.decode(raw);
            } catch (e) {
              throw ToolException('payload is not valid base64: $e');
            }
          } else {
            payload = Uint8List.fromList(utf8.encode(raw));
          }

          var opcodeValue = args['opcode'];
          var opcode = 1;
          if (opcodeValue is num) {
            opcode = opcodeValue.toInt();
          } else if (opcodeValue?.toString() == 'binary') {
            opcode = 2;
          } else if (opcodeValue != null && opcodeValue.toString() != 'text') {
            throw ToolException('opcode must be text or binary');
          }
          if (opcode != 1 && opcode != 2) throw ToolException('opcode must be 1 (text) or 2 (binary)');

          var to = args['to']?.toString() ?? 'server';
          if (to != 'server' && to != 'client') throw ToolException('to must be server or client');
          try {
            var frame = WebSocketControl.instance.send(id,
                payload: payload, opcode: opcode, toClient: to == 'client');
            return {
              'sent': true,
              'flowId': id,
              'to': to,
              'opcode': opcode,
              'bytes': payload.length,
              'preview': opcode == 1 ? utf8.decode(payload, allowMalformed: true) : base64.encode(payload),
              'time': frame.time.millisecondsSinceEpoch,
            };
          } on StateError catch (e) {
            throw ToolException(e.message);
          }
        },
      );

  McpTool _setRewrite() => McpTool(
        name: 'set_ws_rewrite',
        description:
            'Add a text-frame rewrite rule to a live WebSocket session, or clear all rules with clear:true. '
            'The rule is applied to complete text frames in the chosen direction before forwarding; binary/control '
            'frames pass through unchanged. Frames split across TCP reads are buffered until complete, so no partial '
            r'frame is forwarded. Regex replace supports $1 group references.',
        inputSchema: {
          'type': 'object',
          'properties': {
            'flowId': {'type': 'string'},
            'match': {'type': 'string'},
            'replace': {'type': 'string'},
            'direction': {'type': 'string', 'enum': ['both', 'c2s', 's2c'], 'description': 'Default both'},
            'regex': {'type': 'boolean', 'description': 'Default true'},
            'clear': {'type': 'boolean', 'description': 'Remove all rules for this flow and return'},
          },
          'required': ['flowId'],
        },
        handler: (args) async {
          var id = args['flowId']?.toString() ?? '';
          var session = WebSocketControl.instance.session(id);
          if (session == null || !session.isOpen) {
            throw ToolException('no open WebSocket session for flow $id; trigger the connection first');
          }
          if (args['clear'] == true) {
            WebSocketControl.instance.setRules(id, const []);
            return {'flowId': id, 'cleared': true, 'rules': 0};
          }

          var match = args['match']?.toString() ?? '';
          if (match.isEmpty) throw ToolException('match is required (or pass clear:true)');
          var replace = args['replace']?.toString() ?? '';
          var direction = args['direction']?.toString() ?? 'both';
          if (!{'both', 'c2s', 's2c'}.contains(direction)) {
            throw ToolException('direction must be both / c2s / s2c');
          }
          var regex = args['regex'] != false;
          if (regex) {
            try {
              RegExp(match);
            } catch (e) {
              throw ToolException('invalid regular expression: $e');
            }
          }

          var rules = [...WebSocketControl.instance.rules(id)];
          rules.add(WsRewriteRule(match: match, replace: replace, regex: regex, direction: direction));
          WebSocketControl.instance.setRules(id, rules);
          return {
            'flowId': id,
            'added': true,
            'rules': WebSocketControl.instance.rules(id).length,
            'rule': WsRewriteRule(match: match, replace: replace, regex: regex, direction: direction).toJson(),
            'note': 'Rules live in memory and disappear when the WebSocket closes or ProxyPin restarts.',
          };
        },
      );

  McpTool _listRewrites() => McpTool(
        name: 'list_ws_rewrites',
        description: 'List in-memory WebSocket rewrite rules grouped by live flow id.',
        inputSchema: {'type': 'object', 'properties': {}},
        handler: (_) async {
          var all = WebSocketControl.instance.allRules();
          return {
            'count': all.length,
            'flows': all.entries
                .map((entry) => {
                      'flowId': entry.key,
                      'open': WebSocketControl.instance.session(entry.key)?.isOpen ?? false,
                      'rules': entry.value.map((rule) => rule.toJson()).toList(),
                    })
                .toList(),
          };
        },
      );
}
