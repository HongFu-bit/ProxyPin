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

import 'package:proxypin/network/bin/listener.dart';
import 'package:proxypin/network/channel/channel.dart';
import 'package:proxypin/network/channel/channel_context.dart';
import 'package:proxypin/network/http/http.dart';
import 'package:proxypin/network/http/websocket.dart';

/// 双向 WebSocket 改写规则。只处理完整 text frame；binary/ping/close 原样转发。
class WsRewriteRule {
  final String match;
  final String replace;

  /// true 时按正则匹配，[replace] 支持 `$1` 分组引用。
  final bool regex;

  /// both / c2s / s2c
  final String direction;

  WsRewriteRule({required this.match, required this.replace, this.regex = true, this.direction = 'both'});

  bool get appliesToClientFrames => direction == 'both' || direction == 'c2s';
  bool get appliesToServerFrames => direction == 'both' || direction == 's2c';

  Map<String, dynamic> toJson() => {
        'match': match,
        'replace': replace,
        'regex': regex,
        'direction': direction,
      };
}

/// 一条活跃 WS 连接的可写句柄与改写规则。
class WsSession {
  final String id;
  final HttpRequest? request;
  Channel? clientChannel;
  Channel? serverChannel;
  ChannelContext? context;
  EventListener? listener;

  WsSession(this.id, this.request);

  bool get isOpen => clientChannel?.isOpen == true && serverChannel?.isOpen == true;
}

/// WebSocket 会话注册表 + 帧编码 + 改写执行。
///
/// 中继层在每次读到帧时 [attach] 一次（幂等），因此工具侧总能拿到两个方向的
/// 写句柄；连接关闭时由处理器 [detach]。
class WebSocketControl {
  static final WebSocketControl instance = WebSocketControl._();

  WebSocketControl._();

  static const int _maxSessions = 200;
  static const int _maxRules = 100;

  final Map<String, WsSession> _sessions = {};
  final Map<String, List<WsRewriteRule>> _rules = {};

  void attach(
    String id,
    Channel proxyChannel, {
    required bool toClient,
    HttpRequest? request,
    ChannelContext? context,
    EventListener? listener,
  }) {
    var session = _sessions[id];
    if (session == null) {
      if (_sessions.length >= _maxSessions) _sessions.remove(_sessions.keys.first);
      session = WsSession(id, request);
      _sessions[id] = session;
    }
    if (toClient) {
      session.clientChannel = proxyChannel;
    } else {
      session.serverChannel = proxyChannel;
    }
    session.context ??= context;
    session.listener ??= listener;
  }

  void detach(String id, {required bool toClient}) {
    var session = _sessions[id];
    if (session == null) return;
    if (toClient) {
      session.clientChannel = null;
    } else {
      session.serverChannel = null;
    }
    if (session.clientChannel == null && session.serverChannel == null) {
      _sessions.remove(id);
    }
  }

  WsSession? session(String id) => _sessions[id];

  void setRules(String id, List<WsRewriteRule> rules) {
    if (rules.isEmpty) {
      _rules.remove(id);
    } else {
      _rules[id] = rules.take(_maxRules).toList();
    }
  }

  List<WsRewriteRule> rules(String id) => _rules[id] ?? const [];

  Map<String, List<WsRewriteRule>> allRules() => Map.unmodifiable(_rules);

  /// 返回重新编码后的字节；没有规则命中时返回 null（调用方直接透传原始字节）。
  Uint8List? rewrite(WebSocketFrame frame, String id, {required bool toClient}) {
    if (!frame.isText) return null;
    var applicable = rules(id)
        .where((rule) => toClient ? rule.appliesToServerFrames : rule.appliesToClientFrames)
        .toList();
    if (applicable.isEmpty) return null;

    var text = utf8.decode(frame.payloadData, allowMalformed: true);
    var updated = text;
    for (var rule in applicable) {
      try {
        if (rule.regex) {
          updated = updated.replaceAllMapped(RegExp(rule.match), (m) => _expand(m, rule.replace));
        } else {
          updated = updated.replaceAll(rule.match, rule.replace);
        }
      } catch (_) {
        // 单条规则的正则/替换非法时跳过，不影响其它规则
      }
    }
    if (updated == text) return null;

    return encodeFrame(
      opcode: 0x01,
      payload: Uint8List.fromList(utf8.encode(updated)),
      mask: frame.mask,
      fin: frame.fin,
    );
  }

  /// 向活跃会话推送一帧；[toClient] 为 true 表示伪装成服务端下行。
  WebSocketFrame send(
    String id, {
    required Uint8List payload,
    int opcode = 0x01,
    bool toClient = false,
  }) {
    var session = _sessions[id];
    if (session == null) throw StateError('no active WebSocket session for flow $id');
    var target = toClient ? session.clientChannel : session.serverChannel;
    if (target == null || !target.isOpen) {
      throw StateError('WebSocket ${toClient ? 'client' : 'server'} channel is not open');
    }
    var frame = WebSocketFrame(
      fin: true,
      opcode: opcode,
      mask: !toClient,
      maskingKey: 0,
      payloadLength: payload.length,
      payloadData: payload,
    )..isFromClient = toClient;

    target.writeBytes(encodeFrame(opcode: opcode, payload: payload, mask: !toClient));
    session.request?.messages.add(frame);
    var request = session.request;
    if (request != null) {
      try {
        session.listener?.onMessage(
            toClient ? session.clientChannel! : session.serverChannel!, request, frame);
      } catch (_) {
        // 监听器异常不应影响已发出的帧
      }
    }
    return frame;
  }

  static Uint8List encodeFrame({
    required int opcode,
    required Uint8List payload,
    required bool mask,
    bool fin = true,
  }) {
    var header = BytesBuilder();
    header.addByte((fin ? 0x80 : 0x00) | (opcode & 0x0f));
    var maskBit = mask ? 0x80 : 0x00;
    if (payload.length < 126) {
      header.addByte(maskBit | payload.length);
    } else if (payload.length <= 0xffff) {
      header.addByte(maskBit | 126);
      header.addByte((payload.length >> 8) & 0xff);
      header.addByte(payload.length & 0xff);
    } else {
      header.addByte(maskBit | 127);
      for (var shift = 56; shift >= 0; shift -= 8) {
        header.addByte((payload.length >> shift) & 0xff);
      }
    }

    if (!mask) {
      header.add(payload);
      return header.takeBytes();
    }

    var key = List<int>.generate(4, (_) => Random.secure().nextInt(256));
    header.add(key);
    var masked = Uint8List(payload.length);
    for (var i = 0; i < payload.length; i++) {
      masked[i] = payload[i] ^ key[i % 4];
    }
    header.add(masked);
    return header.takeBytes();
  }

  static Uint8List decodeBase64(String value) => base64.decode(value);

  /// 展开 `$1` 分组引用（Dart 的 Match 没有内建 expand）。
  static String _expand(Match match, String replacement) =>
      replacement.replaceAllMapped(RegExp(r'\$(\d+)'), (ref) => match.group(int.parse(ref.group(1)!)) ?? '');
}
