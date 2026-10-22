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
import 'dart:io';
import 'dart:math';

import 'package:proxypin/mcp/capture/cert_status.dart';
import 'package:proxypin/mcp/capture/flow_store.dart';
import 'package:proxypin/mcp/capture/history_provider.dart';
import 'package:proxypin/mcp/extra/audit_log.dart';
import 'package:proxypin/mcp/extra/extra_tools.dart';
import 'package:proxypin/mcp/extra/flow_broadcaster.dart';
import 'package:proxypin/mcp/extra/intercept_queue.dart';
import 'package:proxypin/mcp/protocol/mcp_actions.dart';
import 'package:proxypin/mcp/protocol/mcp_server.dart';
import 'package:proxypin/mcp/transport/mcp_http_server.dart';
import 'package:proxypin/native/floating_window.dart';
import 'package:proxypin/network/bin/server.dart';
import 'package:proxypin/network/components/request_breakpoint.dart';
import 'package:proxypin/network/http/http.dart';
import 'package:proxypin/network/util/logger.dart';
import 'package:proxypin/security/secure_store.dart';
import 'package:proxypin/storage/histories.dart';
import 'package:proxypin/ui/configuration.dart';

/// MCP 服务编排：挂载抓包索引、启停本地 HTTP 传输。
///
/// 作为 [EventListener] 挂到 [ProxyServer.listeners]，与 UI 同源接收流量，
/// 因而平台无关且不依赖具体列表容器。默认所有平台都只绑 127.0.0.1；移动端可在设置页
/// 开启「允许局域网访问」绑 0.0.0.0 并要求 Bearer token，也可自定义监听地址。
/// 是否需要 Bearer token 按「暴露范围」决定：绑非回环地址才要求，只绑回环则免令牌。
/// 移动端可开启悬浮窗前台服务，避免 App 退到后台被系统冻结导致端口不可达。
/// 所有平台都优先固定 [defaultPort]
/// （移动端可经 cfg.mcpPort 自定义），被占用时才回退到系统随机端口，
/// 保证 AI 客户端一次配置、重启 App 后无需改动。AI 客户端直接以 HTTP 连接，无需额外桥进程。
///
/// @author wanghongen
class McpService {
  static final McpService instance = McpService._();

  McpService._();

  /// 默认监听端口；移动端可经 cfg.mcpPort 自定义，被占用时回退随机端口。
  static const int defaultPort = 9127;

  FlowStore? _store;
  McpServer? _mcp;
  McpHttpServer? _http;
  ProxyServer? _attachedServer;

  /// 本次启动注册到断点拦截器的外部处理器（停服时注销）
  BreakpointExternalHandler? _breakpointHandler;

  /// 桥接 HistoryStorage 的历史数据源（lazy，与 FlowStore 同生命周期）
  late final HistoryProvider _historyProvider = _HistoryStorageBridge();

  FlowStore _createStore() => FlowStore(historyProvider: _historyProvider);

  /// 串行化 start/stop，避免自动启动与手动开关并发时重复 bind 端口
  Future<void>? _transitionLock;

  Future<void> _synchronized(Future<void> Function() action) {
    var previous = _transitionLock ?? Future<void>.value();
    var next = previous.then((_) => action());
    // 单次失败不能让后续操作永远拿不到锁
    _transitionLock = next.catchError((_) {});
    return next;
  }

  /// 由 UI 层注册：清空界面抓包列表（MCP clear_session 时一并触发）
  Future<void> Function()? clearUiSession;

  bool get isRunning => _http?.isRunning ?? false;

  /// 供脚本 `context.mcp.call` 等进程内调用方复用同一套工具实现。
  McpServer? get server => _mcp;

  int? get port => _http?.port;

  /// 移动端 LAN 模式的访问 token；桌面 loopback 模式为 null
  String? get token => _http?.token;

  /// 是否移动端（决定默认绑定地址：移动端 0.0.0.0、桌面 127.0.0.1）
  bool get lanMode => Platform.isAndroid || Platform.isIOS;

  /// 生成并持久化 token：优先安全存储，不可用时回退到 ui_config.json。
  static Future<String> generateAndStoreToken(AppConfiguration cfg) async {
    var token = generateToken();
    if (await SecureStore.writeMcpToken(token)) {
      if (cfg.mcpToken != null) {
        cfg.mcpToken = null;
        await cfg.flushConfig();
      }
    } else {
      cfg.mcpToken = token;
      await cfg.flushConfig();
    }
    return token;
  }

  /// 读取 token 并迁移旧明文：安全存储优先；旧值迁移成功后从 ui_config 删除。
  static Future<String?> loadStoredToken(AppConfiguration cfg) async {
    var secured = await SecureStore.readMcpToken();
    var legacy = cfg.mcpToken;
    if (secured != null) {
      if (legacy != null) {
        cfg.mcpToken = null;
        await cfg.flushConfig();
      }
      return secured;
    }
    if (legacy == null || legacy.isEmpty) return null;
    if (await SecureStore.writeMcpToken(legacy)) {
      cfg.mcpToken = null;
      await cfg.flushConfig();
    }
    return legacy;
  }

  /// 生成 48 位十六进制随机 token
  static String generateToken() {
    var random = Random.secure();
    return List.generate(24, (_) => random.nextInt(256).toRadixString(16).padLeft(2, '0')).join();
  }

  /// 解析用户自定义的监听地址；为空或非法时返回 null（表示按平台自动）
  static InternetAddress? _parseBind(String? address) {
    var value = address?.trim();
    if (value == null || value.isEmpty) return null;
    return InternetAddress.tryParse(value);
  }

  /// 判断是否为回环地址（仅本机可达）——据此决定是否要求 Bearer token
  static bool _isLoopback(InternetAddress address) {
    var raw = address.rawAddress;
    if (address.type == InternetAddressType.IPv4) {
      return raw.length == 4 && raw[0] == 127;
    }
    // IPv6 回环为 ::1
    return raw.length == 16 && raw.take(15).every((b) => b == 0) && raw[15] == 1;
  }

  /// 注册抓包索引到代理服务（幂等）。[existing] 用于启用时一次性回填已抓到的请求。
  void attach(ProxyServer server, {Iterable<HttpRequest>? existing}) {
    _store ??= _createStore();
    _attachedServer = server;
    if (!server.listeners.contains(_store)) {
      server.addListener(_store!);
    }
    if (!server.listeners.contains(FlowBroadcaster.instance)) {
      server.addListener(FlowBroadcaster.instance);
    }
    if (existing != null && existing.isNotEmpty) {
      _store!.backfill(existing);
    }
  }

  /// 按当前配置启动（必要时先挂到已存在的代理服务）。串行执行，避免并发重复绑定。
  Future<void> start(AppConfiguration cfg) => _synchronized(() => _startLocked(cfg));

  Future<void> _startLocked(AppConfiguration cfg) async {
    if (isRunning) return;

    var proxyServer = _attachedServer ?? ProxyServer.current;
    if (proxyServer != null) {
      attach(proxyServer);
    }
    _store ??= _createStore();

    var actions = McpActions(
      store: _store!,
      onClearSession: () async => clearUiSession?.call(),
      certStatusProvider: Platform.isMacOS || Platform.isWindows || Platform.isLinux ? CertStatus.query : null,
      redactEnabled: () => cfg.mcpRedactEnabled,
    );
    var audit = AuditLog(enabled: () => cfg.mcpAuditEnabled);
    var extras = McpExtraTools(
      store: _store!,
      redactEnabled: () => cfg.mcpRedactEnabled,
      audit: audit,
    );
    _mcp = McpServer(
      store: _store!,
      redactEnabled: () => cfg.mcpRedactEnabled,
      extraTools: [...actions.tools(), ...extras.tools()],
    );
    // 绑定地址优先级：用户自定义 > 平台默认。
    // 移动端默认只绑 127.0.0.1（无需令牌）；只有显式开启「允许局域网访问」才绑 0.0.0.0。
    // 桌面默认 loopback。
    InternetAddress bindAddress = _parseBind(cfg.mcpAddress) ??
        (lanMode && cfg.mcpLanEnabled ? InternetAddress.anyIPv4 : InternetAddress.loopbackIPv4);

    // 令牌按「暴露范围」而非平台决定：只有绑到非回环地址（局域网可达）才要求
    // Bearer token；只绑回环（仅本机可达）时免令牌——这样手机本机客户端也不用带。
    String? token;
    if (!_isLoopback(bindAddress)) {
      token = await loadStoredToken(cfg);
      if (token == null || token.isEmpty) token = await generateAndStoreToken(cfg);
    } else {
      // 回环模式不需要令牌，但仍迁移旧明文，避免密码留在 ui_config.json。
      await loadStoredToken(cfg);
    }
    _http = McpHttpServer(mcp: _mcp!, address: bindAddress, token: token, audit: audit);

    // 所有平台都优先固定端口，便于 AI 客户端一次配置、重启后无需改动；
    // 端口被占用时回退到系统分配的空闲端口。桌面与移动端均可经 cfg.mcpPort 自定义。
    var preferredPort = cfg.mcpPort ?? defaultPort;
    try {
      try {
        await _http!.start(preferredPort);
      } on SocketException catch (e) {
        logger.w('MCP port $preferredPort unavailable, falling back to a random port: $e');
        await _http!.start(0);
        // 回写真实端口：否则客户端里配置的固定端口会永久失效，而界面仍显示“已启动”
        cfg.mcpPort = _http!.port;
        await cfg.flushConfig();
        logger.w('MCP port $preferredPort busy, now listening on ${_http!.port}');
      }
      logger.i('MCP service started on ${bindAddress.address}:${_http!.port}');
      // 交互式断点：MCP 与 UI 共享同一批挂起请求，谁先处置谁生效
      _breakpointHandler = extras.breakpointHandler;
      RequestBreakpointInterceptor.externalHandler = _breakpointHandler;
      // 移动端可按需启动悬浮窗前台服务，避免 App 退到后台后被系统冻结
      if (Platform.isAndroid && cfg.mcpFloatingEnabled) {
        unawaited(FloatingWindow.ensureStarted());
      }
    } catch (e) {
      logger.e('MCP service start failed: $e');
      _detachBreakpointHandler();
      InterceptQueue.instance.clear();
      _http = null;
      rethrow;
    }
  }

  /// 注销断点钩子并放行所有挂起请求，避免停服后目标 App 的请求继续悬挂。
  void _detachBreakpointHandler() {
    var handler = _breakpointHandler;
    if (handler != null && RequestBreakpointInterceptor.externalHandler == handler) {
      RequestBreakpointInterceptor.externalHandler = null;
    }
    _breakpointHandler = null;
  }

  Future<void> stop() => _synchronized(_stopLocked);

  Future<void> _stopLocked() async {
    _detachBreakpointHandler();
    InterceptQueue.instance.clear();
    await _http?.stop();
    _http = null;
    _mcp = null;
    // 停用 MCP 后不再需要保持进程存活，收起悬浮窗前台服务
    if (Platform.isAndroid) {
      unawaited(FloatingWindow.stop());
    }
    // 解绑抓包监听并清空索引：关闭后不再缓冲流量，避免停用期间抓到的敏感请求
    // 在下次开启时被局域网客户端读到；同时避免 start/stop 反复切换造成监听器堆积。
    if (_store != null) {
      _attachedServer?.removeListener(_store!);
      _store!.clear();
    }
  }
}

/// 桥接 [HistoryStorage] 为 [HistoryProvider]。
///
/// 放在编排层，避免 mcp 核心直接依赖历史存储及其平台插件。请求列表的懒加载/缓存
/// 由 [HistoryStorage.getRequests] 自身保证（缓存在 HistoryItem.requests）。
class _HistoryStorageBridge implements HistoryProvider {
  @override
  Future<List<HistoryMeta>> list() async {
    var storage = await HistoryStorage.instance;
    var histories = storage.histories;
    return [
      for (var history in histories)
        HistoryMeta(
          id: history.stableId,
          name: history.name,
          requestCount: history.requestLength,
          fileSize: history.fileSize,
          createTimeMs: history.createTime.millisecondsSinceEpoch,
        )
    ];
  }

  @override
  Future<List<HttpRequest>> requests(int id) async {
    var storage = await HistoryStorage.instance;
    HistoryItem? history;
    for (var item in storage.histories) {
      if (item.stableId == id) {
        history = item;
        break;
      }
    }
    if (history == null) throw ArgumentError('history not found: $id');
    // 不写入 HistoryItem 永久缓存：报文只由 FlowStore 的 LRU 有界持有
    return await storage.readRequests(history);
  }
}
