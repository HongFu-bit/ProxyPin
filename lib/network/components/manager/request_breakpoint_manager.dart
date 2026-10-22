import 'dart:convert';
import 'dart:io';

import 'package:proxypin/network/http/http.dart';
import 'package:proxypin/storage/path.dart';
import 'package:proxypin/network/util/logger.dart';
import 'package:proxypin/utils/rule_id.dart';

class RequestBreakpointRule {
  /// 稳定标识，供 MCP 等外部调用方寻址；旧配置缺省时自动生成并回写。
  final String id;
  bool enabled;
  String? name;
  String url;

  bool interceptRequest;
  bool interceptResponse;

  // Optional HTTP method matching; null means match any method
  HttpMethod? method;

  RequestBreakpointRule({
    String? id,
    this.enabled = true,
    this.name,
    required this.url,
    this.interceptRequest = true,
    this.interceptResponse = true,
    this.method,
  }) : id = id ?? newRuleId();

  bool match(String url, {HttpMethod? method}) {
    if (!enabled) return false;
    if (this.method != null && method != null && this.method != method) return false;
    return RegExp(this.url).hasMatch(url);
  }

  factory RequestBreakpointRule.fromJson(Map<dynamic, dynamic> map) {
    HttpMethod? method;
    try {
      if (map['method'] != null) {
        method = HttpMethod.valueOf(map['method']);
      }
    } catch (e) {
      logger.e('Failed to parse HTTP method from request intercept rule', error: e);
    }

    return RequestBreakpointRule(
      id: map['id']?.toString(),
      enabled: map['enabled'] ?? true,
      name: map['name'],
      url: map['url'] ?? '',
      interceptRequest: map['interceptRequest'] ?? true,
      interceptResponse: map['interceptResponse'] ?? true,
      method: method,
    );
  }

  Map<String, dynamic> toJson() {
    return {
      'id': id,
      'enabled': enabled,
      'name': name,
      'url': url,
      'interceptRequest': interceptRequest,
      'interceptResponse': interceptResponse,
      'method': method?.name,
    };
  }
}

class RequestBreakpointManager {
  static RequestBreakpointManager? _instance;

  RequestBreakpointManager._();

  static Future<RequestBreakpointManager> get instance async {
    if (_instance == null) {
      _instance = RequestBreakpointManager._();
      await _instance!.load();
    }
    return _instance!;
  }

  bool enabled = true;
  List<RequestBreakpointRule> list = [];

  Future<void> load() async {
    try {
      var home = await Paths.homePath();
      var file = File('$home${Platform.pathSeparator}request_breakpoint.json');
      if (await file.exists()) {
        var json = jsonDecode(await file.readAsString());
        enabled = json['enabled'] ?? false;
        var rawList = json['list'] as List? ?? [];
        list = rawList.map((e) => RequestBreakpointRule.fromJson(e)).toList();
        // 旧配置没有 id：生成后立即回写，保证跨重启稳定
        if (rawList.any((e) => e is Map && (e['id'] == null || e['id'].toString().isEmpty))) {
          await save();
        }
      }
    } catch (e) {
      logger.e('Failed to load request breakpoint config', error: e);
    }
  }

  Future<void> save() async {
    try {
      var home = await Paths.homePath();
      var file = File('$home${Platform.pathSeparator}request_breakpoint.json');
      if (!await file.exists()) {
        await file.create(recursive: true);
      }
      var json = {
        'enabled': enabled,
        'list': list.map((e) => e.toJson()).toList(),
      };
      await file.writeAsString(jsonEncode(json));
    } catch (e) {
      logger.e('Failed to save request breakpoint config', error: e);
    }
  }

  void add(RequestBreakpointRule rule) {
    list.add(rule);
    save();
  }

  void remove(RequestBreakpointRule rule) {
    list.remove(rule);
    save();
  }
}
