/*
 * Copyright 2023 Hongen Wang All rights reserved.
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

import 'package:path_provider/path_provider.dart';
import 'package:proxypin/network/util/url_pattern.dart';
import 'package:proxypin/utils/rule_id.dart';

/// 请求屏蔽
/// @author wanghongen
/// 2024/02/02
class RequestBlockManager {
  static RequestBlockManager? _instance;
  bool enabled = true;
  List<RequestBlockItem> list = [];
  final File _storageFile;

  RequestBlockManager._(this._storageFile);

  ///单例
  static Future<RequestBlockManager> get instance async {
    if (_instance == null) {
      var file = await configFile();
      _instance = RequestBlockManager._(file);
      await _instance?._load();
    }
    return _instance!;
  }

  static Future<File> configFile() async {
    var directory = await getApplicationSupportDirectory().then((it) => it.path);
    var file = File('$directory${Platform.pathSeparator}request_block.json');
    if (!await file.exists()) {
      await file.create(recursive: true);
    }
    return file;
  }

  ///加载
  Future<void> _load() async {
    var json = await _storageFile.readAsString();
    if (json.isEmpty) return;
    var config = jsonDecode(json);
    enabled = config['enabled'] == true;
    list.clear();
    var rawList = config['list'] as List? ?? [];
    for (var element in rawList) {
      list.add(RequestBlockItem.fromJson(element));
    }
    // 旧配置没有 id：生成后立即回写，保证跨重启稳定
    if (rawList.any((e) => e is Map && (e['id'] == null || e['id'].toString().isEmpty))) {
      await flushConfig();
    }
  }

  addBlockRequest(RequestBlockItem item) {
    list.add(item);
    flushConfig();
  }

  removeBlockRequest(int index) {
    list.removeAt(index);
    flushConfig();
  }

  /// 是否启用
  bool enableBlockRequest(String url) {
    if (!enabled) {
      return false;
    }
    return list.any((element) => element.match(url, BlockType.blockRequest));
  }

  bool enableBlockResponse(String url) {
    if (!enabled) {
      return false;
    }
    return list.any((element) => element.match(url, BlockType.blockResponse));
  }

  ///刷新配置
  Future<void> flushConfig() async {
    _storageFile.writeAsString(jsonEncode({'enabled': enabled, 'list': list}));
  }
}

enum BlockType {
  blockRequest('屏蔽请求'),
  blockResponse('屏蔽响应');

  //名称
  final String label;

  const BlockType(this.label);
  static BlockType nameOf(String name) {
    return BlockType.values.firstWhere((element) => element.name == name);
  }
}

class RequestBlockItem {
  /// 稳定标识，供 MCP 等外部调用方寻址；旧配置缺省时自动生成并回写。
  final String id;
  bool enabled = true;
  String url;
  BlockType type;
  RegExp? urlReg;

  RequestBlockItem(this.enabled, this.url, this.type, {String? id}) : id = id ?? newRuleId();

  //匹配url
  bool match(String matchUrl, BlockType blockType) {
    urlReg ??= UrlPattern.toHostRegExp(url);
    return enabled && type == blockType && urlReg!.hasMatch(matchUrl);
  }

  factory RequestBlockItem.fromJson(Map<String, dynamic> json) {
    return RequestBlockItem(json['enabled'], json['url'], BlockType.nameOf(json['type']), id: json['id']?.toString());
  }

  Map<String, dynamic> toJson() {
    return {'id': id, 'enabled': enabled, 'url': url, 'type': type.name};
  }

  @override
  String toString() {
    return toJson().toString();
  }
}
