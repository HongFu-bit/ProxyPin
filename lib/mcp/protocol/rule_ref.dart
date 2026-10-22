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

import 'mcp_server.dart';

/// 规则稳定标识参数；优先于 [ruleIndexSchema]。
const Map<String, dynamic> ruleIdSchema = {
  'type': 'string',
  'description': 'Stable rule id from list_rules (preferred)',
};

/// 旧版位置索引；列表增删后会漂移，仅为兼容保留。
const Map<String, dynamic> ruleIndexSchema = {
  'type': 'integer',
  'description': 'Legacy positional index; use id instead',
};

/// 规则寻址：优先稳定 id，兼容旧的 index。
int resolveRuleIndex<T>(List<T> rules, Map<String, dynamic> args, String Function(T) idOf, String kind) {
  var id = args['id']?.toString();
  if (id != null && id.isNotEmpty) {
    var index = rules.indexWhere((e) => idOf(e) == id);
    if (index < 0) throw ToolException('$kind not found: $id (call list_rules for valid ids)');
    return index;
  }
  var raw = args['index'];
  int? index;
  if (raw is int) {
    index = raw;
  } else if (raw is num) {
    index = raw.toInt();
  } else if (raw is String) {
    index = int.tryParse(raw);
  }
  if (index == null) throw ToolException('missing id (or legacy index) for $kind');
  if (index < 0 || index >= rules.length) throw ToolException('invalid index');
  return index;
}
