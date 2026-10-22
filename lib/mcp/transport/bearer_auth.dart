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

/// 校验 `Authorization: Bearer <token>`，全长度常量时间比较。
///
/// 长度不同直接返回 false，避免逐字符提前返回泄漏 token 前缀。
bool bearerTokenMatches(String? header, String token) {
  var want = 'Bearer $token';
  if (header == null || header.length != want.length) return false;
  var diff = 0;
  for (var i = 0; i < want.length; i++) {
    diff |= header.codeUnitAt(i) ^ want.codeUnitAt(i);
  }
  return diff == 0;
}
