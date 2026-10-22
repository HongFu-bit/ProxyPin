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

import 'package:flutter/foundation.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

import 'package:proxypin/network/util/logger.dart';

/// 安全存储后端；测试可替换为内存实现。
abstract class SecureBackend {
  Future<String?> read(String key);

  Future<void> write(String key, String value);

  Future<void> delete(String key);
}

class PluginSecureBackend implements SecureBackend {
  const PluginSecureBackend();

  /// macOS 关闭 Data Protection Keychain：使用登录钥匙串即可，无需 Keychain Sharing
  /// entitlement（启用它需要 provisioning profile，会限制分发）。
  static const FlutterSecureStorage _storage =
      FlutterSecureStorage(mOptions: MacOsOptions(usesDataProtectionKeychain: false));

  @override
  Future<String?> read(String key) => _storage.read(key: key);

  @override
  Future<void> write(String key, String value) => _storage.write(key: key, value: value);

  @override
  Future<void> delete(String key) => _storage.delete(key: key);
}

/// MCP token 与 CA 私钥的安全存储。
///
/// 平台后端：Android Keystore、iOS/macOS Keychain、Windows DPAPI、Linux libsecret。
/// 不可用时（测试环境、未安装 keyring）所有方法静默降级：读返回 null、写返回 false，
/// 调用方继续使用旧的明文文件，避免因升级直接把用户锁死。
class SecureStore {
  SecureStore._();

  static const String mcpTokenKey = 'proxypin.mcp_token';
  static const String caPrivateKeyKey = 'proxypin.ca_private_key';

  static SecureBackend backend = const PluginSecureBackend();

  static final Set<String> _warned = {};

  static bool get isSupported => !kIsWeb;

  static Future<String?> read(String key) async {
    if (!isSupported) return null;
    try {
      var value = await backend.read(key);
      return value != null && value.isNotEmpty ? value : null;
    } catch (e) {
      _warnOnce(key, 'read', e);
      return null;
    }
  }

  static Future<bool> write(String key, String value) async {
    if (!isSupported || value.isEmpty) return false;
    try {
      await backend.write(key, value);
      return true;
    } catch (e) {
      _warnOnce(key, 'write', e);
      return false;
    }
  }

  static Future<bool> delete(String key) async {
    if (!isSupported) return false;
    try {
      await backend.delete(key);
      return true;
    } catch (e) {
      _warnOnce(key, 'delete', e);
      return false;
    }
  }

  static Future<String?> readMcpToken() => read(mcpTokenKey);

  static Future<bool> writeMcpToken(String token) => write(mcpTokenKey, token);

  static Future<String?> readCaPrivateKey() => read(caPrivateKeyKey);

  static Future<bool> writeCaPrivateKey(String pem) => write(caPrivateKeyKey, pem);

  static Future<bool> deleteCaPrivateKey() => delete(caPrivateKeyKey);

  static void _warnOnce(String key, String op, Object error) {
    if (_warned.add('$op:$key')) {
      logger.w('Secure storage $op failed for $key; falling back to legacy storage: $error');
    }
  }

  @visibleForTesting
  static void resetForTest() {
    backend = const PluginSecureBackend();
    _warned.clear();
  }
}
