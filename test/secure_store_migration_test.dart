import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:proxypin/mcp/mcp_service.dart';
import 'package:proxypin/network/util/file_read.dart';
import 'package:proxypin/security/secure_store.dart';
import 'package:proxypin/ui/configuration.dart';

class _MemoryBackend implements SecureBackend {
  final Map<String, String> values = {};
  bool failWrite = false;

  @override
  Future<String?> read(String key) async => values[key];

  @override
  Future<void> write(String key, String value) async {
    if (failWrite) throw StateError('write failed');
    values[key] = value;
  }

  @override
  Future<void> delete(String key) async => values.remove(key);
}

void main() {
  late _MemoryBackend backend;
  late String home;
  String? previousHome;

  setUp(() {
    backend = _MemoryBackend();
    SecureStore.backend = backend;
    previousHome = FileRead.userHome;
    home = '${Directory.systemTemp.path}${Platform.pathSeparator}proxypin_migration_'
        '${DateTime.now().microsecondsSinceEpoch}';
    FileRead.userHome = home;
  });

  tearDown(() {
    SecureStore.resetForTest();
    FileRead.userHome = previousHome;
  });

  Future<File> configFile() async {
    var file = File('$home${Platform.pathSeparator}.proxypin${Platform.pathSeparator}ui_config.json');
    return file;
  }

  Future<Map<String, dynamic>> readConfig() async {
    var file = await configFile();
    return jsonDecode(await file.readAsString()) as Map<String, dynamic>;
  }

  group('MCP token migration', () {
    test('legacy plaintext token moves into secure storage and leaves ui_config', () async {
      var cfg = await AppConfiguration.instance;
      cfg.mcpToken = 'legacy-token';
      await cfg.flushConfig();
      expect((await readConfig())['mcpToken'], 'legacy-token');

      expect(await McpService.loadStoredToken(cfg), 'legacy-token');
      expect(backend.values[SecureStore.mcpTokenKey], 'legacy-token');
      expect(cfg.mcpToken, isNull);
      expect((await readConfig()).containsKey('mcpToken'), isFalse);

      // 二次启动直接命中安全存储，不再回写明文
      expect(await McpService.loadStoredToken(cfg), 'legacy-token');
      expect((await readConfig()).containsKey('mcpToken'), isFalse);
    });

    test('secure value wins and stale legacy value is cleared', () async {
      backend.values[SecureStore.mcpTokenKey] = 'secured-token';
      var cfg = await AppConfiguration.instance;
      cfg.mcpToken = 'stale-token';

      expect(await McpService.loadStoredToken(cfg), 'secured-token');
      expect(cfg.mcpToken, isNull);
      expect(backend.values[SecureStore.mcpTokenKey], 'secured-token');
    });

    test('secure write failure keeps the legacy value in place', () async {
      backend.failWrite = true;
      var cfg = await AppConfiguration.instance;
      cfg.mcpToken = 'legacy-token';

      expect(await McpService.loadStoredToken(cfg), 'legacy-token');
      expect(cfg.mcpToken, 'legacy-token');
      expect(backend.values, isEmpty);
    });

    test('returns null when neither store holds a token', () async {
      var cfg = await AppConfiguration.instance;
      cfg.mcpToken = null;
      expect(await McpService.loadStoredToken(cfg), isNull);
      expect(backend.values, isEmpty);
    });
  });
}
