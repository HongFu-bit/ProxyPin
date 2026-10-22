import 'dart:async';

import 'package:flutter_test/flutter_test.dart';
import 'package:proxypin/mcp/transport/bearer_auth.dart';
import 'package:proxypin/security/secure_store.dart';

class _MemoryBackend implements SecureBackend {
  final Map<String, String> values = {};
  bool failRead = false;
  bool failWrite = false;
  bool failDelete = false;

  @override
  Future<String?> read(String key) async {
    if (failRead) throw StateError('read failed');
    return values[key];
  }

  @override
  Future<void> write(String key, String value) async {
    if (failWrite) throw StateError('write failed');
    values[key] = value;
  }

  @override
  Future<void> delete(String key) async {
    if (failDelete) throw StateError('delete failed');
    values.remove(key);
  }
}

void main() {
  late _MemoryBackend backend;

  setUp(() {
    backend = _MemoryBackend();
    SecureStore.backend = backend;
  });

  tearDown(SecureStore.resetForTest);

  group('SecureStore', () {
    test('writes, reads and deletes secrets by key', () async {
      expect(await SecureStore.writeMcpToken('abc123'), isTrue);
      expect(await SecureStore.readMcpToken(), 'abc123');

      expect(await SecureStore.writeCaPrivateKey('-----BEGIN KEY-----'), isTrue);
      expect(await SecureStore.readCaPrivateKey(), '-----BEGIN KEY-----');
      expect(backend.values.keys, containsAll([SecureStore.mcpTokenKey, SecureStore.caPrivateKeyKey]));

      expect(await SecureStore.deleteCaPrivateKey(), isTrue);
      expect(await SecureStore.readCaPrivateKey(), isNull);
      expect(await SecureStore.readMcpToken(), 'abc123');
    });

    test('rejects empty values so callers keep legacy storage', () async {
      expect(await SecureStore.writeMcpToken(''), isFalse);
      expect(backend.values, isEmpty);

      backend.values[SecureStore.mcpTokenKey] = '';
      expect(await SecureStore.readMcpToken(), isNull);
    });

    test('read failure degrades to null instead of throwing', () async {
      backend.failRead = true;
      expect(await SecureStore.readMcpToken(), isNull);
      expect(await SecureStore.readCaPrivateKey(), isNull);
    });

    test('write/delete failure degrades to false instead of throwing', () async {
      backend.failWrite = true;
      expect(await SecureStore.writeMcpToken('token'), isFalse);

      backend.failWrite = false;
      await SecureStore.writeMcpToken('token');
      backend.failDelete = true;
      expect(await SecureStore.delete(SecureStore.mcpTokenKey), isFalse);
      expect(await SecureStore.readMcpToken(), 'token');
    });

    test('resetForTest restores the plugin backend', () async {
      SecureStore.resetForTest();
      expect(SecureStore.backend, isA<PluginSecureBackend>());
    });
  });

  group('bearerTokenMatches', () {
    const token = 'a1b2c3d4e5f6';

    test('accepts exact scheme and token', () {
      expect(bearerTokenMatches('Bearer $token', token), isTrue);
    });

    test('rejects null, empty and wrong scheme', () {
      expect(bearerTokenMatches(null, token), isFalse);
      expect(bearerTokenMatches('', token), isFalse);
      expect(bearerTokenMatches(token, token), isFalse);
      expect(bearerTokenMatches('Basic $token', token), isFalse);
    });

    test('rejects prefix, suffix and same-length mismatches', () {
      expect(bearerTokenMatches('Bearer a1b2c3', token), isFalse);
      expect(bearerTokenMatches('Bearer ${token}ff', token), isFalse);
      expect(bearerTokenMatches('Bearer a1b2c3d4e5f7', token), isFalse);
    });
  });
}
