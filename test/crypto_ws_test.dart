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
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:pointycastle/asymmetric/api.dart';
import 'package:proxypin/mcp/capture/flow_store.dart';
import 'package:proxypin/mcp/extra/crypto_tools.dart';
import 'package:proxypin/network/components/crypto_transparent.dart';
import 'package:proxypin/network/components/js/context_bridge.dart';
import 'package:proxypin/network/components/ws_control.dart';
import 'package:proxypin/network/http/http.dart';
import 'package:proxypin/network/http/websocket.dart';
import 'package:proxypin/network/util/crypto.dart';

String _hex(List<int> bytes) => bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

Uint8List _hexBytes(String value) {
  var out = Uint8List(value.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(value.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}

void main() {
  group('crypto profile', () {
    test('AES-128-ECB/NoPadding matches the FIPS-197 vector', () {
      var profile = CryptoProfile(
        name: 'ecb',
        alg: 'AES/ECB/NoPadding',
        key: '2b7e151628aed2a6abf7158809cf4f3c',
        applyTo: const CryptoApply(hostPattern: 'x'),
      );
      var cipher = profile.encryptBody(_hexBytes('6bc1bee22e409f96e93d7e117393172a'));
      expect(_hex(cipher), '3ad77bb40d7a3660a89ecaf32466ef97');
      expect(_hex(profile.decryptBody(cipher)), '6bc1bee22e409f96e93d7e117393172a');
    });

    test('AES-CBC PKCS7 roundtrip through base64 body encoding', () {
      var profile = CryptoProfile(
        name: 'cbc',
        alg: 'AES/CBC/PKCS7',
        key: '30313233343536373839303132333435',
        iv: '00000000000000000000000000000000',
        encoding: 'base64',
        applyTo: const CryptoApply(hostPattern: 'x'),
      );
      var plaintext = utf8.encode('{"orderId":42,"amount":9.9}');
      var wire = profile.encryptBody(plaintext);
      // body 是 base64 文本，不是原始二进制
      expect(utf8.decode(wire), matches(RegExp(r'^[A-Za-z0-9+/=]+$')));
      expect(profile.decryptBody(wire), plaintext);
    });

    test('decrypt/encrypt honors hex body encoding', () {
      var profile = CryptoProfile(
        name: 'hex',
        alg: 'AES/ECB/PKCS7',
        key: '00112233445566778899aabbccddeeff',
        encoding: 'hex',
        applyTo: const CryptoApply(hostPattern: 'x'),
      );
      var plaintext = utf8.encode('hello 世界');
      var wire = profile.encryptBody(plaintext);
      expect(utf8.decode(wire), matches(RegExp(r'^[0-9a-f]+$')));
      expect(profile.decryptBody(wire), plaintext);
    });

    test('applyTo matches host glob, content type and header hint', () {
      var request = HttpRequest(HttpMethod.post, 'https://api.example.com/v1/order');
      request.headers.contentType = 'application/octet-stream';
      request.headers.set('X-Encrypted', '1');
      var profile = CryptoProfile(
        name: 'match',
        key: '00000000000000000000000000000000',
        applyTo: const CryptoApply(
          hostPattern: '*.example.com',
          pathPattern: '/v1/*',
          contentTypes: ['application/octet-stream'],
          headerHint: 'X-Encrypted: 1',
        ),
      );
      expect(profile.matches(request, request.headers), isTrue);

      request.headers.set('X-Encrypted', '0');
      expect(profile.matches(request, request.headers), isFalse);
    });
  });

  group('transparent decrypt + wire swap', () {
    late Directory tempDir;

    setUpAll(() async {
      tempDir = await Directory.systemTemp.createTemp('proxypin_crypto_test');
    });

    tearDownAll(() async {
      await tempDir.delete(recursive: true);
    });

    test('decrypts in memory, sends original ciphertext, restores plaintext', () async {
      var profile = CryptoProfile(
        name: 'wire',
        alg: 'AES/CBC/PKCS7',
        key: '30313233343536373839303132333435',
        iv: '00000000000000000000000000000000',
        applyTo: const CryptoApply(hostPattern: 'api.example.com', contentTypes: ['application/octet-stream']),
      );
      var file = File('${tempDir.path}/crypto_profiles.json');
      await file.writeAsString(jsonEncode({
        'version': 1,
        'profiles': [profile.toJson()]
      }));
      CryptoProfileStore.instance.fileProvider = () async => file;
      CryptoProfileStore.instance.profiles.clear();
      await CryptoProfileStore.instance.ensureLoaded();

      var plaintext = utf8.encode('{"uid":1001,"sign":"abc"}');
      var cipher = profile.encryptBody(plaintext);
      var request = HttpRequest(HttpMethod.post, 'https://api.example.com/v1/order')
        ..headers.contentType = 'application/octet-stream'
        ..body = cipher;

      await CryptoTransparent.decryptRequest(request);

      expect(request.body, plaintext);
      expect(request.attributes['cryptoAssumedPlaintext'], isNull);

      List<int>? sent;
      await CryptoTransparent.writeRequest(request, () async {
        sent = List<int>.from(request.body!);
      });

      // 未修改时发回原始密文（保持 IV/sign），而不是重新加密
      expect(sent, cipher);
      expect(request.body, plaintext);

      var edited = utf8.encode('{"uid":1002,"sign":"new"}');
      request.body = edited;
      await CryptoTransparent.writeRequest(request, () async {
        sent = List<int>.from(request.body!);
      });
      expect(sent, isNot(cipher));
      expect(profile.decryptBody(Uint8List.fromList(sent!)), edited);
      expect(request.body, edited);
    });

    test('treats undecryptable text body as plaintext for replay', () async {
      var profile = CryptoProfile(
        name: 'replay',
        alg: 'AES/ECB/PKCS7',
        key: '00112233445566778899aabbccddeeff',
        applyTo: const CryptoApply(hostPattern: 'api.example.com', contentTypes: ['application/octet-stream']),
      );
      CryptoProfileStore.instance.profiles
        ..clear()
        ..add(profile);

      var request = HttpRequest(HttpMethod.post, 'https://api.example.com/v1/order')
        ..headers.contentType = 'application/octet-stream'
        ..body = utf8.encode('{"uid":7}');
      await CryptoTransparent.decryptRequest(request);

      expect(request.body, utf8.encode('{"uid":7}'));
      expect(request.attributes['cryptoAssumedPlaintext'], isTrue);

      List<int>? sent;
      await CryptoTransparent.writeRequest(request, () async {
        sent = List<int>.from(request.body!);
      });
      expect(profile.decryptBody(Uint8List.fromList(sent!)), utf8.encode('{"uid":7}'));
    });
  });

  group('crypto detector', () {
    test('detects ECB block repetition in raw bodies', () {
      var profile = CryptoProfile(
        name: 'ecb-detect',
        alg: 'AES/ECB/NoPadding',
        key: '2b7e151628aed2a6abf7158809cf4f3c',
        applyTo: const CryptoApply(hostPattern: 'x'),
      );
      var plaintext = utf8.encode(List.filled(4, '0123456789abcdef').join());
      // NoPadding 需要 16 字节对齐
      var padded = Uint8List((plaintext.length + 15) ~/ 16 * 16)..setAll(0, plaintext);
      var flow = HttpRequest(HttpMethod.post, 'https://api.example.com/v1/order');
      flow.response = HttpResponse(HttpStatus.ok)
        ..headers.contentType = 'application/octet-stream'
        ..body = profile.encryptBody(padded);

      var result = CryptoDetector.detect([flow], host: 'api.example.com');
      expect(result['samples'], 1);
      expect(result['blockSize'], 16);
      expect(result['mode'], 'ECB');
      expect(result['encoding'], 'raw');
      expect(result['repeatedBlocks'], greaterThan(0));
      expect((result['keyCandidates'] as List), isEmpty);
      expect(result['note'], contains('Key material'));
    });

    test('returns an empty result for text-only traffic', () {
      var flow = HttpRequest(HttpMethod.post, 'https://api.example.com/v1/order');
      flow.response = HttpResponse(HttpStatus.ok)
        ..headers.contentType = 'application/json'
        ..body = utf8.encode('{"status":"ok"}');
      var result = CryptoDetector.detect([flow], host: 'api.example.com');
      expect(result['samples'], 0);
      expect(result['mode'], isNull);
    });
  });

  group('crypto tools', () {
    late Directory tempDir;
    late CryptoTools tools;

    setUpAll(() async {
      tempDir = await Directory.systemTemp.createTemp('proxypin_crypto_tools');
      CryptoProfileStore.instance.fileProvider =
          () async => File('${tempDir.path}/crypto_profiles.json');
    });

    tearDownAll(() async {
      await tempDir.delete(recursive: true);
    });

    test('register / list / apply off / remove', () async {
      tools = CryptoTools(FlowStore());
      var byName = {for (var tool in tools.tools()) tool.name: tool};
      expect(byName.keys, containsAll(['register_crypto_profile', 'list_crypto_profiles', 'apply_crypto_profile',
        'remove_crypto_profile', 'detect_crypto_profile']));

      var registered = await byName['register_crypto_profile']!.handler({
        'name': 'tool-profile',
        'alg': 'AES/ECB/PKCS7',
        'keyHex': '00112233445566778899aabbccddeeff',
        'applyTo': {'hostPattern': 'api.example.com', 'contentTypes': ['application/octet-stream']},
      }) as Map;
      expect(registered['registered'], isTrue);
      expect((registered['profile'] as Map)['keyBytes'], 16);

      var listed = await byName['list_crypto_profiles']!.handler({}) as Map;
      expect((listed['profiles'] as List).any((p) => (p as Map)['name'] == 'tool-profile'), isTrue);
      expect(jsonEncode(listed).contains('00112233'), isFalse);

      var disabled = await byName['apply_crypto_profile']!
          .handler({'name': 'tool-profile', 'mode': 'off'}) as Map;
      expect(disabled['enabled'], isFalse);

      var removed = await byName['remove_crypto_profile']!.handler({'name': 'tool-profile'}) as Map;
      expect(removed['removed'], isTrue);
    });

    test('rejects a profile without any match scope', () async {
      var register = CryptoTools(FlowStore()).tools().firstWhere((t) => t.name == 'register_crypto_profile');
      await expectLater(
        register.handler({
          'name': 'too-broad',
          'alg': 'AES/ECB/PKCS7',
          'keyHex': '00000000000000000000000000000000',
        }),
        throwsA(predicate((e) => '$e'.contains('applyTo'))),
      );
    });
  });

  group('context bridge crypto', () {
    test('hash and HMAC-SHA256 match known vectors', () {
      expect(ContextBridge.handle({'op': 'hash', 'algo': 'SHA-256', 'data': 'abc'}),
          'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');

      var key = List<int>.filled(20, 0x0b);
      expect(
        ContextBridge.handle({'op': 'hmac', 'algo': 'SHA-256', 'key': key, 'data': 'Hi There'}),
        'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7',
      );
    });

    test('AES helpers roundtrip through hex and base64', () {
      var encrypted = ContextBridge.handle({
        'op': 'aesEncrypt',
        'data': 'secret payload',
        'key': '00112233445566778899aabbccddeeff',
        'keyEncoding': 'hex',
        'mode': 'ECB',
        'padding': 'PKCS7',
        'out': 'base64',
      }) as String;
      var decrypted = ContextBridge.handle({
        'op': 'aesDecrypt',
        'data': encrypted,
        'in': 'base64',
        'key': '00112233445566778899aabbccddeeff',
        'keyEncoding': 'hex',
        'mode': 'ECB',
        'padding': 'PKCS7',
        'out': 'utf8',
      });
      expect(decrypted, 'secret payload');
    });

    test('rejects unsupported mode instead of silently using ECB', () {
      expect(
        () => ContextBridge.handle({
          'op': 'aesEncrypt',
          'data': 'x',
          'key': '00' * 16,
          'keyEncoding': 'hex',
          'mode': 'GCM',
        }),
        throwsA(predicate((e) => '$e'.contains('unsupported AES mode'))),
      );
    });

    test('rsaSign produces a signature that rsaVerify accepts', () {
      // 512-bit 仅用于单测速度；生产应使用 >=2048 位
      var pair = CryptoUtilsTestKeys.generate();
      var signature = ContextBridge.handle({
        'op': 'rsaSign',
        'data': 'payload',
        'key': pair.privatePem,
        'algo': 'SHA-256',
      }) as String;
      expect(
        ContextBridge.handle({
          'op': 'rsaVerify',
          'data': 'payload',
          'key': pair.publicPem,
          'signature': signature,
          'algo': 'SHA-256',
        }),
        isTrue,
      );
      expect(
        ContextBridge.handle({
          'op': 'rsaVerify',
          'data': 'payload2',
          'key': pair.publicPem,
          'signature': signature,
          'algo': 'SHA-256',
        }),
        isFalse,
      );
    });
  });

  group('websocket control', () {
    test('frame encoder roundtrips payloads across all length encodings', () {
      for (var size in [0, 5, 125, 126, 65535, 65536]) {
        for (var mask in [false, true]) {
          var payload = Uint8List.fromList(List.generate(size, (i) => i & 0xff));
          var encoded = WebSocketControl.encodeFrame(opcode: 2, payload: payload, mask: mask, fin: true);
          var frame = WebSocketDecoder().decode(encoded);
          expect(frame, isNotNull, reason: 'size=$size mask=$mask');
          expect(frame!.payloadData, payload, reason: 'size=$size mask=$mask');
          expect(frame.mask, mask);
          expect(frame.opcode, 2);
        }
      }
    });

    test('rewrites text frames with regex groups and respects direction', () {
      var control = WebSocketControl.instance;
      control.setRules('flow-1', [
        WsRewriteRule(match: r'order=(\d+)', replace: r'order=9$1', direction: 'c2s'),
      ]);
      var frame = WebSocketFrame(
        fin: true,
        opcode: 1,
        mask: true,
        maskingKey: 0,
        payloadLength: 0,
        payloadData: Uint8List.fromList(utf8.encode('order=42')),
      );
      var clientFrame = control.rewrite(frame, 'flow-1', toClient: false);
      expect(clientFrame, isNotNull);
      var decoded = WebSocketDecoder().decode(clientFrame!)!;
      expect(utf8.decode(decoded.payloadData), 'order=942');
      expect(decoded.mask, isTrue);

      // s2c 规则不命中 c2s 帧
      expect(control.rewrite(frame, 'flow-1', toClient: true), isNull);

      control.setRules('flow-1', const []);
      expect(control.rewrite(frame, 'flow-1', toClient: false), isNull);
    });

    test('leaves binary frames untouched', () {
      var control = WebSocketControl.instance;
      control.setRules('flow-2', [WsRewriteRule(match: 'a', replace: 'b')]);
      var frame = WebSocketFrame(
        fin: true,
        opcode: 2,
        mask: false,
        maskingKey: 0,
        payloadLength: 0,
        payloadData: Uint8List.fromList([1, 2, 3]),
      );
      expect(control.rewrite(frame, 'flow-2', toClient: false), isNull);
      control.setRules('flow-2', const []);
    });
  });
}

class CryptoUtilsTestKeys {
  final String privatePem;
  final String publicPem;

  CryptoUtilsTestKeys(this.privatePem, this.publicPem);

  static CryptoUtilsTestKeys generate() {
    var pair = CryptoUtils.generateRSAKeyPair(keySize: 1024);
    var privateKey = pair.privateKey as RSAPrivateKey;
    var publicKey = pair.publicKey as RSAPublicKey;
    return CryptoUtilsTestKeys(
      CryptoUtils.encodeRSAPrivateKeyToPemPkcs1(privateKey),
      CryptoUtils.encodeRSAPublicKeyToPem(publicKey),
    );
  }
}
