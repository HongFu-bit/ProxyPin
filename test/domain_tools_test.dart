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
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:proxypin/mcp/capture/flow_store.dart';
import 'package:proxypin/mcp/extra/domain_tools.dart';
import 'package:proxypin/mcp/protocol/mcp_server.dart';
import 'package:proxypin/mcp/protocol/mcp_tool.dart';
import 'package:proxypin/network/channel/host_port.dart';
import 'package:proxypin/network/http/http.dart';
import 'package:proxypin/network/util/crypto.dart';

String md5Hex(String input) => CryptoUtils.getHashPlain(
      Uint8List.fromList(utf8.encode(input)),
      algorithmName: 'MD5',
    ).map((b) => b.toRadixString(16).padLeft(2, '0')).join();

HttpRequest makeRequest(
  String method,
  String path, {
  Map<String, String>? query,
  Map<String, dynamic>? json,
  String host = 'https://api.example.com',
  int secondsAgo = 0,
}) {
  var queryString = query == null || query.isEmpty ? '' : '?${Uri(queryParameters: query).query}';
  var request = HttpRequest(HttpMethod.valueOf(method), '$path$queryString');
  request.hostAndPort = HostAndPort.of(host);
  request.requestTime = DateTime.now().subtract(Duration(seconds: secondsAgo));
  if (json != null) {
    request.headers.set('Content-Type', 'application/json');
    var bytes = utf8.encode(jsonEncode(json));
    request.body = bytes;
    request.headers.contentLength = bytes.length;
  }
  return request;
}

void main() {
  group('domain tool generation', () {
    test('groups endpoints, normalizes ids and derives parameters', () async {
      var flows = [
        makeRequest('POST', '/api/v1/user/123/info', query: {'lang': 'en'}, json: {
          'name': 'alice',
          'age': 20,
          'token': 'secret-token',
        }),
        makeRequest('POST', '/api/v1/user/456/info', query: {'lang': 'zh'}, json: {
          'name': 'bob',
          'age': 31,
          'token': 'other-token',
        }, secondsAgo: 5),
      ];

      var result = await DomainToolGenerator.build(flows, host: 'api.example.com', registerAs: 'app');
      expect(result.tools, hasLength(1));
      expect(result.tools.single.name, 'app_user_by_id_info');
      expect(result.endpoints.single['path'], '/api/v1/user/{id}/info');

      var params = (result.endpoints.single['params'] as List).cast<Map>();
      var byName = {for (var p in params) p['name']: p};
      expect(byName['id']?['in'], 'path');
      expect(byName['id']?['required'], true);
      expect(byName['lang']?['in'], 'query');
      expect(byName['name']?['in'], 'body');
      expect(byName['age']?['type'], 'integer');

      var schema = result.tools.single.inputSchema;
      var properties = schema['properties'] as Map;
      expect(schema['required'], contains('id'));
      expect(properties['token'], isNot(containsPair('default', anything)));
      expect((properties['token'] as Map)['description'], contains('redacted'));
      expect(properties['lang'], containsPair('default', 'en'));
    });

    test('duplicate slugs get distinct names and methods can be filtered', () async {
      var flows = [
        makeRequest('GET', '/api/order/list'),
        makeRequest('POST', '/api/order/list'),
        makeRequest('DELETE', '/api/order/list'),
      ];
      var result = await DomainToolGenerator.build(flows, host: 'api.example.com', registerAs: 'shop');
      expect(result.tools.map((t) => t.name).toSet(), hasLength(3));
      expect(result.tools.map((t) => t.name), everyElement(startsWith('shop_order_list')));

      var filtered = await DomainToolGenerator.build(
        flows,
        host: 'api.example.com',
        registerAs: 'shop',
        methods: {'POST'},
      );
      expect(filtered.tools, hasLength(1));
      expect(filtered.endpoints.single['method'], 'POST');
    });

    test('skips websocket and CONNECT flows', () async {
      var connect = HttpRequest(HttpMethod.connect, 'api.example.com:443');
      connect.hostAndPort = HostAndPort.of('https://api.example.com');
      var socket = makeRequest('GET', '/socket');
      socket.headers.set('Upgrade', 'websocket');
      var normal = makeRequest('GET', '/api/ping');

      var result = await DomainToolGenerator.build([connect, socket, normal], host: 'api.example.com');
      expect(result.tools, hasLength(1));
      expect(result.endpoints.single['path'], '/api/ping');
    });
  });

  group('signature profile', () {
    test('auto infers MD5(sorted-pairs) and recomputes it after overrides', () async {
      String signFor(String user, String nonce) => md5Hex('nonce=$nonce&user=$user');
      var flows = [
        makeRequest('POST', '/api/login', json: {
          'user': 'alice',
          'nonce': '1',
          'sign': signFor('alice', '1'),
        }),
        makeRequest('POST', '/api/login', json: {
          'user': 'bob',
          'nonce': '2',
          'sign': signFor('bob', '2'),
        }, secondsAgo: 3),
      ];

      var result = await DomainToolGenerator.build(
        flows,
        host: 'api.example.com',
        registerAs: 'auth',
        signatureProfile: 'auto',
      );
      expect(result.endpoints.single['signature']?['field'], 'sign');
      expect(result.endpoints.single['signature']?['algorithm'], 'MD5');
      expect(result.endpoints.single['signature']?['input'], 'sorted-pairs');

      var prepared = DomainToolGenerator.prepareForTest(
        flows,
        host: 'api.example.com',
        signatureProfile: 'auto',
        args: {'user': 'carol', 'nonce': '9'},
      );
      var body = jsonDecode(prepared['body'] as String) as Map;
      expect(body['user'], 'carol');
      expect(body['nonce'], '9');
      expect(body['sign'], signFor('carol', '9'));
      expect(prepared['url'], endsWith('/api/login'));
    });

    test('query signatures are replaced in place', () {
      var flows = [
        makeRequest('GET', '/api/data', query: {
          'id': '1',
          'nonce': '2',
          'sign': md5Hex('id=1&nonce=2'),
        }),
        makeRequest('GET', '/api/data', query: {
          'id': '1',
          'nonce': '3',
          'sign': md5Hex('id=1&nonce=3'),
        }, secondsAgo: 2),
      ];

      var prepared = DomainToolGenerator.prepareForTest(
        flows,
        host: 'api.example.com',
        signatureProfile: 'auto',
        args: {'nonce': '7'},
      );
      var url = Uri.parse(prepared['url'] as String);
      expect(url.queryParameters['sign'], md5Hex('id=1&nonce=7'));
      expect(prepared['signature']?['field'], 'sign');
    });

    test('unsupported explicit recipe is reported and ignored', () async {
      var result = await DomainToolGenerator.build(
        [makeRequest('POST', '/api/ping', json: {'a': 1})],
        host: 'api.example.com',
        signatureProfile: {'field': 'sign', 'algorithm': 'SHA-256', 'input': 'nope'},
      );
      expect(result.endpoints.single.containsKey('signature'), isFalse);
      expect(result.warnings.any((w) => w.contains('unsupported signatureProfile.input')), isTrue);
    });

    test('"none" disables signature handling', () async {
      var result = await DomainToolGenerator.build(
        [
          makeRequest('POST', '/api/ping', json: {'sign': md5Hex('a=1'), 'a': '1'}),
          makeRequest('POST', '/api/ping', json: {'sign': md5Hex('a=2'), 'a': '2'}, secondsAgo: 1),
        ],
        host: 'api.example.com',
        signatureProfile: 'none',
      );
      expect(result.endpoints.single.containsKey('signature'), isFalse);
    });
  });

  group('dynamic registration', () {
    test('registers tools, lists them and replaces only its own set', () async {
      var store = FlowStore();
      var server = McpServer(store: store, redactEnabled: () => true);
      var flows = [makeRequest('GET', '/api/user/1')];

      var first = await DomainToolGenerator.build(flows, host: 'api.example.com', registerAs: 'app');
      expect(server.registerTools(first.tools), first.tools.length);

      var list = await server.handle({'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list'});
      var names = ((list!['result'] as Map)['tools'] as List).map((t) => (t as Map)['name']).toSet();
      expect(names, contains('app_user_by_id'));

      var second = await DomainToolGenerator.build(
        [makeRequest('GET', '/api/item/1')],
        host: 'api.example.com',
        registerAs: 'app',
      );
      expect(server.removeDynamicTools((t) => first.tools.map((e) => e.name).contains(t.name)), 1);
      expect(server.registerTools(second.tools), 1);

      list = await server.handle({'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list'});
      names = ((list!['result'] as Map)['tools'] as List).map((t) => (t as Map)['name']).toSet();
      expect(names, contains('app_item_by_id'));
      expect(names, isNot(contains('app_user_by_id')));
    });

    test('refuses to shadow a built-in tool', () {
      var store = FlowStore();
      var server = McpServer(store: store, redactEnabled: () => true);
      var duplicate = McpTool(
        name: 'list_flows',
        description: 'shadow',
        inputSchema: const {},
        handler: (_) async => null,
      );
      expect(() => server.registerTools([duplicate]), throwsArgumentError);
    });
  });
}
