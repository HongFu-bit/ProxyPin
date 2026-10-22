import 'dart:async';
import 'dart:convert';
import 'dart:io' as io;
import 'dart:typed_data';

import 'package:archive/archive_io.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:proxypin/mcp/capture/flow_store.dart';
import 'package:proxypin/mcp/extra/apk_string_locator.dart';
import 'package:proxypin/mcp/capture/flow_view.dart';
import 'package:proxypin/mcp/extra/active_runner.dart';
import 'package:proxypin/mcp/extra/active_tools.dart';
import 'package:proxypin/mcp/extra/audit_log.dart';
import 'package:proxypin/mcp/extra/codec_detector.dart';
import 'package:proxypin/mcp/extra/contract_generator.dart';
import 'package:proxypin/mcp/extra/extra_tools.dart';
import 'package:proxypin/mcp/extra/field_flow_tracker.dart';
import 'package:proxypin/mcp/extra/flow_broadcaster.dart';
import 'package:proxypin/mcp/extra/intercept_queue.dart';
import 'package:proxypin/mcp/extra/offline_mock.dart';
import 'package:proxypin/mcp/extra/protobuf_decoder.dart';
import 'package:proxypin/mcp/extra/signature_analyzer.dart';
import 'package:proxypin/mcp/protocol/mcp_server.dart';
import 'package:proxypin/mcp/transport/mcp_http_server.dart';
import 'package:proxypin/network/http/http.dart';
import 'package:proxypin/network/util/crypto.dart';

String hex(List<int> bytes) => bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

List<int> varintBytes(int value) {
  var result = <int>[];
  var current = value;
  do {
    var byte = current & 0x7f;
    current >>= 7;
    result.add(current > 0 ? byte | 0x80 : byte);
  } while (current > 0);
  return result;
}

/// field 1 varint 150, field 2 string "hi", field 3 nested { field 1 varint 7 }
List<int> protoSample() => [
      ...varintBytes(1 << 3), ...varintBytes(150),
      ...varintBytes(2 << 3 | 2), 2, 0x68, 0x69,
      ...varintBytes(3 << 3 | 2), 2, ...varintBytes(1 << 3), 7,
    ];

List<int> grpcFrame(List<int> payload, {int flag = 0}) => [
      flag,
      (payload.length >> 24) & 0xff,
      (payload.length >> 16) & 0xff,
      (payload.length >> 8) & 0xff,
      payload.length & 0xff,
      ...payload,
    ];

void main() {
  test('codec detector recognizes jwt / base64 / hex / urlencoded', () {
    var header = base64Url.encode(utf8.encode('{"alg":"HS256"}')).replaceAll('=', '');
    var payload = base64Url.encode(utf8.encode('{"uid":123,"name":"a"}')).replaceAll('=', '');
    var jwt = '$header.$payload.signature';
    expect(CodecDetector.detect(jwt).any((e) => e['codec'] == 'jwt'), isTrue);

    var b64 = base64.encode(utf8.encode('{"hello":"world"}'));
    expect(CodecDetector.detect(b64).any((e) => e['codec'] == 'base64'), isTrue);

    var hexBody = utf8.encode('secret-data').map((b) => b.toRadixString(16).padLeft(2, '0')).join();
    expect(CodecDetector.detect(hexBody).any((e) => e['codec'] == 'hex'), isTrue);

    expect(CodecDetector.detect('a=1%20b&c=%7B%7D').any((e) => e['codec'] == 'urlencoded'), isTrue);

    // 普通文本不应被误判
    expect(CodecDetector.detect('hello world from proxypin'), isEmpty);
  });

  test('flow detail attaches decoded candidates without changing body text', () async {
    var encoded = base64.encode(utf8.encode('{"uid":123}'));
    var request = HttpRequest(HttpMethod.get, 'https://api.example.com/v1/me');
    var response = HttpResponse(HttpStatus.ok);
    response.headers.set('Content-Type', 'text/plain');
    response.body = utf8.encode(encoded);
    response.request = request;
    request.response = response;

    var detail = await FlowView.detail(request);
    var body = detail['response']['body'] as Map;
    expect(body['text'], encoded);
    var decoded = body['decoded'] as List;
    expect(decoded.any((e) => e['codec'] == 'base64'), isTrue);
  });

  test('signature analyzer flags and matches md5 over sorted params', () {
    var flows = <HttpRequest>[];
    for (var i = 0; i < 3; i++) {
      var params = {
        'appId': 'abc',
        'timestamp': '$i',
        'price': '9.9',
        'nonce': 'n$i',
      };
      var sorted = params.keys.toList()..sort();
      var canonical = sorted.map((k) => '$k=${params[k]}').join('&');
      var sign = hex(
          CryptoUtils.getHashPlain(Uint8List.fromList(utf8.encode(canonical)), algorithmName: 'MD5'));

      var request = HttpRequest(HttpMethod.post, 'https://api.example.com/v1/order?appId=abc');
      request.headers.set('Content-Type', 'application/json');
      request.body = utf8.encode(jsonEncode({...params, 'sign': sign}));
      flows.add(request);
    }

    var result = SignatureAnalyzer.analyze(flows);
    expect(result['samples'], 3);
    expect((result['signatureCandidates'] as List).any((e) => e['field'] == 'sign'), isTrue);
    var brute = result['bruteForce'] as Map;
    expect(brute['matched'], isNotNull);
    expect((brute['matched'] as Map)['algorithm'], 'MD5');
  });

  test('intercept queue exposes pending item and resolves once', () async {
    InterceptQueue.instance.clear();
    var request = HttpRequest(HttpMethod.get, 'https://example.com/a');
    request.body = utf8.encode('{"a":1}');

    var item = InterceptQueue.instance.enqueueRequest(request.requestId, request);
    expect(InterceptQueue.instance.count, 1);

    var snapshot = await item.toJson();
    expect(snapshot['phase'], 'request');
    expect(snapshot['url'], 'https://example.com/a');

    var resolved = InterceptQueue.instance.resolve(
        item.id, const InterceptDecision(action: 'continue', headers: {'X-Test': '1'}));
    expect(resolved, isTrue);
    expect(InterceptQueue.instance.count, 0);

    var decision = await item.future;
    expect(decision.headers!['X-Test'], '1');

    // 第二次处置必须失败（already_resolved 语义）
    expect(InterceptQueue.instance.resolve(item.id, const InterceptDecision()), isFalse);
  });

  test('contract generator normalizes ids and marks required fields', () {
    var flows = <HttpRequest>[];
    for (var i = 1; i <= 2; i++) {
      var request = HttpRequest(HttpMethod.post, 'https://api.example.com/v1/order/$i?appId=abc');
      request.headers.set('Content-Type', 'application/json');
      request.body = utf8.encode(jsonEncode({'itemId': i, 'count': 2, 'note': 'n$i'}));
      var response = HttpResponse(HttpStatus.ok);
      response.headers.set('Content-Type', 'application/json');
      response.body = utf8.encode(jsonEncode({'ok': true, 'orderId': 'A$i'}));
      request.response = response;
      flows.add(request);
    }

    var result = ContractGenerator.generate(flows, host: 'api.example.com', minSamples: 2);
    var paths = (result['contract'] as Map)['paths'] as Map;
    var operation = (paths['/v1/order/{id}'] as Map)['post'] as Map;
    var schema = ((operation['requestBody'] as Map)['content'] as Map)['application/json']['schema']
        as Map;
    var properties = schema['properties'] as Map;
    expect((properties['itemId'] as Map)['type'], 'integer');
    expect(schema['required'] as List, containsAll(['itemId', 'count', 'note']));

    var parameters = operation['parameters'] as List;
    expect(parameters.any((p) => (p as Map)['name'] == 'appId' && p['in'] == 'query'), isTrue);
  });

  test('field flow tracker links a response token to a later request header', () {
    var login = HttpRequest(HttpMethod.post, 'https://api.example.com/login');
    login.requestTime = DateTime.utc(2026, 1, 1, 10, 0, 0);
    var loginResponse = HttpResponse(HttpStatus.ok);
    loginResponse.headers.set('Content-Type', 'application/json');
    loginResponse.body = utf8.encode(jsonEncode({
      'data': {'token': 'abcdef1234567890'}
    }));
    login.response = loginResponse;

    var me = HttpRequest(HttpMethod.get, 'https://api.example.com/me');
    me.requestTime = DateTime.utc(2026, 1, 1, 10, 0, 1);
    me.headers.set('Authorization', 'Bearer abcdef1234567890');
    var meResponse = HttpResponse(HttpStatus.ok);
    meResponse.body = utf8.encode('{}');
    me.response = meResponse;

    // 故意乱序传入，tracker 内部应按 requestTime 排序
    var result = FieldFlowTracker.trace([me, login]);
    var edges = result['edges'] as List;
    expect(edges, isNotEmpty);
    var authEdge = edges.firstWhere(
        (edge) => ((edge as Map)['to'] as String).toLowerCase().contains('authorization'));
    expect((authEdge as Map)['confidence'] as num, greaterThan(0.5));
    expect(result['identitySeeds'] as List, isNotEmpty);
    expect(result['entryPoints'] as List, contains(login.requestId));
  });

  test('request mutator replaces query, json, form and header values', () {
    var query = HttpRequest(HttpMethod.get, 'https://api.example.com/v1/items?itemId=1&x=2');
    var mq = RequestMutator.apply(query, 'itemId', '99');
    expect(mq, isNotNull);
    expect(mq!.location, 'query');
    expect(mq.request.requestUri!.queryParameters['itemId'], '99');
    expect(mq.request.requestUri!.queryParameters['x'], '2');

    var json = HttpRequest(HttpMethod.post, 'https://api.example.com/v1/order');
    json.headers.set('Content-Type', 'application/json');
    json.body = utf8.encode(jsonEncode({'itemId': 1, 'nested': {'count': 2}}));
    var mj = RequestMutator.apply(json, 'nested.count', '7');
    expect(mj!.location, 'json');
    expect(mj.request.getBodyString(), contains('"count":7'));

    var form = HttpRequest(HttpMethod.post, 'https://api.example.com/login');
    form.headers.set('Content-Type', 'application/x-www-form-urlencoded');
    form.body = utf8.encode('user=a&token=abc');
    var mf = RequestMutator.apply(form, 'token', 'x y');
    expect(mf!.location, 'form');
    expect(mf.request.getBodyString(), 'user=a&token=x+y');

    var header = HttpRequest(HttpMethod.get, 'https://api.example.com/me');
    header.headers.set('X-User', '12');
    var mh = RequestMutator.apply(header, 'x-user', '13');
    expect(mh!.location, 'header');
    expect(mh.request.headers.get('X-User'), '13');

    expect(RequestMutator.apply(json, 'missing', '1'), isNull);
  });

  test('race stats flag status deviations and mark large skew inconclusive', () {
    var results = [
      const ActiveResult(status: 200, size: 100, elapsedMs: 5, preview: ''),
      const ActiveResult(status: 200, size: 100, elapsedMs: 5, preview: ''),
      const ActiveResult(status: 409, size: 20, elapsedMs: 5, preview: ''),
    ];

    var summary = ResponseStats.summarize(results, skewMs: 3, maxSkewMs: 20);
    expect(summary['verdict'], 'suspect');
    expect((summary['anomalies'] as List).length, 1);
    var distribution = summary['statusDistribution'] as Map;
    expect(distribution['200'], 2);
    expect(distribution['409'], 1);

    var skewed = ResponseStats.summarize(results, skewMs: 100, maxSkewMs: 20);
    expect(skewed['verdict'], 'inconclusive');
  });

  test('active tools send loopback traffic and compare responses', () async {
    var server = await io.HttpServer.bind(io.InternetAddress.loopbackIPv4, 0);
    server.listen((request) {
      var id = request.uri.queryParameters['id'] ?? '0';
      request.response.headers.contentType = io.ContentType.json;
      request.response.write(jsonEncode({'id': id, 'padding': 'x' * 20}));
      request.response.close();
    });

    var flow = HttpRequest(HttpMethod.get, 'http://127.0.0.1:${server.port}/race?id=1');
    var store = FlowStore()..backfill([flow]);
    var tools = McpActiveTools(store: store).tools();

    var race = tools.firstWhere((tool) => tool.name == 'race_replay');
    var raceResult =
        await race.handler({'id': flow.requestId, 'copies': 4, 'max_skew_ms': 200}) as Map;
    expect((raceResult['statusDistribution'] as Map)['200'], 4);
    expect(raceResult['verdict'], 'uniform');

    var fuzz = tools.firstWhere((tool) => tool.name == 'fuzz_flow');
    var fuzzResult = await fuzz.handler({
      'id': flow.requestId,
      'param': 'id',
      'payloads': ['2', 'abcdefghij'],
      'max_qps': 20,
    }) as Map;
    var results = fuzzResult['results'] as List;
    expect(results.length, 2);
    expect((results[1] as Map)['size'] as int, greaterThan((results[0] as Map)['size'] as int));
    expect((results[0] as Map)['location'], 'query');

    await server.close(force: true);
  });

  test('offline mock builder keeps the newest response per endpoint', () async {
    var old = HttpRequest(HttpMethod.get, 'https://api.example.com/v1/user?x=1');
    old.requestTime = DateTime.utc(2026, 1, 1, 10);
    var oldResponse = HttpResponse(HttpStatus.ok);
    oldResponse.headers.set('Content-Type', 'application/json');
    oldResponse.headers.set('Content-Length', '2');
    oldResponse.body = utf8.encode('{}');
    old.response = oldResponse;

    var fresh = HttpRequest(HttpMethod.get, 'https://api.example.com/v1/user');
    fresh.requestTime = DateTime.utc(2026, 1, 1, 11);
    var freshResponse = HttpResponse(HttpStatus.ok);
    freshResponse.headers.set('Content-Type', 'application/json');
    freshResponse.body = utf8.encode('{"name":"a"}');
    fresh.response = freshResponse;

    var failed = HttpRequest(HttpMethod.post, 'https://api.example.com/v1/user');
    failed.requestTime = DateTime.utc(2026, 1, 1, 12);
    var failedResponse = HttpResponse(HttpStatus.valueOf(500));
    failedResponse.body = utf8.encode('boom');
    failed.response = failedResponse;

    var noResponse = HttpRequest(HttpMethod.get, 'https://api.example.com/v1/ping');

    var result = await OfflineMockBuilder.build([old, fresh, failed, noResponse]);
    expect(result.skippedNoResponse, 1);
    expect(result.skippedErrors, 1);
    expect(result.rules.length, 1);
    var rule = result.rules.first;
    expect(rule.body, '{"name":"a"}');
    expect(rule.pattern, 'https://api.example.com/v1/user*');
    expect(rule.headers.containsKey('Content-Length'), isFalse);

    var withErrors = await OfflineMockBuilder.build([old, fresh, failed, noResponse], includeErrors: true);
    expect(withErrors.rules.length, 2);
  });

  test('flow broadcaster emits started/completed events', () async {
    var received = <Map<String, dynamic>>[];
    var subscription = FlowBroadcaster.instance.stream.listen(received.add);

    var flow = HttpRequest(HttpMethod.get, 'https://api.example.com/a');
    FlowBroadcaster.instance.publishRequest(flow);
    var response = HttpResponse(HttpStatus.ok);
    response.body = utf8.encode('abc');
    response.request = flow;
    FlowBroadcaster.instance.publishResponse(response);

    expect(received.map((event) => event['event']), containsAll(['flow_started', 'flow_completed']));
    var completed = received.firstWhere((event) => event['event'] == 'flow_completed');
    expect(completed['status'], 200);
    expect(completed['size'], 3);
    await subscription.cancel();
  });

  test('GET /mcp/events streams filtered flow events', () async {
    var server = McpHttpServer(
      mcp: McpServer(store: FlowStore(), redactEnabled: () => true),
      address: io.InternetAddress.loopbackIPv4,
    );
    await server.start(0);
    var client = io.HttpClient();
    try {
      var request =
          await client.getUrl(Uri.parse('http://127.0.0.1:${server.port}/mcp/events?host=api.example.com'));
      var response = await request.close();
      expect(response.statusCode, 200);
      expect(response.headers.contentType?.mimeType, 'text/event-stream');

      var events = <String>[];
      var finished = Completer<void>();
      var lines = response.transform(utf8.decoder).transform(const LineSplitter());
      var subscription = lines.listen((line) {
        if (line.startsWith('event: ')) events.add(line.substring(7));
        if (events.contains('flow_completed') && !finished.isCompleted) finished.complete();
      });

      await Future<void>.delayed(const Duration(milliseconds: 50));
      var flow = HttpRequest(HttpMethod.get, 'https://api.example.com/v1/orders');
      FlowBroadcaster.instance.publishRequest(flow);
      var flowResponse = HttpResponse(HttpStatus.ok);
      flowResponse.body = utf8.encode('ok');
      flowResponse.request = flow;
      FlowBroadcaster.instance.publishResponse(flowResponse);

      await finished.future.timeout(const Duration(seconds: 3));
      expect(events, contains('flow_started'));
      expect(events, contains('flow_completed'));
      await subscription.cancel();
    } finally {
      client.close(force: true);
      await server.stop();
    }
  });

  test('audit log redacts credentials and stops writing when disabled', () async {
    var dir = await io.Directory.systemTemp.createTemp('proxypin_audit_');
    try {
      var file = io.File('${dir.path}/mcp_audit.jsonl');
      var enabled = true;
      var log = AuditLog(enabled: () => enabled, fileProvider: () async => file);

      await log.record(
        tool: 'send_request',
        arguments: {
          'url': 'https://api.example.com/login',
          'headers': {'Authorization': 'Bearer super-secret', 'Cookie': 'sid=abc'},
          'nested': {'token': 'tok', 'count': 2},
          'body': 'x' * 600,
        },
        client: '127.0.0.1',
        userAgent: 'claude-code/1.0',
        elapsed: const Duration(milliseconds: 12),
        ok: true,
      );

      enabled = false;
      await log.record(
        tool: 'ignored_tool',
        arguments: const {'password': 'p'},
        client: '127.0.0.1',
        elapsed: Duration.zero,
        ok: true,
      );

      var entries = await log.read();
      expect(entries.length, 1);
      var entry = entries.first;
      expect(entry['tool'], 'send_request');
      expect(entry['ok'], isTrue);
      expect(entry['client'], '127.0.0.1');
      expect(entry['elapsedMs'], 12);
      var args = entry['args'] as Map;
      expect((args['headers'] as Map)['Authorization'], '<redacted>');
      expect((args['headers'] as Map)['Cookie'], '<redacted>');
      expect((args['nested'] as Map)['token'], '<redacted>');
      expect((args['nested'] as Map)['count'], 2);
      expect((args['body'] as String).length, lessThanOrEqualTo(600 + 32));
      expect(entry.toString(), isNot(contains('super-secret')));
    } finally {
      await dir.delete(recursive: true);
    }
  });

  test('audit log trims the oldest entries to stay under maxBytes', () async {
    var dir = await io.Directory.systemTemp.createTemp('proxypin_audit_ring_');
    try {
      var file = io.File('${dir.path}/mcp_audit.jsonl');
      var log = AuditLog(enabled: () => true, fileProvider: () async => file, maxBytes: 2048);
      for (var i = 0; i < 80; i++) {
        await log.record(
          tool: 'tool_$i',
          arguments: {'payload': 'p' * 60},
          client: '127.0.0.1',
          elapsed: const Duration(milliseconds: 1),
          ok: true,
        );
      }
      expect(await file.length(), lessThanOrEqualTo(2048));
      var entries = await log.read(limit: 500);
      expect(entries.length, lessThan(80));
      expect(entries.last['tool'], 'tool_79');
      expect(entries.any((e) => e['tool'] == 'tool_0'), isFalse);
    } finally {
      await dir.delete(recursive: true);
    }
  });

  test('MCP HTTP transport audits tools/call with client ip and error state', () async {
    var dir = await io.Directory.systemTemp.createTemp('proxypin_audit_http_');
    try {
      var file = io.File('${dir.path}/mcp_audit.jsonl');
      var audit = AuditLog(enabled: () => true, fileProvider: () async => file);
      var server = McpHttpServer(
        mcp: McpServer(store: FlowStore(), redactEnabled: () => true),
        address: io.InternetAddress.loopbackIPv4,
        audit: audit,
      );
      await server.start(0);
      var client = io.HttpClient();
      try {
        Future<void> call(String tool, Map<String, dynamic> args) async {
          var request = await client.postUrl(Uri.parse('http://127.0.0.1:${server.port}/mcp'));
          request.headers.contentType = io.ContentType.json;
          request.write(jsonEncode({
            'jsonrpc': '2.0',
            'id': 1,
            'method': 'tools/call',
            'params': {'name': tool, 'arguments': args},
          }));
          var response = await request.close();
          await response.drain<void>();
        }

        await call('get_proxy_status', {});
        await call('no_such_tool', {'token': 'secret-value'});

        var entries = await audit.read();
        expect(entries.length, 2);
        expect(entries[0]['tool'], 'get_proxy_status');
        expect(entries[0]['ok'], isTrue);
        expect(entries[0]['client'], '127.0.0.1');
        expect(entries[1]['tool'], 'no_such_tool');
        expect(entries[1]['ok'], isFalse);
        expect(entries[1]['error'], isNotNull);
        expect((entries[1]['args'] as Map)['token'], '<redacted>');
      } finally {
        client.close(force: true);
        await server.stop();
      }
    } finally {
      await dir.delete(recursive: true);
    }
  });

  test('protobuf decoder walks varint, string and nested message fields', () {
    var decoded = ProtobufDecoder.decode(Uint8List.fromList(protoSample()));
    expect(decoded['format'], 'protobuf');
    var fields = decoded['fields'] as List;
    expect(fields.length, 3);
    expect(fields[0]['number'], 1);
    expect(fields[0]['wireType'], 0);
    expect(fields[0]['value'], 150);
    expect(fields[1]['type'], 'string');
    expect(fields[1]['value'], 'hi');
    expect(fields[2]['type'], 'message');
    var nested = (fields[2]['fields'] as List).first as Map;
    expect(nested['number'], 1);
    expect(nested['value'], 7);
    expect(decoded['parseError'], isNull);
  });

  test('protobuf decoder reports truncated length-delimited fields', () {
    var truncated = Uint8List.fromList([0x12, 0x05, 0x61]);
    var decoded = ProtobufDecoder.decode(truncated);
    expect(decoded['parseError'], contains('truncated bytes'));
    expect((decoded['fields'] as List), isEmpty);
  });

  test('grpc decoder reads multiple frames and gzip-compressed payloads', () {
    var frames = [
      ...grpcFrame(protoSample()),
      ...grpcFrame(protoSample()),
    ];
    var decoded = ProtobufDecoder.decodeBody(
      Uint8List.fromList(frames),
      contentType: 'application/grpc+proto',
    );
    expect(decoded['format'], 'grpc');
    expect(decoded['frameCount'], 2);
    var first = (decoded['frames'] as List).first as Map;
    expect(first['fields'] as List, hasLength(3));

    // 没有 Content-Type 时也应该靠帧结构识别 gRPC
    var auto = ProtobufDecoder.decodeBody(Uint8List.fromList(grpcFrame(protoSample())));
    expect(auto['format'], 'grpc');

    // flag=1 时按 gzip 解压后再解析
    var compressed = ProtobufDecoder.decodeBody(
      Uint8List.fromList(grpcFrame(io.gzip.encode(protoSample()), flag: 1)),
      grpc: true,
    );
    var compressedFrame = (compressed['frames'] as List).first as Map;
    expect(compressedFrame['compressed'], isTrue);
    expect(compressedFrame['decompressed'], isTrue);
    expect(compressedFrame['fields'] as List, hasLength(3));
  });

  test('decode_protobuf tool resolves a flow and decodes the response body', () async {
    var request = HttpRequest(HttpMethod.post, 'https://api.example.com/OrderService/Get');
    request.headers.set('Content-Type', 'application/grpc');
    var response = HttpResponse(HttpStatus.ok);
    response.headers.set('Content-Type', 'application/grpc+proto');
    response.body = grpcFrame(protoSample());
    response.request = request;
    request.response = response;

    var store = FlowStore()..backfill([request]);
    var tools = McpExtraTools(store: store, redactEnabled: () => true).tools();
    var tool = tools.firstWhere((item) => item.name == 'decode_protobuf');

    var result = await tool.handler({'id': request.requestId}) as Map;
    expect(result['format'], 'grpc');
    expect(result['frameCount'], 1);
    expect(result['contentType'], 'application/grpc+proto');
    expect((result['frames'] as List).length, 1);

    var requestResult = await tool.handler({'id': request.requestId, 'side': 'request'}) as Map;
    expect(requestResult['available'], isFalse);
    expect(requestResult['reason'], 'empty body');
  });

  test('apk string locator finds literals in dex/so and reports class hints', () async {
    var dir = await io.Directory.systemTemp.createTemp('proxypin_apk_');
    try {
      var dex = utf8.encode('Lcom/example/OrderApi;\x00/v1/order/create\x00more');
      var so = utf8.encode('https://api.example.com/v1/order/create');
      var ignored = utf8.encode('/v1/order/create in assets');
      var archive = Archive()
        ..addFile(ArchiveFile('classes.dex', dex.length, dex))
        ..addFile(ArchiveFile('lib/arm64-v8a/libnet.so', so.length, so))
        ..addFile(ArchiveFile('assets/config.txt', ignored.length, ignored));
      var apkPath = '${dir.path}/sample.apk';
      await io.File(apkPath).writeAsBytes(ZipEncoder().encode(archive));

      var result = await ApkStringLocator.locate(apkPath, 'https://api.example.com/v1/order/create');
      expect(result['entriesScanned'], 2);
      expect(result['entries'], containsAll(['classes.dex', 'lib/arm64-v8a/libnet.so']));
      expect(result['entries'], isNot(contains('assets/config.txt')));
      expect(result['degraded'], isTrue);

      var hits = (result['hits'] as List).cast<Map>();
      expect(hits, isNotEmpty);
      var dexHit = hits.firstWhere((hit) => hit['entry'] == 'classes.dex');
      expect(dexHit['kind'], 'dex');
      expect(dexHit['classHint'], 'Lcom/example/OrderApi;');
      expect(hits.any((hit) => hit['entry'].toString().endsWith('.so')), isTrue);
      expect(result['candidates'], containsAll(['https://api.example.com/v1/order/create', '/v1/order/create']));

      var limited = await ApkStringLocator.locate(
        apkPath,
        'https://api.example.com/v1/order/create',
        maxHits: 1,
      );
      expect((limited['hits'] as List).length, 1);
      expect(limited['truncated'], isTrue);
    } finally {
      await dir.delete(recursive: true);
    }
  });

  test('locate_api_in_apk tool rejects missing files and non-zip input', () async {
    var dir = await io.Directory.systemTemp.createTemp('proxypin_apk_tool_');
    try {
      var store = FlowStore();
      var tools = McpExtraTools(store: store, redactEnabled: () => true).tools();
      var tool = tools.firstWhere((item) => item.name == 'locate_api_in_apk');

      await expectLater(
        tool.handler({'url': 'https://api.example.com/x', 'apk_path': '${dir.path}/missing.apk'}),
        throwsA(isA<ToolException>()),
      );

      var notZip = io.File('${dir.path}/not.apk');
      await notZip.writeAsString('plain text, not a zip');
      await expectLater(
        tool.handler({'url': 'https://api.example.com/x', 'apk_path': notZip.path}),
        throwsA(isA<ToolException>()),
      );
    } finally {
      await dir.delete(recursive: true);
    }
  });
}
