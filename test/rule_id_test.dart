import 'package:flutter_test/flutter_test.dart';
import 'package:proxypin/mcp/protocol/mcp_server.dart';
import 'package:proxypin/mcp/protocol/rule_ref.dart';
import 'package:proxypin/network/components/manager/request_block_manager.dart';
import 'package:proxypin/network/components/manager/request_breakpoint_manager.dart';
import 'package:proxypin/network/components/manager/request_map_manager.dart';
import 'package:proxypin/network/components/manager/request_rewrite_manager.dart';
import 'package:proxypin/network/components/manager/rewrite_rule.dart';
import 'package:proxypin/network/components/manager/script_manager.dart';
import 'package:proxypin/utils/rule_id.dart';

void main() {
  group('newRuleId', () {
    test('returns RFC 4122 version 4 UUIDs', () {
      var pattern = RegExp(r'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$');
      for (var i = 0; i < 100; i++) {
        expect(newRuleId(), matches(pattern));
      }
    });

    test('does not collide across a large batch', () {
      var ids = {for (var i = 0; i < 5000; i++) newRuleId()};
      expect(ids.length, 5000);
    });
  });

  group('rule models keep stable ids in JSON', () {
    test('breakpoint', () {
      var rule = RequestBreakpointRule(url: r'https://example\.com/.*');
      var json = rule.toJson();
      expect(json['id'], rule.id);
      expect(RequestBreakpointRule.fromJson(json).id, rule.id);
    });

    test('block', () {
      var item = RequestBlockItem(true, '*.example.com/*', BlockType.blockRequest);
      var json = item.toJson();
      expect(json['id'], item.id);
      expect(RequestBlockItem.fromJson(json).id, item.id);
    });

    test('map-local', () {
      var rule = RequestMapRule(url: '*.example.com/*', type: RequestMapType.local);
      var json = rule.toJson();
      expect(json['id'], rule.id);
      expect(RequestMapRule.fromJson(json).id, rule.id);
    });

    test('rewrite', () {
      var rule = RequestRewriteRule(url: '*.example.com/*', type: RuleType.requestUpdate);
      var json = rule.toJson();
      expect(json['id'], rule.id);
      expect(RequestRewriteRule.formJson(json).id, rule.id);
    });

    test('script', () {
      var item = ScriptItem(true, 'demo', '*.example.com/*');
      var json = item.toJson();
      expect(json['id'], item.id);
      expect(ScriptItem.fromJson(json).id, item.id);
    });

    test('legacy JSON without id gets a generated one', () {
      var bp = RequestBreakpointRule.fromJson({'url': 'x'});
      var block = RequestBlockItem.fromJson({'enabled': true, 'url': 'x', 'type': 'blockRequest'});
      var map = RequestMapRule.fromJson({'enabled': true, 'url': 'x', 'type': 'local'});
      var rewrite = RequestRewriteRule.formJson({'enabled': true, 'url': 'x', 'type': 'requestUpdate'});
      var script = ScriptItem.fromJson({'enabled': true, 'name': 's', 'url': 'x'});

      for (var id in [bp.id, block.id, map.id, rewrite.id, script.id]) {
        expect(id, isNotEmpty);
      }
      // 生成后再次序列化，id 固定不变
      expect(RequestBreakpointRule.fromJson(bp.toJson()).id, bp.id);
      expect(RequestBlockItem.fromJson(block.toJson()).id, block.id);
      expect(RequestMapRule.fromJson(map.toJson()).id, map.id);
      expect(RequestRewriteRule.formJson(rewrite.toJson()).id, rewrite.id);
      expect(ScriptItem.fromJson(script.toJson()).id, script.id);
    });
  });

  group('resolveRuleIndex', () {
    var rules = [
      _Rule('id-a'),
      _Rule('id-b'),
      _Rule('id-c'),
    ];
    String idOf(_Rule r) => r.id;

    test('id wins over a conflicting index', () {
      expect(resolveRuleIndex(rules, {'id': 'id-c', 'index': 0}, idOf, 'rule'), 2);
    });

    test('falls back to legacy index', () {
      expect(resolveRuleIndex(rules, {'index': 1}, idOf, 'rule'), 1);
      expect(resolveRuleIndex(rules, {'index': '2'}, idOf, 'rule'), 2);
    });

    test('requires id or index', () {
      expect(() => resolveRuleIndex(rules, {}, idOf, 'rule'), throwsA(isA<ToolException>()));
    });

    test('rejects unknown ids', () {
      expect(() => resolveRuleIndex(rules, {'id': 'missing'}, idOf, 'rule'), throwsA(isA<ToolException>()));
    });

    test('rejects out-of-range indices', () {
      expect(() => resolveRuleIndex(rules, {'index': -1}, idOf, 'rule'), throwsA(isA<ToolException>()));
      expect(() => resolveRuleIndex(rules, {'index': 3}, idOf, 'rule'), throwsA(isA<ToolException>()));
    });
  });
}

class _Rule {
  final String id;

  _Rule(this.id);
}
