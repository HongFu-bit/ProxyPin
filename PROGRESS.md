# ProxyPin Fork 进度快照

- 日期：2026-10-22
- 分支：`main`
- 状态：改动均在工作区，**尚未提交 git**
- 依据：`ProxyPin-MCP-缺陷分析与Fork改进方案.md`
- 原则：MCP 扩展尽量放 `lib/mcp/extra/`，上游文件只做必要接入

## 已完成

### A. 方案文档六项

| # | 改进项 | 落点 | 状态 |
|---|--------|------|------|
| 1 | 移动端不再硬编码 `0.0.0.0`，默认回环，局域网需显式开启 | `lib/mcp/mcp_service.dart`、移动端 MCP 设置页 | 完成 |
| 2 | 端口被占用回退随机端口后回写 `cfg.mcpPort` | `lib/mcp/mcp_service.dart` | 完成 |
| 3 | Android 前台服务/悬浮窗保活，避免后台冻结断连 | `FloatingWindowService.kt`、`FloatingWindowPlugin.kt`、`lib/native/floating_window.dart` | 完成 |
| 4 | MCP token / CA 私钥改用系统安全存储，旧明文自动迁移 | `lib/security/secure_store.dart`、`mcp_service.dart`、`crts.dart`、SSL 导出页 | 完成 |
| 5 | 规则 UUID 稳定寻址，MCP 工具 `id` 优先、兼容 `index` | `lib/utils/rule_id.dart`、`lib/mcp/protocol/rule_ref.dart`、5 类规则模型、`mcp_actions.dart` | 完成 |
| 6 | `set_recording` 语义化命名，保留 `toggle_recording` 别名 | `lib/mcp/protocol/mcp_actions.dart`、`test/mcp_flow_test.dart` | 完成 |

### B. MCP 能力扩展（前序批次）

- 加密桥 / 透明解密：`lib/network/components/crypto_transparent.dart`、`lib/mcp/extra/crypto_tools.dart`
  - `register_crypto_profile`、`apply_crypto_profile`、`remove_crypto_profile`、`list_crypto_profiles`、`detect_crypto_profile`
- WebSocket 控制：`lib/network/components/ws_control.dart`、`lib/mcp/extra/ws_tools.dart`
  - `send_ws_message`、`set_ws_rewrite`、`list_ws_rewrites`
- 按域名生成工具：`lib/mcp/extra/domain_tools.dart`
  - `generate_domain_tools`，支持参数 schema、签名推断与 MD5/SHA-1/SHA-256/HMAC-SHA256 重算
- 分析与测试辅助：`lib/mcp/extra/` 下
  - `build_offline_mock`、`race_replay`、`fuzz_flow`、`scan_cross_user`
  - `analyze_signature`、`generate_api_contract`、`trace_field_flow`、`decode_protobuf`、`locate_api_in_apk`
  - 交互断点 `get_pending_intercepts` / `resolve_intercept`、审计日志 `get_audit_log`
- 脚本进程内桥：`lib/network/components/js/context_bridge.dart`
- MCP 动态工具注册与移除：`lib/mcp/protocol/mcp_server.dart`
- 常量时间 Bearer 校验：`lib/mcp/transport/bearer_auth.dart`

### C. 文档与测试

- `SKILL.md`：补充完整工具契约、id 寻址、域名工具说明
- 新增测试：
  - `test/secure_store_test.dart`（安全存储降级 + 常量时间鉴权，8 项）
  - `test/rule_id_test.dart`（UUID、序列化、id/index 解析，13 项）
  - `test/domain_tools_test.dart`（9 项）
  - `test/mcp_extra_test.dart`、`test/crypto_ws_test.dart`
  - `test/secure_store_migration_test.dart`（旧明文 token 迁移、安全存储优先、写失败回退，4 项）
- 修改：`test/mcp_flow_test.dart`（本轮新增规则稳定 id 端到端寻址用例）

## 验证状态

- `flutter analyze --no-fatal-infos --no-fatal-warnings lib`：**0 errors**（206 条均为 info）
- 定向测试（MCP、安全存储、规则、域名工具等）：**81 项全部通过**
- 全量 `flutter test`：**275 通过 / 1 跳过 / 8 失败**
- 8 项失败均为既有环境或 binding 问题，本轮未新增：
  1. `cert_test.dart` 加载失败
  2. `favorites_trim_test.dart`（依赖运行环境）
  3. `http_test.dart` 加载失败
  4. `js_test.dart` 加载失败
  5. `search_controller_test.dart` 缺少 `TestWidgetsFlutterBinding`
  6. `setup_script_test.dart` 平台相关
  7. `virtualized_highlight_text_test.dart` 滚动定位
  8. `web_test.dart` 回环端口连接被拒

## 未执行 / 待验证

- 未在 Android/iOS/Windows/macOS/Linux 真机或桌面构建中验证 Keystore、Keychain、DPAPI、libsecret 实际落盘。
- token 旧明文迁移已用临时目录回放验证；CA 私钥明文文件迁移仍未回放。
- 规则 id 寻址已通过 MCP 分发端到端用例（创建→插入扰动→按 id 读/改/删→旧 index 兼容）；其余规则类型与真实 MCP 客户端未逐一验证。
- 加密透明解密、WebSocket 改写、域名生成工具尚未对真实 App 流量做端到端验证。
- UI 开关、证书安装/信任、VPN/局域网权限等仍需人工路径验证。
- 未提交 git。

## 恢复命令

```bash
export PATH="/e/Flutter/bin:$PATH"
cd /e/IDEA/proxypin-main
flutter pub get
flutter analyze --no-fatal-infos --no-fatal-warnings lib
flutter test
```

定向回归：

```bash
flutter test test/secure_store_test.dart test/rule_id_test.dart \
  test/domain_tools_test.dart test/mcp_extra_test.dart \
  test/crypto_ws_test.dart test/mcp_flow_test.dart
```
