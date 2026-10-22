# ProxyPin MCP 缺陷分析与 Fork 改进方案

> **分析对象**：ProxyPin（`com.network.proxy`）v39，`wanghongenpin/proxypin` @ `main`
> **仓库规模**：14171 star / 1241 fork / 660 文件 / Apache-2.0 / 语言 Dart
> **测试设备**：Redmi 23049RAD8C（HyperOS, Android, arm64）
> **分析方法**：运行时实测（端口/socket/cgroup/iptables）+ 源码审读（GitHub API 拉取）
> **分析日期**：2026-10-21

---

## 一、结论摘要

ProxyPin 的 MCP 集成深度在同类工具里罕见（42 个工具，覆盖流量读取、断点改包、本地伪造响应、JS 脚本钩子、重放），方向正确。问题集中在**工程成熟度**而非设计方向：

| # | 问题 | 严重性 | 改动成本 |
|---|---|---|---|
| 1 | MCP server 与 UI 进程绑死，无独立常驻能力 | **高** | 中 |
| 2 | 移动端硬编码绑定 `0.0.0.0`，默认暴露到局域网 | **高** | **极低（3 行）** |
| 3 | 端口被占用时静默回退随机端口，客户端配置永久失效 | 中 | 极低 |
| 4 | MCP token / CA 私钥明文落盘 | 中 | 低 |
| 5 | 规则用 index 寻址，批量操作易误删 | 低 | 中 |
| 6 | `toggle_recording` 命名与语义不符（要求必填 `enabled`） | 低 | 极低 |

---

## 二、勘误（重要，避免误导读者）

以下两条是初次分析时的**误判**，经源码核对后撤回：

### 勘误 1：「工具描述被 inputSchema 字段污染」——不成立

**现象**：`tools/list` 输出被解析成

```
list_flows      :: Epoch milliseconds lower bound
search_flows    :: Max items, default 20, max 100
export_flow_curl :: Forced true unless the user has disabled redaction
```

**原因**：分析侧用 `sed` 正则贪婪匹配，抓到了 `inputSchema.properties` 里**最后一个**字段的 description。

**源码事实**：`lib/mcp/protocol/mcp_server.dart:136-164` 定义完全正确：

```dart
McpTool(
  name: 'get_proxy_status',
  description: 'Get ProxyPin capture status: whether recording, proxy port, ...',
  inputSchema: {'type': 'object', 'properties': {}},
  handler: (_) async { ... },
)
```

**结论：此项缺陷作废。**

### 勘误 2：「toggle_recording 非幂等」——不成立

源码 `lib/mcp/protocol/mcp_actions.dart:1003-1023`：

```dart
McpTool _toggleRecording() => McpTool(
      name: 'toggle_recording',
      inputSchema: {
        'type': 'object',
        'properties': {'enabled': {'type': 'boolean'}},
        'required': ['enabled'],              // <- 必填
      },
      handler: (a) async {
        var server = ProxyServer.current;
        var enabled = a['enabled'] == true;   // 传 {} 时 = false -> 执行 stop
        if (enabled && !server.isRunning) {
          await server.start();
        } else if (!enabled && server.isRunning) {
          await server.stop();
        }
        return {'recording': server.isRunning};
      },
    );
```

调用方传空参 `{}` → `enabled == false` → 每次都执行 stop，所以连续三次都返回 `false`。

**实际语义是 set 且幂等**。唯一可讨论的是命名：叫 `toggle_*` 却要求必填 `enabled`，易误导调用方（尤其 LLM）。

---

## 三、实测证据附录

### 3.1 后台冻结导致 MCP 端口不可达（核心问题）

```
# 现象：服务端 socket 处于 LISTEN，但连接方卡在 SYN_SENT
/proc/net/tcp:  0100007F:23A7 00000000:0000 0A ... uid 10343   <- LISTEN, Recv-Q=0
/proc/net/tcp6: ... :C1C2 ... :23A7 02 ... 01:00000197 uid 10279 <- SYN_SENT, 重传 197 次

# 进程状态
curProcState = 16  (cached)
oom adj cur  = 700 (CACHED_APP_MIN_ADJ)
cat /sys/fs/cgroup/uid_10343/pid_27616/cgroup.freeze = 1

# 客户端表现
curl: (28) Connection timed out after 5001 milliseconds
```

**关键判据**：服务端 `Recv-Q = 0` 说明 SYN 一个都没进 accept queue——不是应用层不 accept，而是**内核层直接丢弃**。

**排除项**：

```bash
iptables -L INPUT -n -v        # policy ACCEPT，fw_INPUT 空链
iptables -L fw_OUTPUT -n -v    # 空链
iptables -t raw -L -n -v       # 仅 netd eBPF 统计链，无 DROP 规则
nft list ruleset               # 空
ip rule show                   # 0: from all lookup local（本地交付优先）
```

结论：iptables 层面无拦截规则，丢弃发生在 **HyperOS 的 netd eBPF ingress 过滤**（该层不体现在 iptables 规则中）。

### 3.2 AOSP 的 freezer 开关对此 ROM 无效

```bash
settings put global cached_apps_freezer disabled   # 已落盘 settings_global.xml
settings get global cached_apps_freezer            # -> disabled
cat /sys/fs/cgroup/uid_10343/pid_27616/cgroup.freeze # -> 仍为 1
```

**结论**：该 ROM 用自有实现，不读取 AOSP 的 `cached_apps_freezer`。



### 3.4 敏感信息落盘位置

```json
// /data/data/com.network.proxy/files/ui_config.json
{
  "mcpEnabled": true,
  "mcpRedactEnabled": true,
  "mcpToken": "<48位hex，见实际文件>",
  "mcpPort": 9127
}
```

```
// /data/data/com.network.proxy/files/
-rw------- ca.crt
-rw------- ca_key.pem          <- CA 私钥明文，仅靠 0600 权限保护
```

### 3.5 易用性陷阱（导致“抓不到数据”）

```json
// files/.proxypin/config.cnf
{
  "port": 9098,
  "enableSsl": false,                  // HTTPS 解密默认关闭
  "appWhitelist": [],                  // 白名单为空
  "appWhitelistEnabled": true,         // 但白名单开关是开的 -> 一个 App 都不代理
  "blacklist": {"list": [".*.apple.com", ".*.icloud.com"], "enabled": true}
}
```

表现：`recording: true`、MCP 连接正常，但 `bufferedFlows: 0`，用户无法判断根源。

---

## 四、源码结构地图

```
lib/mcp/
├── mcp_service.dart              (203 行) 启停编排、绑定地址决策、token 生成、端口回退
├── mcp_names.dart                (  1 KB) 工具名常量
├── transport/
│   ├── mcp_http_server.dart      (188 行) HTTP 层、路由、Bearer 鉴权、SSE/JSON 双写
│   └── setup_script.dart                  /mcp/setup.sh、/mcp/setup.ps1 一键配置脚本
├── protocol/
│   ├── mcp_server.dart           (473 行) JSON-RPC 2.0、内置只读工具定义
│   ├── mcp_actions.dart          (1233 行) 规则写操作工具（断点/重写/重放/脚本）
│   ├── mcp_tool.dart             ( 41 行) 工具元数据容器
│   └── json_rpc.dart                       JSON-RPC 编解码
└── capture/
    ├── flow_store.dart                     流量索引（LRU 有界）
    ├── flow_view.dart                      报文视图
    ├── history_provider.dart               历史会话桥接
    ├── curl_builder.dart                   export_flow_curl
    ├── sensitive_data.dart                 脱敏
    └── cert_status.dart                    证书状态（桌面）

lib/ui/
├── mobile/setting/mcp.dart                移动端 MCP 设置页
├── desktop/toolbar/mcp_panel.dart         桌面端 MCP 面板
└── component/mcp_docs.dart                文档组件

test/
├── mcp_flow_test.dart                     流量工具测试
└── mcp_http_setup_test.dart               setup 脚本下发测试
```

**改动面非常集中**：核心逻辑只在 `lib/mcp/` 14 个文件里，且有现成测试可回归。

---

## 五、改进项详述

### 改进项 1：绑定地址硬编码 `0.0.0.0`（最高性价比）

**源码位置**：`lib/mcp/mcp_service.dart:81`、`:124-132`

```dart
// 现状
bool get lanMode => Platform.isAndroid || Platform.isIOS;   // 81 行

String? token;
InternetAddress bindAddress = InternetAddress.loopbackIPv4;
if (lanMode) {
  bindAddress = InternetAddress.anyIPv4;      // <- Android 无条件绑所有网卡
  token = (cfg.mcpToken?.isNotEmpty ?? false) ? cfg.mcpToken : generateToken();
  cfg.mcpToken = token;
}
```

**源码设计意图**（`mcp_http_server.dart:27-30` 注释）：

> 桌面仅绑定 loopback 且不鉴权，AI 客户端直接以 HTTP 连接；
> 移动端绑定所有网卡并要求 Bearer token，供同一局域网内电脑上的 AI 客户端远程连接。

设计本身合理，但**默认值选错了**。手机抓包场景下绝大多数用户是本机 MCP 客户端连接，默认开 `0.0.0.0` 属于不必要的暴露面（token 又是明文落盘）。

**改法**：

```dart
String? token;
var bindAddress = InternetAddress.loopbackIPv4;
// 仅在用户显式开启「允许局域网接入」时才绑 0.0.0.0
if (lanMode && cfg.mcpLanEnabled) {
  bindAddress = InternetAddress.anyIPv4;
  token = (cfg.mcpToken?.isNotEmpty ?? false) ? cfg.mcpToken : generateToken();
  cfg.mcpToken = token;
}
```

**配套改动**：
- `AppConfiguration` 增加 `bool mcpLanEnabled = false;`
- `lib/storage/shared_preference_keys.dart` 增加对应 key
- `lib/ui/mobile/setting/mcp.dart` 增加开关，token 展示移到开关之下
- `McpHttpServer` 的 `token` 为空时 `_authorized()` 全放行，loopback 模式下这是安全前提

**工作量**：约 1 小时
**收益**：默认消除局域网暴露面

---

### 改进项 2：端口回退静默失效

**源码位置**：`lib/mcp/mcp_service.dart:136-143`

```dart
var preferredPort = cfg.mcpPort ?? defaultPort;   // defaultPort = 9127
try {
  try {
    await _http!.start(preferredPort);
  } on SocketException catch (e) {
    logger.w('MCP port $preferredPort unavailable, falling back to a random port: $e');
    await _http!.start(0);        // <- 换随机端口，cfg 未更新，UI 无提示
  }
```

**后果**：AI 客户端里配的 `:9127` 永久失效，App 界面却显示“服务已启动”。

**改法**：

```dart
} on SocketException {
  await _http!.start(0);
  cfg.mcpPort = _http!.port;      // 回写真实端口
  await cfg.flushConfig();
  logger.w('MCP port $preferredPort busy, now listening on ${_http!.port}');
}
```

**进一步（可选）**：在 `_initializeResult` 的 `serverInfo` 里带上 `port` 和 `recording` 状态，客户端连上即可自检。

**工作量**：30 分钟

---

### 改进项 3：MCP 服务无独立常驻能力（核心痛点）

**问题本质**：`McpService` 是纯 Dart 单例（`McpService.instance`），MCP server 运行在 Flutter isolate 内，生命周期完全绑定 UI 进程。

`mcp_service.dart:32-38` 注释说明了它的定位：

> 作为 `EventListener` 挂到 `ProxyServer.listeners`，与 UI 同源接收流量，因而平台无关且不依赖具体列表容器。

这个设计对**数据通路**合理（与抓包同源），但对**服务可用性**致命：进程一旦被 ROM 判定 cached，端口变哑。

**注意**：`mcp_http_server.dart:56` 有 `onError` 回调，但**捕获不到“SYN 被内核丢弃”**——这种情况下 server 侧没有任何事件，属于静默失效。

**三条实施路径**：

| 方案 | 做法 | 成本 | 效果 | 上游接受度 |
|---|---|---|---|---|
| **A（推荐）** | MCP 开启时复用抓包 VPN 的前台 Service（`ESTABLISH_VPN_SERVICE` 已在用），服务存活期 = 抓包期 | 低 | 覆盖 90% 场景 | 高 |
| B | 独立 `FOREGROUND_SERVICE` + 常驻通知，接 `flutter_foreground_task` | 中 | 不抓包也能常驻 | 低 |
| C | 仅做健康检查：客户端探活失败时提示「请将 ProxyPin 切到前台」 | 极低 | 治标，但错误可读 | 高 |

**推荐组合：A + C**。

**A 的实施要点**：
- ProxyPin 抓包时已有前台 Service（VPN 模式），检查 MCP 启用状态时主动拉起该 Service
- `_startLocked` 成功后调用原生层保持前台通知
- 在 `android/app/src/main/AndroidManifest.xml` 确认 `FOREGROUND_SERVICE` 相关权限已声明

**C 的实施要点**：
- `get_proxy_status` 已返回 `recording`，在 `initialize` 响应的 `instructions` 字段说明该限制
- 客户端探活失败时引导用户将 App 切到前台

**工作量**：方案 A 约半天，方案 C 约 1 小时

---

### 改进项 4：token / CA 私钥存储加固

**现状**：

| 敏感数据 | 位置 | 保护方式 |
|---|---|---|
| `mcpToken`（48 位 hex） | `files/ui_config.json` | 明文 JSON |
| `ca_key.pem` | `files/ca_key.pem` | 0600 文件权限 |

token 生成本身没问题（`mcp_service.dart:84-87` 用了 `Random.secure()`）：

```dart
static String generateToken() {
  var random = Random.secure();
  return List.generate(24, (_) => random.nextInt(256).toRadixString(16).padLeft(2, '0')).join();
}
```

**改法**：

1. **迁移存储**：引入 `flutter_secure_storage`（Android Keystore 后端），`mcpToken` 与 CA 私钥改走安全存储；迁移时保留旧值读取以兼容升级用户。

2. **常量时间比较**：`mcp_http_server.dart:129-137` 目前是字符串直接比较，理论上存在时序侧信道：

```dart
// 现状
if (token == null || req.headers.value(HttpHeaders.authorizationHeader) == 'Bearer $token') {
  return true;
}
```

```dart
// 改法
bool _authorized(HttpRequest req) {
  if (token == null) return true;
  final got = req.headers.value(HttpHeaders.authorizationHeader);
  final want = 'Bearer $token';
  if (got != null && got.length == want.length) {
    var diff = 0;
    for (var i = 0; i < want.length; i++) {
      diff |= got.codeUnitAt(i) ^ want.codeUnitAt(i);
    }
    if (diff == 0) return true;
  }
  req.response.statusCode = HttpStatus.unauthorized;
  req.response.headers.set(HttpHeaders.wwwAuthenticateHeader, 'Bearer');
  unawaited(req.response.close());
  return false;
}
```

**工作量**：约 2 小时（含兼容迁移）

---

### 改进项 5：规则 index 寻址（不建议提 PR）

**问题**：`mcp_actions.dart` 中所有 `update_*` / `remove_*` 依赖 `list_rules` 返回的数组下标。中间删一条，后续下标集体漂移，批量操作必然误删。

**改法**：规则对象增加稳定 UUID，工具契约改为 `id` 寻址。

**风险**：属于 **breaking change**（MCP 工具契约变更），上游大概率不接受，适合 fork 自用。

**工作量**：约 3 小时

---

### 改进项 6：命名与语义（极低成本）

`toggle_recording` -> `set_recording`，保留旧名作为 alias 以向后兼容。

```dart
McpTool _setRecording() => McpTool(
      name: 'set_recording',
      description: 'Start (enabled=true) or stop (enabled=false) traffic recording '
          'by starting/stopping the local proxy server.',
      inputSchema: {
        'type': 'object',
        'properties': {'enabled': {'type': 'boolean'}},
        'required': ['enabled'],
      },
      handler: ...,
    );
```

**工作量**：20 分钟

---

## 六、实施优先级

```
第 1 步   改进项 1（绑定 127.0.0.1） + 改进项 2（端口回写）     ~1 小时   收益最高
第 2 步   改进项 3A（MCP 挂抓包前台服务）+ 3C（健康检查提示）   ~半天     解决核心痛点
第 3 步   改进项 4（secure storage + 常量时间比较）             ~2 小时   安全加固
第 4 步   改进项 6（命名修正）                                   ~20 分钟  API 友好度
可选      改进项 5（index -> UUID）                              ~3 小时   仅 fork 自用
```

---

## 七、PR 策略

| 改进项 | 建议 | 理由 |
|---|---|---|
| 1 绑定地址 | 提 PR | 小、正交、不破坏兼容，附带安全收益 |
| 2 端口回写 | 提 PR | 纯 bug 修复，无争议 |
| 4 token 加固 | 提 PR | 安全改进，全平台受益 |
| 6 命名修正 | 提 PR（带 alias） | 保持向后兼容后风险低 |
| 3 常驻能力 | 自己留 | 跨平台 + 前台服务，维护者倾向保守 |
| 5 index->UUID | 不提 | breaking change，破坏 MCP 工具契约 |

**提 PR 前**：
- 确认 `LICENSE` 为 Apache-2.0，保留全部版权头（`Copyright 2026 Hongen Wang`）
- 每个 PR 只做一个改进项，方便 review
- 附上 `test/mcp_flow_test.dart` 与 `test/mcp_http_setup_test.dart` 的回归结果

---

## 八、起步操作

```bash
# 1. 克隆并确认基线
git clone https://github.com/wanghongenpin/proxypin.git
cd proxypin
flutter pub get

# 2. 先跑测试，确认基线为绿
flutter test test/mcp_flow_test.dart test/mcp_http_setup_test.dart

# 3. 阅读测试，了解 MCP 启停与 setup 脚本的覆盖范围

# 4. 开始改动（建议顺序）
#    lib/mcp/mcp_service.dart               <- 改进项 1、2
#    lib/mcp/transport/mcp_http_server.dart <- 改进项 4
#    lib/ui/mobile/setting/mcp.dart         <- 改进项 1 的 UI 配套
```

**建议先改 `mcp_service.dart`**：改进项 1 和 2 加起来不超过 20 行，却是收益最高的部分。

---

## 九、可复现的验证命令

以下命令用于在设备上独立验证 MCP 服务状态（需要 root）：

```bash
# 1. MCP 端口是否在监听
grep -i "23A7" /proc/net/tcp          # 23A7 = 9127

# 2. 进程是否被冻结（1 = 冻结）
P=$(pidof com.network.proxy | awk '{print $1}')
cat /sys/fs/cgroup/uid_10343/pid_$P/cgroup.freeze

# 3. 进程调度状态
dumpsys activity processes | grep -A25 "APP\* UID 10343" | grep -E "curProcState|oom adj"

# 4. MCP 握手测试
curl -s -X POST http://127.0.0.1:9127/mcp \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "MCP-Protocol-Version: 2024-11-05" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"c","version":"1"}}}'

# 5. 读取配置（含 token / 端口 / 开关）
cat /proc/$P/root/data/data/com.network.proxy/files/ui_config.json
cat /proc/$P/root/data/data/com.network.proxy/files/.proxypin/config.cnf
```

**预期结果**：
- 正常：`initialize` 返回 `200`，body 含 `"name":"proxypin"`
- 被冻结：`curl: (28) Connection timed out`，且 `/proc/net/tcp` 中客户端连接停在状态 `02`（SYN_SENT）

---

## 十、附：MCP 工具清单（42 个）

**流量读取**：`get_proxy_status` `list_histories` `list_flows` `search_flows` `get_flow_detail` `get_flow_body` `get_flow_messages` `export_flow_curl` `generate_code` `add_favorite`

**规则篡改**：`create_breakpoint` `update_breakpoint` `remove_breakpoint` `create_block` `update_block` `remove_block` `create_map_local` `update_map_local` `remove_map_rule` `create_redirect` `update_redirect` `remove_rewrite_rule` `create_rewrite` `update_rewrite` `get_rewrite_detail`

**脚本钩子**：`create_script` `update_script` `get_script_template` `get_script_detail` `remove_script`

**域名过滤**：`list_hosts` `add_host` `remove_host` `set_hosts_enabled`

**SSL / 代理**：`get_ssl_proxying_list` `enable_ssl_proxying` `set_system_proxy` `get_certificate_status`

**发包与状态**：`send_request` `replay_flow` `toggle_recording` `clear_session`

---

*本文档由实测数据 + 源码审读生成，所有源码引用均标注文件名与行号，可对照 `main` 分支核查。*
