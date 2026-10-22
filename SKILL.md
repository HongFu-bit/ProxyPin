# ProxyPin MCP Skill

ProxyPin's MCP service exposes captured traffic to AI assistants (Claude Code, Cursor, Codex, Gemini CLI, etc.), so agents can analyze flows, create/edit debugging rules, and replay requests. This skill teaches agents how to use those tools correctly.

## Connection

- **HTTP** (the user-facing transport): the desktop app listens on `http://127.0.0.1:9127/mcp` (loopback, no auth). Register it with e.g. `claude mcp add proxypin_desktop -s user --transport http "http://127.0.0.1:9127/mcp"`. If port 9127 is already in use the app picks a random free port and persists it — use the URL shown in the settings panel rather than hand-copying. No extra bridge process is started, so launching the AI client does not launch ProxyPin.

- **Mobile**: listens on `http://127.0.0.1:9127/mcp` by default (loopback, no token). Enable **Allow LAN access** in MCP settings to bind `0.0.0.0` for computers on the same Wi-Fi — that mode requires the Bearer token shown in the app. Android may freeze background apps (port stays LISTEN but connections time out); enable the **floating-window keep-alive** in MCP settings if that happens.

- **Recording control**: use `set_recording` with the required `enabled` boolean. `toggle_recording` still works as a backward-compatible alias with identical semantics (it sets, it does not toggle).

- **Live stream** (optional): `GET /mcp/events?host=&method=&events=flow_started,flow_completed,flow_message` returns `text/event-stream` and pushes capture events as they happen, so you don't have to poll `list_flows`. `host`/`method` filter server-side; `events` is a comma list (omit for all). A `: keepalive` comment arrives every 15s; reconnect when the connection drops. Same auth as `/mcp` (Bearer token in LAN mode).

Prerequisites: desktop ProxyPin is running and the MCP service is enabled. By default tools read the **live capture buffer** (already-captured traffic — ask the user to trigger the request first), but they can also read **saved history sessions** (the History tab): call `list_histories`, then pass `history_id`. The proxy itself does not need to be capturing to analyze a saved session.

## Tool surface

The service always exposes the full tool set (like Proxyman — there is no read-only mode):

- **Read-only tools**: `get_proxy_status`, `list_histories`, `list_flows`, `search_flows`, `get_flow_detail`, `get_flow_body`, `get_flow_messages`, `get_ssl_proxying_list`, `export_flow_curl`, `get_pending_intercepts`, `analyze_signature`, `generate_api_contract`, `trace_field_flow`, `decode_protobuf`, `locate_api_in_apk`, `get_audit_log`, `list_crypto_profiles`, `detect_crypto_profile`, `list_ws_rewrites`.
- **Write tools**: rule writes (breakpoint / block / map-local / rewrite / script), host filter, replay, system proxy, favorites, clear session, code generation, `resolve_intercept`, `build_offline_mock`, `register_crypto_profile`, `apply_crypto_profile`, `remove_crypto_profile`, `send_ws_message`, `set_ws_rewrite`, `generate_domain_tools`.
- **Active testing tools** (send real requests): `race_replay`, `fuzz_flow`, `scan_cross_user` — rate-limited by default; see below.

Confirm reachability with `get_proxy_status` first; then get each rule's stable `id` from `list_rules` (every `remove_*` / `update_*` / detail tool takes `id`; the legacy `index` is still accepted but drifts when the list changes).

## Recommended workflow

1. **Overview**: `list_flows(limit: 20)` for the latest traffic; for aggregates (host/method/status) pull a batch once and count locally — don't call `get_flow_detail` per flow.
   - **Saved history**: to analyze an earlier session, call `list_histories` to get its `id`, then pass `history_id` to `list_flows` / `search_flows` / `get_flow_detail` / `get_flow_body` / `export_flow_curl` / `replay_flow` / `generate_code`. The same flow `id` is used; `history_id` only selects the session. WebSocket frames are not saved in history (`get_flow_messages` returns `available:false`).
2. **Locate**:
   - Filter by URL/host/method/status: `list_flows(host:, method:, keyword:, status_from:, status_to:)` (`keyword` matches the full URL; `host` is a substring).
   - **Search inside bodies**: `search_flows(keyword: "error 500")` — only searches bodies; binary and >2MB bodies are skipped.
3. **Drill in**: `get_flow_detail(id:)` for headers (redacted by default) + a truncated body preview. Text previews include a `decoded` list when the body looks like JWT / Base64 / Hex / URL-encoded / protobuf-Any. Page large bodies with `get_flow_body(id:, side:, offset:, limit:)`; use `encoding: "base64"` to export raw bytes (including binary bodies) instead of `mimeType/size/sha256` only. WebSocket frames via `get_flow_messages`.
4. **Reproduce / change**:
   - Get the `id` with `list_rules`; `update_*` only changes the fields you pass, `remove_*` deletes, `create_*` adds and returns the new `id`.
   - Debug a single request: `replay_flow(id:)` to replay; `send_request(curl:)` to fire a new one.
   - Export code: `export_flow_curl(id:)` / `generate_code(id:, language:)` (curl/fetch/python).
5. **Clean up**: disable or delete temporary rules you created, so they don't affect real traffic.

## Rewrite rules — the most used feature

Rewrite (重写) is ProxyPin's primary debugging rule type. MCP exposes it through generic tools plus the redirect helpers:

- **List / detail**: `list_rules` → `rewrites` category for ids; `get_rewrite_detail(id)` returns the full rule (type, url, enabled, method) and its operations.
- **Create**: `create_rewrite(url, type?, name?, method?, enabled?, operations)` — `type` ∈ `requestUpdate` / `responseUpdate` / `requestReplace` / `responseReplace` (omit to infer from the ops). `operations` is a list; each op has `op` plus fields:
  - header / body edits: `addHeader`, `updateHeader`, `removeHeader`, `updateBody` → fields `key`, `value`, `use_regex`
  - query params (request only): `addQueryParam`, `updateQueryParam`, `removeQueryParam` → `key`, `value`, `use_regex`
  - full replace: `replaceRequestLine` (`method`, `path`, `query`); `replaceRequestHeader` / `replaceResponseHeader` (`headers`); `replaceRequestBody` / `replaceResponseBody` (`body`, `body_type`); `replaceResponseStatus` (`status_code`)
- **Update**: `update_rewrite(id, url?, name?, method?, enabled?, operations?)` — passing `operations` replaces the whole list.
- **Redirect** (map remote): `create_redirect(url, target_url)` / `update_redirect(id, ...)`.
- **Remove / toggle**: `remove_rewrite_rule(id)` deletes a rule; `remove_rewrite_rule(enabled: false)` disables rewriting globally.

Type constraints: one rule = one type. `requestUpdate` may combine header + body + query ops; `responseUpdate` only header/body ops; `requestReplace` / `responseReplace` only their replace ops. Don't mix request and response ops in one rule — create two rules.

Common patterns:
- "Make X point to Y" → `create_redirect` / `update_redirect` with a `target_url`.
- "Inject a debug header / edit a body value" → `create_rewrite` with `addHeader` / `updateBody`, verify with `replay_flow`.

## Interactive breakpoints

Breakpoint rules pause matching traffic for editing. The MCP client can drive that pause directly:

1. `get_pending_intercepts(phase?: request|response, limit?)` — list paused items. Each item has `id`, `flowId`, `headers`, `body`, `expiresAtMs`, `remainingMs`.
2. `resolve_intercept(id, action: continue|drop, headers?, body?, statusCode?)` — `headers` are merged (same-name overwritten), `body` replaces the whole message as UTF-8, `statusCode` applies to response phase only. A dropped request/response is aborted; a dropped response is not sent.
3. Each item resolves exactly once; a second call returns an error. Unresolved items **auto-continue** at `expiresAtMs` (default 60s) so a disconnected client cannot hang the target app.

The ProxyPin UI window and the MCP client race on the same item — whichever acts first wins. Use this when you need to inspect a live request, rewrite a field, and observe the response without asking the user to edit in the UI.

## Encoding & signature analysis

- **Nothing to set up**: `get_flow_detail` automatically appends `decoded` candidates for JWT, Base64, Hex, URL-encoded and protobuf-Any bodies. Treat them as hints, not proof.
- **Find the signature field**: `analyze_signature(host:, path?, sample_limit?, secret?, history_id?)` compares 2+ captured requests to the same endpoint and reports `constantFields`, `varyingFields`, `signatureCandidates`, and a `bruteForce` block. It tries common concatenations (sorted `k=v&...`, concatenated, raw body, query, with/without a supplied secret) against MD5 / SHA-1 / SHA-256 / HMAC-SHA256. `matched` is evidence; absence of a match is not proof the field is unrelated.
- A useful chain: decrypt/identify a body with `decoded` → `analyze_signature` to find the `sign` field → create a breakpoint → `resolve_intercept` with edited parameters and recomputed signature.
- **Protobuf / gRPC**: `decode_protobuf(id:, side?, format?, history_id?)` decodes a captured body without a `.proto`. It parses the wire format (field number/wire type/raw value); length-delimited values are guessed as string → nested message → bytes. gRPC is detected from `Content-Type: application/grpc*` or a valid 5-byte frame sequence, supports multiple frames, and gunzips `flag=1` frames. Output is explicitly `degraded: true` — field names and enums are unknowable without the schema.

## Contracts & field flow

- **Generate a contract**: `generate_api_contract(host:, min_samples?, format?, history_id?)` groups captured flows by method + normalized path (numeric segments become `{id}`) and returns `openapi` (3.0 document, default), `typescript` (interfaces) or `curl` (replayable commands). `required` = present in every sample; parameter values are omitted. Endpoints with fewer than `min_samples` are skipped and counted in `skippedLowSample`.
- **Map the auth chain**: `trace_field_flow(host:, session_limit?, min_value_len?, history_id?)` finds response values (JSON leaves, `Set-Cookie` pairs, other headers) that reappear in later requests, returning `nodes`, `edges`, `identitySeeds` and `entryPoints`. `identitySeeds` are edges whose target is an Authorization/Cookie/token field; `entryPoints` are the flows that produced them. Values are masked, and `contains` matches on short values can be coincidental.

## Transparent crypto (decrypt / edit / re-encrypt)

`register_crypto_profile` describes one body codec: `alg` (`AES/CBC/PKCS7`, `AES/ECB/PKCS7`, also ZeroPadding/NoPadding), key (`keyHex` / `keyBase64` / `keyUtf8`), optional iv, and `encoding` telling how ciphertext is stored in the body (`raw` / `base64` / `hex`). `applyTo` must include at least one of `hostPattern`, `contentTypes` (exact media type), or `headerHint` (`"X-Encrypted: 1"`) — a profile without scope is rejected so it cannot silently rewrite all traffic.

`apply_crypto_profile {name, mode: "transparent"|"off"}` enables or disables it immediately. While transparent:

- matching request/response bodies are decrypted **in memory** before scripts/breakpoints see them, so `get_flow_detail`, `get_flow_body` and `resolve_intercept` work on plaintext;
- just before bytes are written to the socket, the body is swapped back to the original ciphertext (unchanged body) or re-encrypted (edited body); afterwards the captured object is restored to plaintext;
- a text body that fails decryption is treated as already-plaintext and encrypted on the wire, which makes replay of edited captured flows work;
- binary response bodies that fail decryption are left untouched (never guessed).

`detect_crypto_profile {host, path?, sampleLimit?, history_id?}` guesses `blockSize`, `mode` (ECB only when repeated blocks are visible), `padding` and body `encoding` from captured binary bodies. It produces **no key material** — import keys from r2/Unidbg with `register_crypto_profile`. Treat the output as a hint. Keys are stored locally in `crypto_profiles.json` and are masked in `list_crypto_profiles`.

## WebSocket write / rewrite

- `send_ws_message {flowId, payload, encoding?, opcode?, to?}` pushes a frame into a live connection. `to=server` (default) impersonates the client with a masked frame; `to=client` impersonates the server. The injected frame is added to the flow's message list. Live sessions only — saved history has no socket.
- `set_ws_rewrite {flowId, match, replace, direction?, regex?, clear?}` adds an in-memory text-frame rule (`direction` both/c2s/s2c; regex replace supports `$1`). Rules apply to complete frames before forwarding; binary/control frames and fragmented tails pass through untouched. `clear:true` removes all rules for the flow.
- Rules and sessions are in-memory and disappear when the socket closes or the app restarts.

## Domain tools (generated per host)

`generate_domain_tools {host, history_id?, registerAs?, cryptoProfile?, signatureProfile?, methods?, max_tools?}` turns captured endpoints into callable semantic tools (`app_login`, `app_user_by_id_info`, ...). Names default to `<host label>_<path slug>`; numeric segments become `{id}` → `by_id`. Each generated tool:

- replays the newest captured flow for that method+path, keeping its headers/Cookie/Authorization;
- exposes path parameters (required), query parameters and scalar JSON/form fields as overrides with captured defaults (values with token/sign/password/secret names are redacted from the schema);
- sends a real request through the running proxy and returns status, redacted headers, parsed JSON body (or a truncated text body) and elapsed time;
- with `cryptoProfile`, decrypts the response body when it matches that profile's codec;
- with `signatureProfile: "auto"`, runs `analyze_signature` on the endpoint samples and recomputes the field only when a digest match is proven (MD5/SHA-1/SHA-256/HMAC-SHA256 over sorted pairs/concatenation/body/query/path). The observed `query` and `raw-body` recipes are best-effort, because the captured signature itself was part of those inputs. When no signature is proven, captured signature values are reused — editing signed fields will usually fail.

Pass an explicit object (`{field, algorithm, input, secret?}`) when you already know the recipe. Regenerating for the same host replaces only the tools generated by the previous run. Generated tools live in memory, appear in `tools/list`, and disappear on restart. They operate under the captured account — do not point them at another user without authorization.

## APK string locator

`locate_api_in_apk(url:, apk_path:, max_hits?)` searches an APK you point it at for the URL and its path segments. It scans `classes*.dex` and `.so` entries for UTF-8 literals and reports the zip entry, byte offset, hex context and (for dex hits) the nearest `L...;` class descriptor. This is **string-level evidence only** — it does not decompile, build an xref, or prove which code calls the endpoint. The APK is read from disk; nothing is uploaded.

## Offline mock

`build_offline_mock(host:, history_id?, include_errors?, replace_existing?)` converts captured responses into map-local rules so the app can run without the server. One rule per method+path, newest response wins; binary/oversized bodies and (by default) 4xx/5xx are skipped. Rules are named `mock ...` and the next call replaces them. Map-local matches URLs only, so check `coverage.methodConflicts` when the same path serves several methods. Delete these rules when you go back online.

## Active testing

These tools send real traffic to the target. They reuse the captured request, so signed endpoints keep working only until you change a signed value; when they stop returning 2xx, treat that as a signature problem, not a dead endpoint.

- `race_replay(id:, copies?, max_skew_ms?)` — sends N copies of the same request at once (default 10, max 50) and returns `statusDistribution`, `medianSize`, `anomalies`, `actualSkewMs`, `verdict`. `verdict=inconclusive` means dispatch skew exceeded 2× `max_skew_ms`, so rerun before trusting it.
- `fuzz_flow(id:, param:, payloads:, location?, max_qps?)` — replaces one parameter (`query` / `json` / `form` / `header`, `auto` tries in that order; JSON accepts dot paths) and reports status/size/size delta against an unmodified baseline. `interesting` = status change or >25% size change.
- `scan_cross_user(id:, param:, from:, to:, location?, max_qps?)` — iterates an integer id (max 100 values) and flags 2xx responses with a non-empty body within 2× the baseline size. `suspectHits` is a heuristic; confirm the data belongs to another user before calling it IDOR.

All three accept `history_id` like the other flow tools. Default rate is 3 QPS for fuzzing loops; keep it low — these requests reach the real service.

## Scripts

ProxyPin lets you run JavaScript on matching request/response:

- Read a script before editing it: `get_script_detail(id)` returns name, urls, enabled, remoteUrl and the full JS body; `list_rules` → `scripts` gives the ids.
- Create: `create_script(urls, name?, script?, remote_url?, enabled?)` — omit `script` to use the starter template; `get_script_template` returns it.
- Update: `update_script(id, urls?, script?, name?, enabled?, remote_url?)` — only the fields you pass change.
- Remove / toggle: `remove_script(id)` or `remove_script(enabled: false)`.

Remote scripts (`remote_url`) are fetched from a URL at runtime; `get_script_detail` returns the fetched/cached body.

The `context` object exposes three helpers inside `onRequest`/`onResponse`:

- `context.store.get/set/has/remove/keys` — key/value state persisted in the script session, shared across requests and between the request and response phases.
- `context.crypto.hash(algo, data)`, `hmac(algo, key, data)`, `aesEncrypt/aesDecrypt(data, {key, iv, mode, padding, out})`, `base64Encode/base64Decode`, `rsaSign(data, privateKey, {algo})`, `rsaVerify`, `randomBytes(n)`. Algorithms: MD5/SHA-1/SHA-224/SHA-256/SHA-384/SHA-512; AES only CBC/ECB with PKCS7/ZeroPadding/NoPadding (other modes are rejected, not silently downgraded). Binary I/O is a string (UTF-8), an int array, or base64/hex via `in`/`out`.
- `context.mcp.call(tool, args)` — async; invokes the same MCP tool implementations in-process and resolves to the tool's JSON result (nested calls are capped at depth 5).

## Host filter

Control which hosts are captured:

- `list_hosts` — patterns + enabled state for whitelist/blacklist.
- `add_host(list: whitelist|blacklist, pattern)` / `remove_host(list, pattern)` — `*` is a wildcard, e.g. `*.example.com`.
- `set_hosts_enabled(list, enabled)`.

Semantics: when the whitelist is enabled, only whitelisted hosts are captured; when the blacklist is enabled, blacklisted hosts are skipped.

## Privacy & security

- Redaction is on by default for `Authorization` / `Cookie` / `Set-Cookie`. Do **not** talk users into disabling redaction to grab production secrets — if a value is truly needed, have the user confirm it in the ProxyPin UI.
- Binary bodies return only `mimeType/size/sha256` by default; `get_flow_body(encoding: "base64")` exports raw bytes deliberately and only when the user asked for the binary content.
- `clear_session` is destructive — confirm with the user before calling.
- **Audit log** is opt-in in MCP settings. When enabled, every `tools/call` appends one JSONL line (tool, redacted arguments, client IP, elapsed time, ok/error) to `mcp_audit.jsonl`; the file is capped at 256 KB and old lines are dropped first. `get_audit_log(limit?)` reads recent entries and reports whether logging is currently on. Argument values under keys like authorization/cookie/token/secret/password are replaced with `<redacted>` before writing.

## Boundaries

- MCP operates only on rules ProxyPin supports: breakpoints, blocks, map-local, rewrites/redirects, JS scripts. Don't invent anything.
- The **live** capture buffer keeps the most recent 1000 flows; older ones are dropped. If `get_flow_detail` on the live buffer returns `Flow not found`, either ask the user to re-trigger the request or look in `list_histories` — captured sessions are persisted and do not expire that way.
- `history_id` is a stable id (the session's filename timestamp), not a list index. The in-memory history cache is a small LRU: evicted sessions are re-read from disk automatically, so a flow "not found" from history only happens if the session file itself was deleted.
- Tool results are JSON text — `jsonDecode` before reading fields.