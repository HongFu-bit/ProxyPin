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

import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:proxypin/l10n/app_localizations.dart';

/// MCP 服务地址/端口编辑对话框（移动端）。
///
/// 地址留空表示按平台自动（移动端用手机局域网 IP 并绑 0.0.0.0）；也可手填任意
/// IPv4（如 127.0.0.1 让服务只在本机可达）。端口沿用 [PortEditDialog] 的规则。
///
/// 返回校验通过的值；取消或非法时返回 null。
///
/// @author wanghongen
class McpEndpointValue {
  /// 监听地址；null 表示自动
  final String? address;
  final int port;

  const McpEndpointValue(this.address, this.port);
}

class McpEndpointDialog extends StatefulWidget {
  final String? initialAddress;
  final int initialPort;
  final int defaultPort;

  const McpEndpointDialog(
      {super.key, this.initialAddress, required this.initialPort, required this.defaultPort});

  /// 便捷打开入口
  static Future<McpEndpointValue?> show(BuildContext context,
      {String? initialAddress, required int initialPort, required int defaultPort}) {
    return showDialog<McpEndpointValue>(
      context: context,
      builder: (_) => McpEndpointDialog(
          initialAddress: initialAddress, initialPort: initialPort, defaultPort: defaultPort),
    );
  }

  @override
  State<McpEndpointDialog> createState() => _McpEndpointDialogState();
}

class _McpEndpointDialogState extends State<McpEndpointDialog> {
  late final TextEditingController _addressController =
      TextEditingController(text: widget.initialAddress ?? '');
  late final TextEditingController _portController =
      TextEditingController(text: '${widget.initialPort}');

  AppLocalizations get l => AppLocalizations.of(context)!;

  @override
  void dispose() {
    // 仅在对话框真正卸载后释放，避免退出动画期间 TextField 仍访问已释放的 controller
    _addressController.dispose();
    _portController.dispose();
    super.dispose();
  }

  bool get _addressValid {
    var value = _addressController.text.trim();
    return value.isEmpty || InternetAddress.tryParse(value) != null;
  }

  bool get _portValid {
    var value = int.tryParse(_portController.text.trim());
    return value != null && value >= 1024 && value <= 65535;
  }

  void _snack(String message) {
    ScaffoldMessenger.of(context)
        .showSnackBar(SnackBar(content: Text(message), duration: const Duration(seconds: 2)));
  }

  void _submit() {
    if (!_addressValid) {
      _snack(l.mcpAddressInvalid);
      return;
    }
    if (!_portValid) {
      _snack(l.mcpPortInvalid);
      return;
    }
    var address = _addressController.text.trim();
    Navigator.pop(context, McpEndpointValue(address.isEmpty ? null : address, int.parse(_portController.text.trim())));
  }

  @override
  Widget build(BuildContext context) {
    var canSave = _addressValid && _portValid;
    return AlertDialog(
      contentPadding: const EdgeInsets.fromLTRB(20, 20, 20, 8),
      title: Text(l.mcpEndpoint, style: const TextStyle(fontSize: 16)),
      content: Column(mainAxisSize: MainAxisSize.min, children: [
        TextField(
          controller: _addressController,
          autofocus: true,
          keyboardType: TextInputType.url,
          decoration: InputDecoration(
            labelText: l.mcpAddress,
            hintText: '0.0.0.0 / 127.0.0.1',
          ),
          onChanged: (_) => setState(() {}),
          onSubmitted: (_) => _submit(),
        ),
        const SizedBox(height: 8),
        TextField(
          controller: _portController,
          keyboardType: TextInputType.number,
          inputFormatters: [FilteringTextInputFormatter.digitsOnly],
          decoration: InputDecoration(labelText: l.mcpPort, hintText: '${widget.defaultPort}'),
          onChanged: (_) => setState(() {}),
          onSubmitted: (_) => _submit(),
        ),
      ]),
      actions: [
        TextButton(onPressed: () => Navigator.pop(context), child: Text(l.cancel)),
        TextButton(onPressed: canSave ? _submit : null, child: Text(l.save)),
      ],
    );
  }
}
