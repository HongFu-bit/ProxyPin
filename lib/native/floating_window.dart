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

import 'package:flutter/services.dart';
import 'package:proxypin/network/util/logger.dart';

/// 悬浮窗前台服务（仅 Android）。
///
/// 显示一个可拖动的小气泡并以前台服务运行，避免 App 退到后台后被系统冻结，
/// 导致 MCP 端口处于 LISTEN 但连接被内核丢弃。调用前需要 [hasPermission] 为真
/// （SYSTEM_ALERT_WINDOW）；服务本身也以前台通知保活。
class FloatingWindow {
  FloatingWindow._();

  static const MethodChannel _channel = MethodChannel('com.proxy/floatingWindow');

  /// 是否已授予悬浮窗权限
  static Future<bool> hasPermission() async {
    if (!Platform.isAndroid) return false;
    try {
      return await _channel.invokeMethod<bool>('hasPermission') ?? false;
    } on PlatformException catch (e) {
      logger.e('[FloatingWindow] hasPermission error: ${e.message}');
      return false;
    } on MissingPluginException {
      return false;
    }
  }

  /// 打开系统「显示在其他应用上层」授权页（结果需用户返回后重新检查）
  static Future<void> requestPermission() async {
    if (!Platform.isAndroid) return;
    try {
      await _channel.invokeMethod('requestPermission');
    } on PlatformException catch (e) {
      logger.e('[FloatingWindow] requestPermission error: ${e.message}');
    } on MissingPluginException {
      // 非 Android 或旧包未内置插件
    }
  }

  /// 启动悬浮窗前台服务；无权限时返回 false
  static Future<bool> start() async {
    if (!Platform.isAndroid) return false;
    try {
      return await _channel.invokeMethod<bool>('start') ?? false;
    } on PlatformException catch (e) {
      logger.e('[FloatingWindow] start error: ${e.message}');
      return false;
    } on MissingPluginException {
      return false;
    }
  }

  /// 启动（若已有权限且尚未运行）
  static Future<bool> ensureStarted() async {
    if (!Platform.isAndroid) return false;
    if (await isRunning()) return true;
    if (!await hasPermission()) return false;
    return start();
  }

  static Future<void> stop() async {
    if (!Platform.isAndroid) return;
    try {
      await _channel.invokeMethod('stop');
    } on PlatformException catch (e) {
      logger.e('[FloatingWindow] stop error: ${e.message}');
    } on MissingPluginException {
      // ignore
    }
  }

  static Future<bool> isRunning() async {
    if (!Platform.isAndroid) return false;
    try {
      return await _channel.invokeMethod<bool>('isRunning') ?? false;
    } on PlatformException catch (e) {
      logger.e('[FloatingWindow] isRunning error: ${e.message}');
      return false;
    } on MissingPluginException {
      return false;
    }
  }
}
