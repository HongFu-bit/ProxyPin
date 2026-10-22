package com.network.proxy.plugin

import android.Manifest
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.provider.Settings
import com.network.proxy.FloatingWindowService
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.MethodChannel

/**
 * 悬浮窗控制通道：权限检查/申请、启停前台保活服务。
 */
class FloatingWindowPlugin : AndroidFlutterPlugin() {
    companion object {
        const val CHANNEL = "com.proxy/floatingWindow"
    }

    private lateinit var context: Context

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        context = binding.applicationContext
        val channel = MethodChannel(binding.binaryMessenger, CHANNEL)
        channel.setMethodCallHandler { call, result ->
            when (call.method) {
                "hasPermission" -> result.success(
                    Build.VERSION.SDK_INT >= Build.VERSION_CODES.M && Settings.canDrawOverlays(context)
                )

                "requestPermission" -> {
                    val intent = Intent(
                        Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
                        Uri.parse("package:${context.packageName}")
                    ).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                    context.startActivity(intent)
                    result.success(null)
                }

                "start" -> {
                    // Android 13+ 通知权限缺失时前台通知不可见，但不影响服务运行；顺手申请一次
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
                        context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) !=
                        PackageManager.PERMISSION_GRANTED
                    ) {
                        runCatching {
                            activity.requestPermissions(
                                arrayOf(Manifest.permission.POST_NOTIFICATIONS), 9128
                            )
                        }
                    }
                    result.success(FloatingWindowService.start(context))
                }

                "stop" -> {
                    FloatingWindowService.stop(context)
                    result.success(null)
                }

                "isRunning" -> result.success(FloatingWindowService.isRunning)

                else -> result.notImplemented()
            }
        }
    }
}
