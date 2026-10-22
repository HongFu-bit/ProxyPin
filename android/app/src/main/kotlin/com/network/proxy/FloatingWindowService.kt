package com.network.proxy

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.graphics.Color
import android.graphics.PixelFormat
import android.graphics.drawable.GradientDrawable
import android.os.Build
import android.os.IBinder
import android.provider.Settings
import android.util.Log
import android.view.Gravity
import android.view.MotionEvent
import android.view.View
import android.view.WindowManager
import android.widget.TextView
import kotlin.math.abs

/**
 * 悬浮窗前台服务：显示一个可拖动的小气泡，并以前台服务保活，
 * 避免 ProxyPin 退到后台后被系统判定为 cached 进程而冻结
 * （表现为 MCP 端口仍在 LISTEN，但连接方停在 SYN_SENT）。
 *
 * 需要 SYSTEM_ALERT_WINDOW 权限；服务本身通过常驻通知维持前台优先级。
 */
class FloatingWindowService : Service() {

    companion object {
        private const val TAG = "FloatingWindow"
        private const val CHANNEL_ID = "proxypin_mcp_keepalive"
        private const val NOTIFICATION_ID = 9127

        @Volatile
        var isRunning: Boolean = false
            private set

        /** 启动服务；无悬浮窗权限时返回 false */
        fun start(context: Context): Boolean {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) return false
            if (!Settings.canDrawOverlays(context)) return false
            val intent = Intent(context, FloatingWindowService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
            return true
        }

        fun stop(context: Context) {
            context.stopService(Intent(context, FloatingWindowService::class.java))
        }
    }

    private var windowManager: WindowManager? = null
    private var bubble: View? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        isRunning = true
        startForegroundCompat()
        addOverlay()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // 被系统回收后重建：尽量恢复气泡
        if (bubble == null) addOverlay()
        return START_STICKY
    }

    override fun onDestroy() {
        removeOverlay()
        isRunning = false
        super.onDestroy()
    }

    private fun startForegroundCompat() {
        val notification = buildNotification()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private fun buildNotification(): Notification {
        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            if (manager.getNotificationChannel(CHANNEL_ID) == null) {
                manager.createNotificationChannel(
                    NotificationChannel(
                        CHANNEL_ID,
                        "MCP 后台保活",
                        NotificationManager.IMPORTANCE_LOW
                    ).apply {
                        description = "保持 ProxyPin MCP 服务在后台可用"
                        setShowBadge(false)
                    }
                )
            }
        }
        val openIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java).apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP)
            },
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_ID)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }
        return builder
            .setContentTitle("ProxyPin MCP 运行中")
            .setContentText("悬浮窗保活中，点击打开应用")
            .setSmallIcon(android.R.drawable.stat_notify_sync)
            .setOngoing(true)
            .setContentIntent(openIntent)
            .build()
    }

    private fun addOverlay() {
        if (bubble != null) return
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) return
        if (!Settings.canDrawOverlays(this)) return

        val wm = getSystemService(Context.WINDOW_SERVICE) as WindowManager
        windowManager = wm
        val size = dp(56)
        val view = TextView(this).apply {
            text = "PP"
            setTextColor(Color.WHITE)
            textSize = 14f
            gravity = Gravity.CENTER
            background = GradientDrawable().apply {
                shape = GradientDrawable.OVAL
                setColor(0xE6207B5E.toInt())
            }
        }

        val type = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY
        } else {
            @Suppress("DEPRECATION")
            WindowManager.LayoutParams.TYPE_PHONE
        }
        val params = WindowManager.LayoutParams(
            size,
            size,
            type,
            WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE or
                    WindowManager.LayoutParams.FLAG_LAYOUT_NO_LIMITS,
            PixelFormat.TRANSLUCENT
        ).apply {
            gravity = Gravity.TOP or Gravity.START
            x = dp(12)
            y = dp(220)
        }

        var downRawX = 0f
        var downRawY = 0f
        var startX = 0
        var startY = 0
        var downAt = 0L
        var moved = false
        view.setOnTouchListener { _, event ->
            when (event.actionMasked) {
                MotionEvent.ACTION_DOWN -> {
                    downRawX = event.rawX
                    downRawY = event.rawY
                    startX = params.x
                    startY = params.y
                    downAt = System.currentTimeMillis()
                    moved = false
                    true
                }

                MotionEvent.ACTION_MOVE -> {
                    val dx = (event.rawX - downRawX).toInt()
                    val dy = (event.rawY - downRawY).toInt()
                    if (abs(dx) > dp(4) || abs(dy) > dp(4)) moved = true
                    params.x = startX + dx
                    params.y = startY + dy
                    runCatching { wm.updateViewLayout(view, params) }
                    true
                }

                MotionEvent.ACTION_UP -> {
                    if (!moved && System.currentTimeMillis() - downAt < 400) openApp()
                    true
                }

                else -> false
            }
        }

        try {
            wm.addView(view, params)
            bubble = view
        } catch (e: Exception) {
            Log.w(TAG, "add overlay failed", e)
        }
    }

    private fun removeOverlay() {
        val view = bubble ?: return
        bubble = null
        runCatching { windowManager?.removeView(view) }
    }

    private fun openApp() {
        val intent = Intent(this, MainActivity::class.java).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP)
        }
        startActivity(intent)
    }

    private fun dp(value: Int): Int =
        (value * resources.displayMetrics.density).toInt()
}
