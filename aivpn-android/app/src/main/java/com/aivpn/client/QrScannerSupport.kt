package com.aivpn.client

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build

object QrScannerSupport {
    const val SCAN_INTENT_ACTION = "com.google.zxing.client.android.SCAN"

    data class ScannerApp(
        val packageName: String,
        val label: String,
    )

    fun buildScanIntent(): Intent = Intent(SCAN_INTENT_ACTION).apply {
        putExtra("SCAN_MODE", "QR_CODE_MODE")
        putExtra("PROMPT_MESSAGE", "Scan AIVPN connection QR")
    }

    fun queryScannerApps(context: Context): List<ScannerApp> {
        val intent = buildScanIntent()
        val resolveInfos = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            context.packageManager.queryIntentActivities(
                intent,
                PackageManager.ResolveInfoFlags.of(PackageManager.MATCH_DEFAULT_ONLY.toLong())
            )
        } else {
            @Suppress("DEPRECATION")
            context.packageManager.queryIntentActivities(intent, PackageManager.MATCH_DEFAULT_ONLY)
        }
        return resolveInfos.map {
            ScannerApp(
                packageName = it.activityInfo.packageName,
                label = it.loadLabel(context.packageManager).toString()
            )
        }.sortedBy { it.label.lowercase() }
    }

    fun findScannerLabel(context: Context, packageName: String): String? {
        return queryScannerApps(context).firstOrNull { it.packageName == packageName }?.label
    }
}
