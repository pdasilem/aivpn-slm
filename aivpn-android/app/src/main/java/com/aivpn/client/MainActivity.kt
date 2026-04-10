package com.aivpn.client

import android.app.AlertDialog
import android.content.ActivityNotFoundException
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.View
import android.widget.EditText
import android.widget.ImageButton
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.app.AppCompatDelegate
import com.aivpn.client.databinding.ActivityMainBinding
import org.json.JSONObject
import java.util.Base64
import java.util.Locale
import java.util.UUID

/**
 * Main screen — server address, public key, connect/disconnect button,
 * connection timer, traffic stats, and theme toggle.
 *
 * v0.3.0: Uses EncryptedSharedPreferences for secure key storage.
 */
class MainActivity : AppCompatActivity() {
    companion object {
        private const val CONNECTION_KEY_SIZE_BYTES = 32
    }

    private lateinit var binding: ActivityMainBinding
    private var isConnected = false

    private var profiles = mutableListOf<SecureStorage.ConnectionProfile>()
    private var activeProfileId: String? = null
    private var pendingScanTarget: EditText? = null
    private var pendingScanNameTarget: EditText? = null
    private var connectionKeyParseError = ""

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == RESULT_OK) {
            startVpnService()
        } else {
            Toast.makeText(this, getString(R.string.error_vpn_denied), Toast.LENGTH_SHORT).show()
        }
    }

    private val qrScanLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode != RESULT_OK) return@registerForActivityResult
        val value = result.data?.getStringExtra("SCAN_RESULT")
            ?: result.data?.getStringExtra("com.google.zxing.client.android.SCAN.RESULT")
            ?: result.data?.dataString
        if (value.isNullOrBlank()) {
            Toast.makeText(this, getString(R.string.error_qr_empty), Toast.LENGTH_SHORT).show()
            return@registerForActivityResult
        }
        pendingScanTarget?.setText(value.trim())
        pendingScanTarget?.setSelection(pendingScanTarget?.text?.length ?: 0)
        pendingScanNameTarget?.let { nameInput ->
            if (nameInput.text.toString().trim().isEmpty()) {
                val nextName = buildDefaultProfileName()
                nameInput.setText(nextName)
                nameInput.setSelection(nextName.length)
            }
        }
    }

    // Connection timer
    private val timerHandler = Handler(Looper.getMainLooper())
    private var connectionStartTime = 0L
    private val timerRunnable = object : Runnable {
        override fun run() {
            if (isConnected && connectionStartTime > 0) {
                val elapsed = (System.currentTimeMillis() - connectionStartTime) / 1000
                val h = elapsed / 3600
                val m = (elapsed % 3600) / 60
                val s = elapsed % 60
                binding.textTimer.text = String.format(Locale.ROOT, "%02d:%02d:%02d", h, m, s)
                binding.textDuration.text = String.format(Locale.ROOT, "%02d:%02d", h * 60 + m, s)
                timerHandler.postDelayed(this, 1000)
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        applyTheme()
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        // Load profiles
        profiles = SecureStorage.loadProfiles(this)
        activeProfileId = SecureStorage.loadActiveProfileId(this)

        // If we have an active profile, load its key into the field
        val active = profiles.find { it.id == activeProfileId }
        if (active != null) {
            binding.editConnectionKey.setText(active.key)
        } else if (profiles.isNotEmpty()) {
            activeProfileId = profiles[0].id
            binding.editConnectionKey.setText(profiles[0].key)
            SecureStorage.saveActiveProfileId(this, profiles[0].id)
        }

        renderProfiles()

        updateThemeButton()

        binding.btnConnect.setOnClickListener {
            if (isConnected) disconnect() else connect()
        }

        binding.btnTheme.setOnClickListener {
            toggleTheme()
        }

        binding.btnAddProfile.setOnClickListener {
            showProfileDialog(null)
        }

        binding.btnSplitTunnel.setOnClickListener {
            startActivity(Intent(this, SplitTunnelActivity::class.java))
        }

        updateSplitTunnelHint()

        // Restore connection state if service is already running
        if (AivpnService.isRunning) {
            isConnected = true
            updateUI(true, AivpnService.lastStatusText)
        }
    }

    // ──────────── Profile management ────────────

    private fun extractServerName(connectionKey: String): String {
        val parsed = parseConnectionKey(connectionKey) ?: return "Server"
        val server = parsed[0]
        val host = server.substringBefore(":")
        return host
    }

    private fun renderProfiles() {
        val container = binding.profileList
        container.removeAllViews()

        if (profiles.isEmpty()) {
            val empty = TextView(this).apply {
                text = getString(R.string.no_profiles)
                setTextColor(getColor(R.color.text_secondary))
                textSize = 13f
                setPadding(0, 8.dp, 0, 8.dp)
            }
            container.addView(empty)
            return
        }

        for (profile in profiles) {
            val row = LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = android.view.Gravity.CENTER_VERTICAL
                setPadding(0, 6.dp, 0, 6.dp)
                layoutParams = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT
                )
            }

            val isActive = profile.id == activeProfileId

            // Profile name + server info
            val nameView = TextView(this).apply {
                text = profile.name
                textSize = 14f
                setTextColor(getColor(if (isActive) R.color.accent else R.color.text_primary))
                if (isActive) setTypeface(null, android.graphics.Typeface.BOLD)
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            }

            val editBtn = ImageButton(this).apply {
                setImageResource(android.R.drawable.ic_menu_edit)
                setBackgroundColor(android.graphics.Color.TRANSPARENT)
                setPadding(8.dp, 4.dp, 8.dp, 4.dp)
                contentDescription = getString(R.string.btn_edit)
                setOnClickListener { showProfileDialog(profile) }
            }

            val deleteBtn = ImageButton(this).apply {
                setImageResource(android.R.drawable.ic_menu_delete)
                setBackgroundColor(android.graphics.Color.TRANSPARENT)
                setPadding(8.dp, 4.dp, 8.dp, 4.dp)
                contentDescription = getString(R.string.btn_delete)
                setOnClickListener { confirmDeleteProfile(profile) }
            }

            // Tap the row to select
            row.setOnClickListener {
                if (isConnected) return@setOnClickListener
                activeProfileId = profile.id
                SecureStorage.saveActiveProfileId(this, profile.id)
                binding.editConnectionKey.setText(profile.key)
                renderProfiles()
            }

            row.addView(nameView)
            if (!isConnected) {
                row.addView(editBtn)
                row.addView(deleteBtn)
            }
            container.addView(row)
        }
    }

    private fun buildDefaultProfileName(): String {
        var index = 1
        while (true) {
            val candidate = "Server $index"
            if (profiles.none { it.name.equals(candidate, ignoreCase = true) }) {
                return candidate
            }
            index++
        }
    }

    private fun showProfileDialog(existing: SecureStorage.ConnectionProfile?) {
        if (isConnected) return

        // Use the dialog's theme context so EditText fields inherit proper colours
        // (white text, grey hints) instead of defaulting to the dark-on-dark activity theme.
        val dialogCtx = android.view.ContextThemeWrapper(this, R.style.Theme_AIVPN_Dialog)

        val layout = LinearLayout(dialogCtx).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(24.dp, 16.dp, 24.dp, 0)
        }

        val nameInput = EditText(dialogCtx).apply {
            hint = getString(R.string.hint_profile_name)
            setText(existing?.name ?: "")
            setSingleLine(true)
        }
        val keyInput = EditText(dialogCtx).apply {
            hint = getString(R.string.hint_profile_key)
            setText(existing?.key ?: binding.editConnectionKey.text.toString())
            setSingleLine(true)
            textSize = 13f
        }

        layout.addView(nameInput)
        layout.addView(keyInput)

        if (existing == null
            && nameInput.text.toString().trim().isEmpty()
            && keyInput.text.toString().trim().isEmpty()
        ) {
            val defaultName = buildDefaultProfileName()
            nameInput.setText(defaultName)
            nameInput.setSelection(defaultName.length)
        }

        val title = if (existing != null)
            getString(R.string.dialog_edit_profile)
        else
            getString(R.string.dialog_add_profile)

        val dialog = AlertDialog.Builder(this, R.style.Theme_AIVPN_Dialog)
            .setTitle(title)
            .setView(layout)
            .setPositiveButton(getString(R.string.btn_save)) { _, _ ->
                val name = nameInput.text.toString().trim()
                val key = keyInput.text.toString().trim()

                if (name.isEmpty()) {
                    Toast.makeText(this, getString(R.string.error_profile_name_empty), Toast.LENGTH_SHORT).show()
                    return@setPositiveButton
                }
                if (key.isEmpty()) {
                    Toast.makeText(this, getString(R.string.error_profile_key_empty), Toast.LENGTH_SHORT).show()
                    return@setPositiveButton
                }
                if (parseConnectionKey(key) == null) {
                    Toast.makeText(this, connectionKeyParseError.ifEmpty { getString(R.string.error_profile_key_invalid) }, Toast.LENGTH_LONG).show()
                    return@setPositiveButton
                }

                if (existing != null) {
                    val idx = profiles.indexOfFirst { it.id == existing.id }
                    if (idx >= 0) {
                        profiles[idx] = existing.copy(name = name, key = key)
                    }
                } else {
                    val newProfile = SecureStorage.ConnectionProfile(
                        id = UUID.randomUUID().toString(),
                        name = name,
                        key = key
                    )
                    profiles.add(newProfile)
                    activeProfileId = newProfile.id
                    SecureStorage.saveActiveProfileId(this, newProfile.id)
                    binding.editConnectionKey.setText(key)
                }
                SecureStorage.saveProfiles(this, profiles)
                renderProfiles()
            }
            .setNegativeButton(getString(R.string.btn_cancel), null)
            .setNeutralButton(getString(R.string.btn_scan), null)
            .show()

        dialog.getButton(AlertDialog.BUTTON_NEUTRAL).setOnClickListener {
            pendingScanTarget = keyInput
            pendingScanNameTarget = nameInput
            launchQrScanner()
        }

        dialog.setOnDismissListener {
            pendingScanTarget = null
            pendingScanNameTarget = null
        }
    }

    private fun launchQrScanner() {
        val intent = Intent("com.google.zxing.client.android.SCAN").apply {
            putExtra("SCAN_MODE", "QR_CODE_MODE")
            putExtra("PROMPT_MESSAGE", "Scan AIVPN connection QR")
        }
        try {
            qrScanLauncher.launch(intent)
        } catch (_: ActivityNotFoundException) {
            Toast.makeText(this, getString(R.string.error_no_qr_scanner), Toast.LENGTH_LONG).show()
        }
    }

    private fun confirmDeleteProfile(profile: SecureStorage.ConnectionProfile) {
        if (isConnected) return
        AlertDialog.Builder(this, R.style.Theme_AIVPN_Dialog)
            .setMessage(getString(R.string.confirm_delete_profile, profile.name))
            .setPositiveButton(getString(R.string.btn_delete)) { _, _ ->
                profiles.removeAll { it.id == profile.id }
                if (activeProfileId == profile.id) {
                    activeProfileId = profiles.firstOrNull()?.id
                    activeProfileId?.let { SecureStorage.saveActiveProfileId(this, it) }
                    binding.editConnectionKey.setText(
                        profiles.firstOrNull()?.key ?: ""
                    )
                }
                SecureStorage.saveProfiles(this, profiles)
                renderProfiles()
            }
            .setNegativeButton(getString(R.string.btn_cancel), null)
            .show()
    }

    private val Int.dp: Int get() = (this * resources.displayMetrics.density).toInt()

    private fun updateSplitTunnelHint() {
        val appCount = SecureStorage.loadAllowedApps(this).size
        val siteCount = SecureStorage.loadExcludedDomains(this).size
        binding.textSplitTunnelHint.text = when {
            appCount > 0 && siteCount > 0 -> getString(R.string.split_tunnel_hint_combined,
                resources.getQuantityString(R.plurals.split_tunnel_hint_apps, appCount, appCount),
                resources.getQuantityString(R.plurals.split_tunnel_hint_sites, siteCount, siteCount))
            appCount > 0 -> resources.getQuantityString(R.plurals.split_tunnel_vpn_count, appCount, appCount)
            siteCount > 0 -> resources.getQuantityString(R.plurals.split_tunnel_bypass_count, siteCount, siteCount)
            else -> getString(R.string.split_tunnel_none)
        }
    }

    override fun onResume() {
        super.onResume()
        // Register callbacks when activity becomes visible.
        // Using onResume/onPause instead of onCreate/onDestroy prevents the race condition
        // where a destroyed (rotated) Activity nullifies callbacks registered by the new one.
        AivpnService.statusCallback = { connected, statusText ->
            runOnUiThread {
                isConnected = connected
                updateUI(connected, statusText)
            }
        }

        AivpnService.trafficCallback = { uploadBytes, downloadBytes ->
            runOnUiThread {
                binding.textUpload.text = formatBytes(uploadBytes)
                binding.textDownload.text = formatBytes(downloadBytes)
            }
        }

        // Restore UI state if service is already running (e.g. after returning from
        // VPN permission dialog or screen rotation)
        if (AivpnService.isRunning) {
            isConnected = true
            updateUI(true, AivpnService.lastStatusText)
        }

        updateSplitTunnelHint()
    }

    override fun onPause() {
        super.onPause()
        // Unregister callbacks when activity is no longer in foreground.
        // Only nullify if activity is actually finishing (not just pausing for
        // VPN permission dialog, multi-window, etc.)
        if (isFinishing) {
            AivpnService.statusCallback = null
            AivpnService.trafficCallback = null
        }
    }

    /**
     * Parse connection key: aivpn://BASE64URL_NO_PAD({"s":"host:port","k":"...","g":"...","p":"...","i":"..."})
     * Returns (server, serverKey, serverSigningKey, psk, vpnIp) or null on failure.
     */
    private fun parseConnectionKey(key: String): Array<String>? {
        val raw = key.trim()
        connectionKeyParseError = ""
        if (!raw.startsWith("aivpn://")) {
            connectionKeyParseError = getString(R.string.error_connection_key_prefix)
            return null
        }
        val payload = raw.removePrefix("aivpn://")
        val json = try {
            val jsonBytes = Base64.getUrlDecoder().decode(payload)
            JSONObject(String(jsonBytes, Charsets.UTF_8))
        } catch (_: Exception) {
            connectionKeyParseError = getString(R.string.error_connection_key_payload)
            return null
        }
        val server = requiredConnectionKeyField(json, "s") ?: return null
        val serverKey = requiredConnectionKeyField(json, "k") ?: return null
        val serverSigningKey = requiredConnectionKeyField(json, "g") ?: return null
        val psk = requiredConnectionKeyField(json, "p") ?: return null
        val vpnIp = requiredConnectionKeyField(json, "i") ?: return null
        if (!requireDecodedKeySize("server public key", serverKey)) return null
        if (!requireDecodedKeySize("server signing key", serverSigningKey)) return null
        if (!requireDecodedKeySize("preshared key", psk)) return null
        return arrayOf(server, serverKey, serverSigningKey, psk, vpnIp)
    }

    private fun requiredConnectionKeyField(json: JSONObject, name: String): String? {
        val value = json.optString(name, "")
        return if (value.isBlank()) {
            connectionKeyParseError = getString(R.string.error_connection_key_missing_field, name)
            null
        } else {
            value
        }
    }

    private fun requireDecodedKeySize(label: String, value: String): Boolean {
        val decoded = try {
            android.util.Base64.decode(value, android.util.Base64.DEFAULT)
        } catch (_: IllegalArgumentException) {
            connectionKeyParseError = resources.getQuantityString(
                R.plurals.error_connection_key_size,
                CONNECTION_KEY_SIZE_BYTES,
                label,
                CONNECTION_KEY_SIZE_BYTES
            )
            return false
        }
        if (decoded.size != CONNECTION_KEY_SIZE_BYTES) {
            connectionKeyParseError = resources.getQuantityString(
                R.plurals.error_connection_key_size,
                CONNECTION_KEY_SIZE_BYTES,
                label,
                CONNECTION_KEY_SIZE_BYTES
            )
            return false
        }
        return true
    }

    private fun connect() {
        val connectionKey = binding.editConnectionKey.text.toString().trim()
        if (connectionKey.isEmpty()) {
            Toast.makeText(this, getString(R.string.error_fill_fields), Toast.LENGTH_SHORT).show()
            return
        }

        val parsed = parseConnectionKey(connectionKey)
        if (parsed == null) {
            Toast.makeText(this, getString(R.string.error_invalid_connection_key), Toast.LENGTH_SHORT).show()
            return
        }

        // Auto-save if the key isn't already in profiles
        if (profiles.none { it.key == connectionKey }) {
            val profile = SecureStorage.ConnectionProfile(
                id = UUID.randomUUID().toString(),
                name = extractServerName(connectionKey),
                key = connectionKey
            )
            profiles.add(profile)
            activeProfileId = profile.id
            SecureStorage.saveProfiles(this, profiles)
            SecureStorage.saveActiveProfileId(this, profile.id)
            renderProfiles()
        }

        // Request VPN permission from the system
        val intent = VpnService.prepare(this)
        if (intent != null) {
            vpnPermissionLauncher.launch(intent)
        } else {
            startVpnService()
        }
    }

    private fun disconnect() {
        val intent = Intent(this, AivpnService::class.java).apply {
            action = AivpnService.ACTION_DISCONNECT
        }
        startService(intent)
    }

    private fun startVpnService() {
        val connectionKey = binding.editConnectionKey.text.toString().trim()
        val parsed = parseConnectionKey(connectionKey) ?: return
        val (server, serverKey, serverSigningKey, psk, vpnIp) = parsed

        val intent = Intent(this, AivpnService::class.java).apply {
            action = AivpnService.ACTION_CONNECT
            putExtra("server", server)
            putExtra("server_key", serverKey)
            putExtra("server_signing_key", serverSigningKey)
            putExtra("psk", psk)
            putExtra("vpn_ip", vpnIp)
        }
        startForegroundService(intent)
        updateUI(true, getString(R.string.status_connecting))
    }

    private fun updateUI(connected: Boolean, statusText: String) {
        isConnected = connected
        binding.btnConnect.text = getString(
            if (connected) R.string.btn_disconnect else R.string.btn_connect
        )
        binding.btnConnect.setBackgroundColor(
            getColor(if (connected) R.color.disconnect else R.color.accent)
        )
        binding.textStatus.text = statusText
        binding.statusDot.setBackgroundResource(
            if (connected) R.drawable.dot_green else R.drawable.dot_grey
        )

        // Show/hide stats and timer
        val statsVisibility = if (connected) View.VISIBLE else View.GONE
        binding.textTimer.visibility = statsVisibility
        binding.statsRow.visibility = statsVisibility

        // Lock/unlock input fields while connected
        binding.editConnectionKey.isEnabled = !connected
        binding.btnAddProfile.isEnabled = !connected
        renderProfiles()

        // Timer management
        if (connected && connectionStartTime == 0L) {
            connectionStartTime = System.currentTimeMillis()
            timerHandler.post(timerRunnable)
        } else if (!connected) {
            connectionStartTime = 0L
            timerHandler.removeCallbacks(timerRunnable)
            binding.textTimer.text = getString(R.string.timer_zero)
            binding.textUpload.text = getString(R.string.bytes_zero)
            binding.textDownload.text = getString(R.string.bytes_zero)
            binding.textDuration.text = getString(R.string.duration_zero)
        }
    }

    private fun applyTheme() {
        val mode = if (SecureStorage.loadTheme(this) == "light") {
            AppCompatDelegate.MODE_NIGHT_NO
        } else {
            AppCompatDelegate.MODE_NIGHT_YES
        }
        AppCompatDelegate.setDefaultNightMode(mode)
    }

    private fun toggleTheme() {
        val next = if (SecureStorage.loadTheme(this) == "light") "dark" else "light"
        SecureStorage.saveTheme(this, next)
        applyTheme()
        updateThemeButton()
    }

    private fun updateThemeButton() {
        binding.btnTheme.text = getString(
            if (SecureStorage.loadTheme(this) == "light") R.string.btn_theme_dark else R.string.btn_theme_light
        )
    }

    private fun formatBytes(bytes: Long): String {
        return when {
            bytes < 1024 -> "$bytes B"
            bytes < 1024 * 1024 -> String.format(Locale.ROOT, "%.1f KB", bytes / 1024.0)
            bytes < 1024 * 1024 * 1024 -> String.format(Locale.ROOT, "%.1f MB", bytes / (1024.0 * 1024.0))
            else -> String.format(Locale.ROOT, "%.2f GB", bytes / (1024.0 * 1024.0 * 1024.0))
        }
    }

    override fun onDestroy() {
        timerHandler.removeCallbacks(timerRunnable)
        super.onDestroy()
    }
}