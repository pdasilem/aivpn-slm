package com.aivpn.client

import android.app.AlertDialog
import android.os.Bundle
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.aivpn.client.databinding.ActivitySettingsBinding

class SettingsActivity : AppCompatActivity() {
    private lateinit var binding: ActivitySettingsBinding
    private var profiles = mutableListOf<SecureStorage.ConnectionProfile>()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivitySettingsBinding.inflate(layoutInflater)
        setContentView(binding.root)

        profiles = SecureStorage.loadProfiles(this)

        binding.btnBack.setOnClickListener { finish() }
        binding.btnChooseScanner.setOnClickListener { showScannerPicker() }
        binding.btnResetScanner.setOnClickListener {
            SecureStorage.clearDefaultQrScannerPackage(this)
            refreshUi()
        }
        binding.btnChooseAutoConnect.setOnClickListener { showAutoConnectPicker() }
        binding.btnDisableAutoConnect.setOnClickListener {
            SecureStorage.clearAutoConnectProfileId(this)
            refreshUi()
        }

        refreshUi()
    }

    override fun onResume() {
        super.onResume()
        profiles = SecureStorage.loadProfiles(this)
        refreshUi()
    }

    private fun refreshUi() {
        val defaultScannerPackage = SecureStorage.loadDefaultQrScannerPackage(this)
        val defaultScannerLabel = if (
            defaultScannerPackage.isBlank()
            || defaultScannerPackage == SecureStorage.BUILTIN_QR_SCANNER
        ) {
            getString(R.string.settings_scanner_builtin)
        } else {
            QrScannerSupport.findScannerLabel(this, defaultScannerPackage) ?: defaultScannerPackage
        }
        binding.textScannerValue.text = defaultScannerLabel
        binding.btnResetScanner.isEnabled = defaultScannerPackage != SecureStorage.BUILTIN_QR_SCANNER

        val autoConnectProfileId = SecureStorage.loadAutoConnectProfileId(this)
        val autoConnectProfile = profiles.firstOrNull { it.id == autoConnectProfileId }
        if (autoConnectProfile == null && autoConnectProfileId.isNotBlank()) {
            SecureStorage.clearAutoConnectProfileId(this)
        }
        binding.textAutoConnectValue.text = autoConnectProfile?.name
            ?: getString(R.string.settings_auto_connect_disabled)
        binding.btnDisableAutoConnect.isEnabled = autoConnectProfile != null
    }

    private fun showScannerPicker() {
        val scanners = QrScannerSupport.queryScannerApps(this)
        val labels = buildList {
            add(getString(R.string.settings_scanner_builtin))
            addAll(scanners.map { it.label })
        }.toTypedArray()
        AlertDialog.Builder(this, R.style.Theme_AIVPN_Dialog)
            .setTitle(getString(R.string.dialog_choose_qr_scanner))
            .setItems(labels) { _, which ->
                if (which == 0) {
                    SecureStorage.saveDefaultQrScannerPackage(this, SecureStorage.BUILTIN_QR_SCANNER)
                } else {
                    SecureStorage.saveDefaultQrScannerPackage(this, scanners[which - 1].packageName)
                }
                refreshUi()
            }
            .setNegativeButton(getString(R.string.btn_cancel), null)
            .show()
    }

    private fun showAutoConnectPicker() {
        if (profiles.isEmpty()) {
            Toast.makeText(this, getString(R.string.no_profiles), Toast.LENGTH_LONG).show()
            return
        }
        val labels = profiles.map { it.name }.toTypedArray()
        AlertDialog.Builder(this, R.style.Theme_AIVPN_Dialog)
            .setTitle(getString(R.string.settings_auto_connect_dialog))
            .setItems(labels) { _, which ->
                SecureStorage.saveAutoConnectProfileId(this, profiles[which].id)
                refreshUi()
            }
            .setNegativeButton(getString(R.string.btn_cancel), null)
            .show()
    }
}