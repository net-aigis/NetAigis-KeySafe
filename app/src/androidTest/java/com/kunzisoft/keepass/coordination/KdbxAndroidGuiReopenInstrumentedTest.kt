/* SPDX-License-Identifier: GPL-3.0-or-later */
package com.kunzisoft.keepass.coordination

import android.Manifest
import android.content.Intent
import android.net.Uri
import android.os.Build
import androidx.preference.PreferenceManager
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.By
import androidx.test.uiautomator.UiDevice
import androidx.test.uiautomator.Until
import com.kunzisoft.keepass.R
import com.kunzisoft.keepass.activities.MainCredentialActivity
import com.kunzisoft.keepass.education.Education
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.security.MessageDigest

/**
 * App UI reopen under Studio AVD: crash-pending + published tip unlock to GroupActivity
 * and show entry title `live-entry`. Does not authorize auto-publish.
 */
@RunWith(AndroidJUnit4::class)
class KdbxAndroidGuiReopenInstrumentedTest {

    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val target = instrumentation.targetContext
    private val device = UiDevice.getInstance(instrumentation)

    @Before
    fun prepareAppForUiUnlock() {
        PreferenceManager.getDefaultSharedPreferences(target).edit()
            .putBoolean(target.getString(R.string.enable_education_screens_key), false)
            .commit()
        val edu = Education.getEducationSharedPreferences(target).edit()
        for (keyRes in Education.educationResourcesKeys) {
            edu.putBoolean(target.getString(keyRes), true)
        }
        edu.commit()
        // API 33+: unlock shows a POST_NOTIFICATIONS rationale dialog that blocks loadDatabase.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            instrumentation.uiAutomation.grantRuntimePermission(
                target.packageName,
                Manifest.permission.POST_NOTIFICATIONS
            )
        }
    }

    @Test
    fun crashPendingReopensInAppUiShowingLiveEntry() {
        val kdbx = materializeAsset("crash-pending.kdbx", "gui-crash-pending.kdbx")
        unlockViaCredentialUi(kdbx, MASTER_PASSWORD)
        assertLiveEntryVisible()
    }

    @Test
    fun crashTipReopensInAppUiShowingLiveEntry() {
        val kdbx = materializeAsset("crash-tip.kdbx", "gui-crash-tip.kdbx")
        unlockViaCredentialUi(kdbx, MASTER_PASSWORD)
        assertLiveEntryVisible()
    }

    @Test
    fun coordinatorTipDownloadThenAppUiReopen() {
        val args = InstrumentationRegistry.getArguments()
        val url = args.getString("integration_url")?.trim()
        val token = args.getString("integration_token")?.trim()
        val dbId = args.getString("integration_db_id")?.trim()
        org.junit.Assume.assumeTrue("integration_url required", !url.isNullOrEmpty())
        org.junit.Assume.assumeTrue("integration_token ≥32", !token.isNullOrEmpty() && token.length >= 32)
        org.junit.Assume.assumeTrue("integration_db_id required", !dbId.isNullOrEmpty())

        val tip = KdbxCoordinatorClient(
            url!!,
            dbId!!,
            token!!,
            "KdbxAndroidGuiReopenInstrumentedTest",
            allowInsecureLoopbackForTests = true,
        ).downloadReadOnly()
        org.junit.Assert.assertNotNull("coordinator tip must exist", tip)
        org.junit.Assert.assertTrue(tip!!.isNotEmpty())

        val expectedSha = args.getString("integration_expected_sha256")?.trim()
        if (!expectedSha.isNullOrEmpty()) {
            val actual = MessageDigest.getInstance("SHA-256").digest(tip)
                .joinToString("") { b -> "%02x".format(b) }
            org.junit.Assert.assertEquals(expectedSha.lowercase(), actual)
        }

        val kdbx = File(target.cacheDir, "gui-coord-tip.kdbx")
        kdbx.writeBytes(tip)
        unlockViaCredentialUi(kdbx, MASTER_PASSWORD)
        assertLiveEntryVisible()
    }

    private fun materializeAsset(assetName: String, outName: String): File {
        val out = File(target.cacheDir, outName)
        instrumentation.context.assets.open(assetName).use { input ->
            out.outputStream().use { output -> input.copyTo(output) }
        }
        assertTrue("asset $assetName empty", out.length() > 0)
        return out
    }

    private fun unlockViaCredentialUi(kdbx: File, password: String) {
        device.pressHome()
        val intent = Intent(target, MainCredentialActivity::class.java).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
            putExtra("fileName", Uri.fromFile(kdbx))
            putExtra("password", password)
            putExtra("launchImmediately", true)
        }
        target.startActivity(intent)
        instrumentation.waitForIdleSync()

        // Dismiss TapTarget education overlay if present (full-screen clickable View).
        dismissEducationOverlay()

        // If launchImmediately did not finish unlock (overlay timing), click Unlock.
        val unlock = device.wait(
            Until.findObject(By.res(target.packageName, "activity_password_open_button")),
            8_000
        )
        if (unlock != null) {
            // Ensure password field is filled (extras may race education).
            val passwordField = device.findObject(
                By.res(target.packageName, "password_text_view")
            ) ?: device.findObject(By.res(target.packageName, "password_edit_text"))
                ?: device.findObject(By.clazz("android.widget.EditText"))
            if (passwordField != null) {
                passwordField.click()
                passwordField.setText(password)
            }
            unlock.click()
        }

        // If notification rationale still appears, choose "Later" (starts DB service).
        val later = device.wait(Until.findObject(By.text("Later")), 3_000)
            ?: device.wait(Until.findObject(By.text("Später")), 1_000)
        later?.click()

        val shown = device.wait(Until.hasObject(By.textContains("live-entry")), UNLOCK_TIMEOUT_MS)
            || device.wait(Until.hasObject(By.descContains("live-entry")), 5_000)
        assertTrue("timed out waiting for unlocked UI showing live-entry; hierarchy=${safeDump()}", shown)
    }

    private fun dismissEducationOverlay() {
        // TapTarget draws a full-screen clickable View above the activity.
        repeat(3) {
            val overlay = device.findObject(By.clazz("android.view.View").clickable(true))
            if (overlay != null && overlay.visibleBounds.width() > device.displayWidth * 0.8) {
                overlay.click()
                device.waitForIdle(1_000)
            } else {
                return
            }
        }
    }

    private fun assertLiveEntryVisible() {
        val byText = device.findObject(By.textContains("live-entry"))
        val byDesc = device.findObject(By.descContains("live-entry"))
        assertTrue(
            "live-entry must be visible in app UI after unlock; hierarchy=${safeDump()}",
            byText != null || byDesc != null
        )
    }

    private fun safeDump(): String {
        return try {
            device.dumpWindowHierarchy(File(target.cacheDir, "ui-fail.xml"))
            File(target.cacheDir, "ui-fail.xml").readText().take(1500)
        } catch (_: Exception) {
            "(dump failed)"
        }
    }

    companion object {
        private const val MASTER_PASSWORD = "live-protocol-master"
        private const val UNLOCK_TIMEOUT_MS = 90_000L
    }
}
