// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.connection

import android.content.Context
import android.media.AudioAttributes
import android.media.AudioManager
import android.media.RingtoneManager
import android.os.Build
import android.os.VibrationEffect
import android.os.Vibrator
import android.os.VibratorManager

/**
 * The tone and buzz for something that arrives while the app is on screen,
 * where a notification would be noise (SoundPolicy.IN_APP_TONE). Owner
 * (2026-10-17): "we need a sound & vibrate".
 *
 * As the phone's ring mode says, like any messenger: normal -- tone and
 * buzz; vibrate -- buzz only; silent -- nothing. Never throws: a phone with
 * no vibrator, or a tone that will not play, is not a reason to lose the
 * message that triggered it.
 */
object AlertFeedback {

    /** Two short pulses: noticeable in a pocket, not a ring. */
    val PATTERN = longArrayOf(0, 180, 120, 180)

    fun inApp(context: Context) {
        val mode = runCatching {
            context.getSystemService(AudioManager::class.java)?.ringerMode
        }.getOrNull() ?: AudioManager.RINGER_MODE_NORMAL
        if (mode == AudioManager.RINGER_MODE_SILENT) return
        if (mode == AudioManager.RINGER_MODE_NORMAL) tone(context)
        vibrate(context)
    }

    private fun tone(context: Context) {
        runCatching {
            val uri = RingtoneManager.getDefaultUri(RingtoneManager.TYPE_NOTIFICATION) ?: return
            RingtoneManager.getRingtone(context.applicationContext, uri)?.apply {
                audioAttributes = AudioAttributes.Builder()
                    .setUsage(AudioAttributes.USAGE_NOTIFICATION_EVENT)
                    .setContentType(AudioAttributes.CONTENT_TYPE_SONIFICATION)
                    .build()
                play()
            }
        }
    }

    private fun vibrate(context: Context) {
        runCatching {
            val vibrator: Vibrator? = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S)
                context.getSystemService(VibratorManager::class.java)?.defaultVibrator
            else
                @Suppress("DEPRECATION") context.getSystemService(Vibrator::class.java)
            if (vibrator?.hasVibrator() == true) {
                vibrator.vibrate(VibrationEffect.createWaveform(PATTERN, -1))
            }
        }
    }
}
