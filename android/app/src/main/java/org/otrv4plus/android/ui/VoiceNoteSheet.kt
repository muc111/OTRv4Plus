// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.ui

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.media.MediaPlayer
import android.net.Uri
import android.provider.Settings
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import org.otrv4plus.android.chat.ChatViewModel
import org.otrv4plus.android.chat.VoiceNotes
import org.otrv4plus.android.chat.VoiceSheet
import org.otrv4plus.android.crypto.MicPermission

/**
 * Record a voice note in a synthetic voice (or your own), hear it, then send or discard.
 *
 * Everything the sheet shows is [ChatViewModel.voiceSheet]. The recording
 * never comes to Kotlin; the preview plays the finished, masked file --
 * exactly what the other person will hear.
 */
@Composable
fun VoiceNoteSheet(model: ChatViewModel, jid: String) {
    val sheet = model.voiceSheet ?: return
    val context = LocalContext.current
    model.voiceDir = context.cacheDir

    var askedBefore by rememberSaveable { mutableStateOf(false) }
    var explain by rememberSaveable { mutableStateOf(false) }
    var settings by rememberSaveable { mutableStateOf(false) }

    fun granted(): Boolean =
        ContextCompat.checkSelfPermission(context, Manifest.permission.RECORD_AUDIO) ==
            PackageManager.PERMISSION_GRANTED

    val launcher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { allowed ->
        askedBefore = true
        model.startVoiceNote(allowed)
    }

    fun record() {
        if (granted()) {
            model.startVoiceNote(true)
            return
        }
        val activity = context as? Activity
        val rationale = activity != null &&
            ActivityCompat.shouldShowRequestPermissionRationale(
                activity, Manifest.permission.RECORD_AUDIO)
        when (MicPermission.decide(MicPermission.State(false, rationale, askedBefore))) {
            MicPermission.Decision.Proceed -> model.startVoiceNote(true)
            MicPermission.Decision.Request -> launcher.launch(Manifest.permission.RECORD_AUDIO)
            MicPermission.Decision.ExplainThenRequest -> explain = true
            MicPermission.Decision.OpenSettings -> settings = true
        }
    }

    AlertDialog(
        // Tapping outside does not throw a recording away by accident.
        onDismissRequest = { if (sheet !is VoiceSheet.Recording) model.closeVoiceSheet() },
        title = { Text("Voice note") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                when (sheet) {
                    is VoiceSheet.Choosing, is VoiceSheet.Failed -> {
                        Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                            for (mode in VoiceNotes.MODES) {
                                FilterChip(
                                    selected = sheet.mode == mode,
                                    onClick = { model.chooseVoice(mode) },
                                    label = { Text(VoiceNotes.label(mode)) },
                                )
                            }
                        }
                        Text(VoiceNotes.detail(sheet.mode),
                             style = MaterialTheme.typography.bodyMedium)
                        Text(VoiceNotes.CAVEAT,
                             style = MaterialTheme.typography.bodySmall,
                             color = MaterialTheme.colorScheme.onSurfaceVariant)
                        if (sheet is VoiceSheet.Failed) {
                            Text(sheet.message, color = MaterialTheme.colorScheme.error,
                                 style = MaterialTheme.typography.bodySmall)
                        }
                    }
                    is VoiceSheet.Recording -> {
                        Text("Recording · ${VoiceNotes.label(sheet.mode)} · " +
                             VoiceNotes.clock(sheet.seconds),
                             style = MaterialTheme.typography.titleMedium)
                        LinearProgressIndicator(
                            progress = { sheet.level.toFloat().coerceIn(0f, 1f) },
                            modifier = Modifier.fillMaxWidth(),
                        )
                        Text(VoiceNotes.whileRecording(sheet.mode, "phone"),
                             style = MaterialTheme.typography.bodySmall)
                    }
                    is VoiceSheet.Making -> {
                        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                            CircularProgressIndicator()
                            Text(VoiceNotes.making(sheet.mode))
                        }
                    }
                    is VoiceSheet.Ready -> {
                        Text("${VoiceNotes.label(sheet.mode)} · ${VoiceNotes.clock(sheet.seconds)}",
                             style = MaterialTheme.typography.titleMedium)
                        Text("This is exactly what they will hear.",
                             style = MaterialTheme.typography.bodySmall)
                        Preview(sheet.path)
                    }
                }
            }
        },
        confirmButton = {
            when (sheet) {
                is VoiceSheet.Choosing, is VoiceSheet.Failed ->
                    Button(onClick = { record() }) { Text("Record") }
                is VoiceSheet.Recording ->
                    Button(onClick = { model.stopVoiceNote() }) { Text("Stop") }
                is VoiceSheet.Ready ->
                    Button(onClick = { model.sendVoiceNote(jid) }) { Text("Send") }
                is VoiceSheet.Making -> {}
            }
        },
        dismissButton = {
            if (sheet !is VoiceSheet.Making) {
                TextButton(onClick = { model.closeVoiceSheet() }) {
                    Text(if (sheet is VoiceSheet.Ready || sheet is VoiceSheet.Recording) "Discard" else "Close")
                }
            }
        },
    )

    if (explain) {
        AlertDialog(
            onDismissRequest = { explain = false },
            title = { Text("Microphone") },
            text = { Text(MicPermission.RATIONALE) },
            confirmButton = {
                TextButton(onClick = {
                    explain = false
                    launcher.launch(Manifest.permission.RECORD_AUDIO)
                }) { Text("Continue") }
            },
            dismissButton = { TextButton(onClick = { explain = false }) { Text("Not now") } },
        )
    }
    if (settings) {
        AlertDialog(
            onDismissRequest = { settings = false },
            title = { Text("Microphone") },
            text = { Text(MicPermission.PERMANENTLY_DENIED) },
            confirmButton = {
                TextButton(onClick = {
                    settings = false
                    context.startActivity(
                        Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                               Uri.fromParts("package", context.packageName, null)))
                }) { Text("Open settings") }
            },
            dismissButton = { TextButton(onClick = { settings = false }) { Text("Close") } },
        )
    }
}

/** Play the finished note. The player goes with the sheet. */
@Composable
private fun Preview(path: String) {
    var playing by remember(path) { mutableStateOf(false) }
    val player = remember(path) {
        runCatching { MediaPlayer().apply { setDataSource(path); prepare() } }.getOrNull()
    }
    DisposableEffect(player) { onDispose { player?.release() } }
    if (player == null) {
        Text("This note could not be played here; it can still be sent.",
             style = MaterialTheme.typography.bodySmall)
        return
    }
    player.setOnCompletionListener { playing = false }
    OutlinedButton(onClick = {
        if (playing) player.pause() else player.start()
        playing = !playing
    }) { Text(if (playing) "Pause" else "Play") }
}
