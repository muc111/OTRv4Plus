// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.ui

import android.Manifest
import android.annotation.SuppressLint
import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.location.LocationListener
import android.location.LocationManager
import android.net.Uri
import android.os.Build
import android.os.CancellationSignal
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
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
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import org.otrv4plus.android.chat.ChatViewModel
import org.otrv4plus.android.chat.Location
import org.otrv4plus.android.crypto.MicPermission

/**
 * One position from the GPS RECEIVER only.
 *
 * Never the network or fused provider: those can send nearby Wi-Fi and cell
 * identifiers to Google to work out where the phone is. GPS only listens to
 * satellites. Slower, and best outdoors -- said on screen.
 */
object GpsFix {
    const val TIMEOUT_MS = 90_000L

    fun enabled(context: Context): Boolean = runCatching {
        context.getSystemService(LocationManager::class.java)
            ?.isProviderEnabled(LocationManager.GPS_PROVIDER) == true
    }.getOrDefault(false)

    /** Ask for one fix; [done] runs once, on the main thread. Returns cancel. */
    @SuppressLint("MissingPermission")    // checked by the caller
    fun request(context: Context, done: (Location.Pin?, String?) -> Unit): () -> Unit {
        val lm = context.getSystemService(LocationManager::class.java)
            ?: run { done(null, "This device has no location service."); return {} }
        if (!enabled(context)) {
            done(null, "GPS is switched off. Turn on Location, or type a Plus Code.")
            return {}
        }
        val main = Handler(Looper.getMainLooper())
        var finished = false
        fun finish(fix: android.location.Location?) {
            if (finished) return
            finished = true
            if (fix == null) done(null, "No GPS fix in 90 seconds. Try outdoors, or type a Plus Code.")
            else done(Location.Pin(fix.latitude, fix.longitude,
                                   if (fix.hasAccuracy()) fix.accuracy.toDouble() else null), null)
        }
        val timeout = Runnable { finish(null) }
        main.postDelayed(timeout, TIMEOUT_MS)
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            val signal = CancellationSignal()
            lm.getCurrentLocation(LocationManager.GPS_PROVIDER, signal, context.mainExecutor) { fix ->
                main.removeCallbacks(timeout)
                finish(fix)
            }
            ({ finished = true; main.removeCallbacks(timeout); signal.cancel() })
        } else {
            val listener = object : LocationListener {
                override fun onLocationChanged(location: android.location.Location) {
                    main.removeCallbacks(timeout)
                    lm.removeUpdates(this)
                    finish(location)
                }
                @Deprecated("Deprecated in Java")
                override fun onStatusChanged(provider: String?, status: Int, extras: android.os.Bundle?) {}
                override fun onProviderEnabled(provider: String) {}
                override fun onProviderDisabled(provider: String) {}
            }
            @Suppress("DEPRECATION")
            lm.requestSingleUpdate(LocationManager.GPS_PROVIDER, listener, Looper.getMainLooper())
            ({ finished = true; main.removeCallbacks(timeout); lm.removeUpdates(listener) })
        }
    }
}

/** Share a pin: GPS (satellites only) or a typed Plus Code / coordinates. */
@Composable
fun LocationSheet(model: ChatViewModel) {
    model.locationFor ?: return
    val context = LocalContext.current
    var askedBefore by rememberSaveable { mutableStateOf(false) }
    var settings by rememberSaveable { mutableStateOf(false) }
    val cancel = remember { arrayOfNulls<() -> Unit>(1) }
    DisposableEffect(Unit) { onDispose { cancel[0]?.invoke() } }

    fun startGps() {
        model.gpsStarted()
        cancel[0] = GpsFix.request(context) { pin, failure -> model.gpsFinished(pin, failure) }
    }

    val launcher = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { ok ->
        askedBefore = true
        if (ok) startGps() else model.gpsFinished(null, "Location permission was refused; type a Plus Code instead.")
    }

    fun useGps() {
        val granted = ContextCompat.checkSelfPermission(context, Manifest.permission.ACCESS_FINE_LOCATION) ==
            PackageManager.PERMISSION_GRANTED
        if (granted) { startGps(); return }
        val rationale = (context as? Activity)?.let {
            ActivityCompat.shouldShowRequestPermissionRationale(it, Manifest.permission.ACCESS_FINE_LOCATION)
        } ?: false
        // The same decision table as the microphone: ask, or point to Settings
        // once Android will no longer show the dialog.
        when (MicPermission.decide(MicPermission.State(false, rationale, askedBefore))) {
            MicPermission.Decision.OpenSettings -> settings = true
            MicPermission.Decision.Proceed -> startGps()
            else -> launcher.launch(Manifest.permission.ACCESS_FINE_LOCATION)
        }
    }

    val allowed = model.canShareLocation(model.locationFor ?: "")
    AlertDialog(
        onDismissRequest = { cancel[0]?.invoke(); model.closeLocation() },
        title = { Text("Share a location") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text("Sent encrypted, as a Plus Code and coordinates. Nothing is looked up online.",
                     style = MaterialTheme.typography.bodySmall)
                Text(Location.SET_HINT, style = MaterialTheme.typography.bodySmall,
                     color = MaterialTheme.colorScheme.onSurfaceVariant)
                OutlinedButton(onClick = { useGps() }, enabled = allowed && !model.gpsBusy,
                               modifier = Modifier.fillMaxWidth()) {
                    Text(if (model.gpsBusy) "Finding satellites…" else "Use my position (GPS only)")
                }
                OutlinedTextField(
                    value = model.locationText,
                    onValueChange = { model.typeLocation(it) },
                    enabled = allowed,
                    singleLine = true,
                    label = { Text("Plus Code or coordinates") },
                    modifier = Modifier.fillMaxWidth(),
                )
                model.locationPin?.let { pin ->
                    Text("${pin.code}  ·  ${Location.coordinates(pin)}" +
                         (Location.accuracy(pin)?.let { "  ·  $it" } ?: ""),
                         fontFamily = FontFamily.Monospace,
                         style = MaterialTheme.typography.bodySmall)
                }
                model.locationStatus?.let {
                    Text(it, style = MaterialTheme.typography.bodySmall,
                         color = if (model.gpsBusy) MaterialTheme.colorScheme.onSurfaceVariant
                                 else MaterialTheme.colorScheme.error)
                }
            }
        },
        confirmButton = {
            Button(onClick = { cancel[0]?.invoke(); model.sendLocation() },
                   enabled = allowed && model.locationPin != null) { Text("Send") }
        },
        dismissButton = {
            TextButton(onClick = { cancel[0]?.invoke(); model.closeLocation() }) { Text("Cancel") }
        },
    )
    if (settings) {
        AlertDialog(
            onDismissRequest = { settings = false },
            title = { Text("Location") },
            text = { Text("Location permission was refused. It can be allowed in Settings, " +
                          "or type a Plus Code instead.") },
            confirmButton = {
                TextButton(onClick = {
                    settings = false
                    context.startActivity(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                                                 Uri.fromParts("package", context.packageName, null)))
                }) { Text("Open settings") }
            },
            dismissButton = { TextButton(onClick = { settings = false }) { Text("Close") } },
        )
    }
}

/** A received or sent pin, in a bubble. */
@Composable
fun LocationCard(pin: Location.Pin) {
    val context = LocalContext.current
    var confirmOpen by remember { mutableStateOf(false) }
    Surface(color = MaterialTheme.colorScheme.surfaceVariant, shape = MaterialTheme.shapes.small) {
        Column(Modifier.padding(10.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(Location.MARKER, style = MaterialTheme.typography.labelLarge)
            Text(pin.code, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.titleMedium)
            Text(Location.coordinates(pin) + (Location.accuracy(pin)?.let { "  $it" } ?: ""),
                 fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
            Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                TextButton(onClick = {
                    context.getSystemService(ClipboardManager::class.java)?.setPrimaryClip(
                        ClipData.newPlainText("Plus Code", "${pin.code} (${Location.coordinates(pin)})"))
                }) { Text("Copy") }
                TextButton(onClick = { confirmOpen = true }) { Text("Open in maps app") }
            }
        }
    }
    if (confirmOpen) {
        AlertDialog(
            onDismissRequest = { confirmOpen = false },
            title = { Text("Open in another app?") },
            text = { Text(Location.OPEN_WARNING) },
            confirmButton = {
                TextButton(onClick = {
                    confirmOpen = false
                    runCatching {
                        context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(Location.geoUri(pin))))
                    }
                }) { Text("Open") }
            },
            dismissButton = { TextButton(onClick = { confirmOpen = false }) { Text("Cancel") } },
        )
    }
}
