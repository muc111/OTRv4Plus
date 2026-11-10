// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.ui

import android.content.Context
import android.os.Build
import android.text.InputType
import android.text.method.PasswordTransformationMethod
import android.view.ActionMode
import android.view.Menu
import android.view.MenuItem
import android.view.View
import android.view.inputmethod.EditorInfo
import android.widget.EditText
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.otrv4plus.android.security.AppLock
import org.otrv4plus.android.security.AutoLock
import org.otrv4plus.android.security.Passphrase
import org.otrv4plus.android.security.SecurityLevel

/**
 * A passphrase box that never makes a String (docs/APP_LOCK_PASSPHRASE.md,
 * "Typing"). A plain EditText rather than a Compose text field, whose state
 * IS a String: the characters stay in the widget's char buffer and [take]
 * copies them into a CharArray and clears the widget. The keyboard is told
 * it is a password, not to learn from it, and autofill is off.
 */
class PassphraseInput {
    internal var view: EditText? = null

    /** The typed characters, and the box emptied. The caller zeroes them. */
    fun take(): CharArray {
        val text = view?.text ?: return CharArray(0)
        val out = CharArray(text.length)
        text.getChars(0, text.length, out, 0)
        text.clear()
        return out
    }

    fun clear() { view?.text?.clear() }

    val isEmpty: Boolean get() = (view?.text?.length ?: 0) == 0
}

@Composable
fun PassphraseField(input: PassphraseInput, hint: String, onDone: () -> Unit = {}, onChange: () -> Unit = {}) {
    val text = MaterialTheme.colorScheme.onSurface.toArgb()
    val faint = MaterialTheme.colorScheme.onSurfaceVariant.toArgb()
    AndroidView(
        modifier = Modifier.fillMaxWidth(),
        factory = { context -> passphraseBox(context, onDone, onChange).also { input.view = it } },
        update = { box ->
            box.hint = hint
            box.setTextColor(text)
            box.setHintTextColor(faint)
        },
        onRelease = { box -> box.text?.clear(); if (input.view === box) input.view = null },
    )
}

private fun passphraseBox(context: Context, onDone: () -> Unit, onChange: () -> Unit) = EditText(context).apply {
    inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
    transformationMethod = PasswordTransformationMethod.getInstance()
    imeOptions = EditorInfo.IME_ACTION_DONE or EditorInfo.IME_FLAG_NO_EXTRACT_UI or
        EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING
    setSingleLine(true)
    if (Build.VERSION.SDK_INT >= 26) importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
    // No copy, cut or share of what was typed.
    isLongClickable = false
    setTextIsSelectable(false)
    customSelectionActionModeCallback = object : ActionMode.Callback {
        override fun onCreateActionMode(mode: ActionMode?, menu: Menu?) = false
        override fun onPrepareActionMode(mode: ActionMode?, menu: Menu?) = false
        override fun onActionItemClicked(mode: ActionMode?, item: MenuItem?) = false
        override fun onDestroyActionMode(mode: ActionMode?) {}
    }
    setOnEditorActionListener { _, action, _ ->
        if (action == EditorInfo.IME_ACTION_DONE) { onDone(); true } else false
    }
    addTextChangedListener(object : android.text.TextWatcher {
        override fun beforeTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}
        override fun onTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}
        override fun afterTextChanged(s: android.text.Editable?) = onChange()
    })
}

/** The screen a locked app shows, and nothing else. */
@Composable
fun UnlockScreen(onUnlocked: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val input = remember { PassphraseInput() }
    var busy by remember { mutableStateOf(false) }
    var message by remember { mutableStateOf<String?>(null) }
    val device = remember { AppLock.mode(context) == AppLock.Mode.DEVICE }

    fun submit() {
        if (busy || input.isEmpty) return
        val chars = input.take()
        busy = true
        message = null
        scope.launch {
            val outcome = withContext(Dispatchers.Default) { AppLock.unlock(context, chars) }
            busy = false
            when (outcome) {
                AppLock.Outcome.Ok -> onUnlocked()
                AppLock.Outcome.Wrong -> message = "That passphrase is not right."
                is AppLock.Outcome.Wait -> message =
                    "Too many wrong tries. Wait ${(outcome.millis + 999) / 1000} s and try again."
                is AppLock.Outcome.Failed -> message = outcome.why
            }
        }
    }

    Column(
        Modifier.fillMaxSize().safeDrawingPadding().imePadding().padding(24.dp)
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(16.dp, Alignment.CenterVertically),
    ) {
        Text("OTRv4+ is locked", style = MaterialTheme.typography.headlineSmall)
        if (device) {
            Text("This phone's key store did not open the app's data. Restart the app; if " +
                 "this stays, the data cannot be opened on this phone.",
                 color = MaterialTheme.colorScheme.error)
            return@Column
        }
        Text("Enter your passphrase. Nothing on this phone can be read without it.",
             style = MaterialTheme.typography.bodyMedium)
        PassphraseField(input, "Passphrase", onDone = ::submit)
        Button(onClick = ::submit, enabled = !busy, modifier = Modifier.fillMaxWidth()) {
            Text(if (busy) "Unlocking…" else "Unlock")
        }
        if (busy) LinearProgressIndicator(Modifier.fillMaxWidth())
        message?.let { Text(it, color = MaterialTheme.colorScheme.error) }
        Text("A forgotten passphrase cannot be recovered. To start again without it, clear " +
             "this app's storage in Android's settings: everything on this phone is lost.",
             style = MaterialTheme.typography.bodySmall,
             color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

/** Settings → App lock, on our own profile. [onLockNow] covers the screen
 *  and locks (MainActivity.lockNow). */
@Composable
fun AppLockSection(onLockNow: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var mode by remember { mutableStateOf(AppLock.mode(context)) }
    var autoLock by remember { mutableStateOf(AppLock.autoLock(context)) }
    var dialog by remember { mutableStateOf<String?>(null) }   // "on", "change", "off"
    var status by remember { mutableStateOf<String?>(null) }
    val on = mode == AppLock.Mode.PASSPHRASE

    HorizontalDivider()
    Text("App lock", style = MaterialTheme.typography.titleMedium)
    Text(
        if (on) "On. Everything stored on this phone is under a 256-bit key that your " +
            "passphrase and this phone's ${levelName(AppLock.securityLevel())} unlock together. " +
            "Locking signs you out: no messages or notifications arrive until you unlock."
        else "Off. Set a passphrase to lock the app: your chats, keys and files on this phone " +
            "then open only with it. Locking signs you out, as Molly does.",
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
    if (on) {
        Text("Lock after the app is in the background for", style = MaterialTheme.typography.bodyMedium)
        Column {
            for (choice in AutoLock.entries) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    RadioButton(selected = autoLock == choice, onClick = {
                        autoLock = choice
                        AppLock.setAutoLock(context, choice)
                    })
                    Text(choice.label)
                }
            }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = onLockNow) { Text("Lock now") }
            OutlinedButton(onClick = { dialog = "change" }) { Text("Change passphrase…") }
        }
        TextButton(onClick = { dialog = "off" }) { Text("Turn off the app lock…") }
    } else {
        OutlinedButton(onClick = { dialog = "on" }) { Text("Set a passphrase…") }
    }
    status?.let { Text(it, style = MaterialTheme.typography.bodySmall) }

    dialog?.let { which ->
        PassphraseDialog(
            which = which,
            onDismiss = { dialog = null },
            onSubmit = { current, new, again, done ->
                val problem = if (which == "off") null else Passphrase.problem(new, again)
                again.fill('\u0000')
                if (problem != null) {
                    current.fill('\u0000'); new.fill('\u0000')
                    done(problem)
                    return@PassphraseDialog
                }
                scope.launch {
                    val error = withContext(Dispatchers.Default) {
                        when (which) {
                            "on" -> { current.fill('\u0000'); AppLock.enable(context, new) }
                            "change" -> AppLock.change(context, current, new)
                            else -> { new.fill('\u0000'); AppLock.disable(context, current) }
                        }
                    }
                    done(error)
                    if (error == null) {
                        dialog = null
                        mode = AppLock.mode(context)
                        status = when (which) {
                            "on" -> "The app lock is on."
                            "change" -> "The passphrase is changed."
                            else -> "The app lock is off."
                        }
                    }
                }
            },
        )
    }
}

@Composable
private fun PassphraseDialog(
    which: String,
    onDismiss: () -> Unit,
    onSubmit: (current: CharArray, new: CharArray, again: CharArray, done: (String?) -> Unit) -> Unit,
) {
    val current = remember { PassphraseInput() }
    val new = remember { PassphraseInput() }
    val again = remember { PassphraseInput() }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    val title = when (which) {
        "on" -> "Set a passphrase"
        "change" -> "Change the passphrase"
        else -> "Turn off the app lock"
    }
    AlertDialog(
        onDismissRequest = { if (!busy) onDismiss() },
        title = { Text(title) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                when (which) {
                    "on" -> Text("At least ${Passphrase.MIN_LENGTH} characters; a long phrase " +
                        "of several words is best. THERE IS NO RECOVERY: if you forget it, " +
                        "everything on this phone is lost.", style = MaterialTheme.typography.bodySmall)
                    "off" -> Text("The data stays encrypted under this phone's key store, as " +
                        "before the lock, and the app opens without a passphrase.",
                        style = MaterialTheme.typography.bodySmall)
                }
                if (which != "on") PassphraseField(current, "Current passphrase")
                if (which != "off") {
                    PassphraseField(new, "New passphrase")
                    PassphraseField(again, "New passphrase again")
                }
                if (busy) LinearProgressIndicator(Modifier.fillMaxWidth())
                error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
            }
        },
        confirmButton = {
            Button(enabled = !busy, onClick = {
                busy = true
                error = null
                onSubmit(current.take(), new.take(), again.take()) { problem ->
                    busy = false
                    error = problem
                }
            }) { Text(if (which == "off") "Turn off" else "Save") }
        },
        dismissButton = { TextButton(enabled = !busy, onClick = onDismiss) { Text("Cancel") } },
    )
}

private fun levelName(level: SecurityLevel): String = when (level) {
    SecurityLevel.STRONGBOX -> "StrongBox security chip"
    SecurityLevel.HARDWARE_TEE -> "secure hardware (TEE)"
    SecurityLevel.KEYSTORE_SOFTWARE -> "key store (software only on this phone)"
    SecurityLevel.SOFTWARE_ONLY -> "key store"
}
