// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.ui

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.otrv4plus.android.BuildConfig

/**
 * About, and the third-party licences.
 *
 * This screen exists because of a distribution obligation, not because an
 * about box is conventional. Every third-party component in this build is
 * permissive — MIT, Apache-2.0, BSD-3-Clause, PSF — and every one of those
 * licences requires its notice to travel with the binary. NOTICE is that file;
 * shipping an APK without rendering it anywhere leaves the obligation
 * undischarged. `LICENSING_AUDIT.md` lists this as the last open delivery
 * requirement, and this screen is it.
 *
 * It also carries what AGPL §5(d) calls Appropriate Legal Notices: the
 * copyright line, the absence of warranty, which licence applies, and where to
 * get the source. Everything here is a POINTER to terms that exist in the
 * repository — LICENSE and LICENSE-COMMERCIAL.md are authoritative. No term is
 * stated here that is not stated there, and nothing on this screen grants
 * anything.
 *
 * NOTICE is read from the APK's assets, where :app:syncNoticeAsset put it. It
 * is about 60 KB, so it is read on [Dispatchers.IO] and rendered as a lazy
 * list of lines rather than one enormous Text — a single composable with 1100
 * lines of monospace in it janks on a mid-range handset.
 */
@Composable
fun AboutScreen(onBack: () -> Unit = {}) {
    val context = LocalContext.current
    var notice by remember { mutableStateOf<List<String>?>(null) }
    var noticeError by remember { mutableStateOf<String?>(null) }
    var showNotice by remember { mutableStateOf(false) }

    LaunchedEffect(Unit) {
        val loaded = withContext(Dispatchers.IO) {
            runCatching {
                context.assets.open("NOTICE").use { stream ->
                    stream.reader(Charsets.UTF_8).readText().split("\n")
                }
            }
        }
        loaded.onSuccess { notice = it }
            .onFailure {
                // Say so rather than showing an empty screen. An APK whose
                // NOTICE did not get packaged is a build defect worth seeing.
                noticeError = it.javaClass.simpleName
            }
    }

    if (showNotice) {
        // MainActivity owns back between destinations; this one only unwinds
        // the notices list back to the about page.
        BackHandler { showNotice = false }
        NoticeList(
            lines = notice.orEmpty(),
            onBack = { showNotice = false },
        )
        return
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            // The window no longer fits the decor -- MainActivity turns that
            // off so the keyboard is handled by exactly one mechanism -- so
            // every screen that is not a Scaffold has to inset itself. Without
            // this the title sits under the status bar and the last control
            // sits under the navigation bar.
            .systemBarsPadding()
            .verticalScroll(rememberScrollState())
            .padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("About OTRv4+", style = MaterialTheme.typography.headlineMedium)

        StatusRow("Version", BuildConfig.VERSION_NAME)
        StatusRow("Build", BuildConfig.BUILD_ID)

        Spacer(Modifier.height(4.dp))
        Text("Licence", style = MaterialTheme.typography.titleSmall)
        Text(
            "Copyright (C) 2025-2026 muc111.",
            style = MaterialTheme.typography.bodySmall,
        )
        Text(
            "OTRv4+ is dual-licensed. You receive it under the GNU Affero " +
                "General Public License version 3 (see the LICENSE file in " +
                "the source repository), or under a separate commercial " +
                "licence from the copyright holder (LICENSE-COMMERCIAL.md).",
            style = MaterialTheme.typography.bodySmall,
        )
        Text(
            "Releases up to and including v10.16.2 were published under the " +
                "GNU General Public License version 3. Those releases remain " +
                "available under that licence; the change applies from " +
                "v10.17.0 onward and withdraws nothing already granted.",
            style = MaterialTheme.typography.bodySmall,
        )
        Text(
            "This program comes with ABSOLUTELY NO WARRANTY, to the extent " +
                "permitted by applicable law. It is free software, and you " +
                "are welcome to redistribute it under the conditions the " +
                "AGPL sets out.",
            style = MaterialTheme.typography.bodySmall,
        )

        Spacer(Modifier.height(4.dp))
        Text("Source", style = MaterialTheme.typography.titleSmall)
        // AGPL §13: a user interacting with a modified version over a network
        // must be offered that version's source. Naming where the source is
        // kept is the first half of satisfying that; anyone who modifies and
        // deploys this owes their users the same for their version.
        SelectionContainer {
            Text(
                "https://github.com/muc111/OTRv4Plus",
                style = MaterialTheme.typography.bodySmall,
            )
        }

        Spacer(Modifier.height(4.dp))
        Text("Third-party software", style = MaterialTheme.typography.titleSmall)
        Text(
            "This app includes components from other projects, all of them " +
                "under permissive licences. Their notices are reproduced in " +
                "full.",
            style = MaterialTheme.typography.bodySmall,
        )

        when {
            noticeError != null -> Text(
                "The third-party notices could not be read from this build " +
                    "($noticeError). That is a packaging fault in the APK, " +
                    "not a missing licence — please report it.",
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodySmall,
            )

            notice == null -> {
                CircularProgressIndicator()
                Text("Loading notices...",
                    style = MaterialTheme.typography.bodySmall)
            }

            else -> Button(onClick = { showNotice = true }) {
                Text("Open third-party notices")
            }
        }

        Spacer(Modifier.height(8.dp))
        TextButton(onClick = onBack) { Text("Back") }
    }
}

/**
 * NOTICE itself, one line per row.
 *
 * Monospace because the generated file is column-aligned, and selectable
 * because the point of an attribution screen is that someone can copy what it
 * says.
 */
@Composable
private fun NoticeList(lines: List<String>, onBack: () -> Unit) {
    Column(Modifier.fillMaxSize().padding(horizontal = 16.dp)) {
        Row(
            Modifier.fillMaxWidth().padding(vertical = 8.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Text("Third-party notices",
                style = MaterialTheme.typography.titleMedium)
            TextButton(onClick = onBack) { Text("Back") }
        }
        SelectionContainer(Modifier.weight(1f)) {
            LazyColumn {
                items(lines) { line ->
                    Text(
                        line,
                        style = MaterialTheme.typography.bodySmall
                            .copy(fontFamily = FontFamily.Monospace),
                    )
                }
            }
        }
    }
}
