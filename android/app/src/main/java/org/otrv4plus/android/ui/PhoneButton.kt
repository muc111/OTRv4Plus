// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.material3.FilledIconButton
import androidx.compose.material3.IconButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import org.otrv4plus.android.crypto.CallUi

/**
 * The call button, the same for a contact and a secure group: a phone whose
 * colour says whether the call's I2P path is already built -- red (built on
 * tap, 30-120 s), amber (being built), green (ready: the call starts at
 * once). Owner request, 2026-10-15. Disabled (grey) with the reason beside
 * it when no call can be made here.
 */
@Composable
fun PhoneButton(
    readiness: CallUi.Readiness,
    secondsLeft: Int,
    enabled: Boolean,
    disabledReason: String = "",
    description: String = "Call",
    onClick: () -> Unit,
) {
    val colour = Color(CallUi.readinessColour(readiness))
    Row(verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        FilledIconButton(
            onClick = onClick,
            enabled = enabled,
            colors = IconButtonDefaults.filledIconButtonColors(
                containerColor = colour, contentColor = Color.White),
        ) {
            PhoneIcon(contentDescription = description)
        }
        Text(if (enabled) CallUi.readinessLabel(readiness, secondsLeft) else disabledReason,
             style = MaterialTheme.typography.labelMedium,
             color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}
