// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.desktop.ui

import androidx.compose.foundation.ScrollState
import androidx.compose.foundation.VerticalScrollbar
import androidx.compose.foundation.defaultScrollbarStyle
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyListScope
import androidx.compose.foundation.lazy.LazyListState
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.rememberScrollbarAdapter
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

/*
 * Scroll bars you can see and drag. Owner, 2026-10-20: "desktop app needs
 * built in scroll bar i cant get to bottom of settings". A wheel or
 * touchpad scrolled these already, but nothing showed there was more below,
 * and a touchpad without two-finger scrolling could not reach it.
 */

@Composable
private fun barStyle() = defaultScrollbarStyle().copy(
    thickness = 10.dp,
    shape = RoundedCornerShape(5.dp),
    unhoverColor = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.28f),
    hoverColor = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.55f),
)

/** A Column that scrolls, with a scroll bar on its right edge. */
@Composable
fun ScrollColumn(
    modifier: Modifier = Modifier,
    state: ScrollState = rememberScrollState(),
    verticalArrangement: Arrangement.Vertical = Arrangement.Top,
    horizontalAlignment: Alignment.Horizontal = Alignment.Start,
    content: @Composable ColumnScope.() -> Unit,
) {
    Box(modifier) {
        Column(Modifier.fillMaxSize().verticalScroll(state).padding(end = 12.dp),
               verticalArrangement = verticalArrangement, horizontalAlignment = horizontalAlignment,
               content = content)
        VerticalScrollbar(rememberScrollbarAdapter(state),
                          Modifier.align(Alignment.CenterEnd).fillMaxHeight().padding(vertical = 2.dp),
                          style = barStyle())
    }
}

/** A LazyColumn with a scroll bar on its right edge. */
@Composable
fun ScrollLazyColumn(
    modifier: Modifier = Modifier,
    state: LazyListState = rememberLazyListState(),
    verticalArrangement: Arrangement.Vertical = Arrangement.Top,
    content: LazyListScope.() -> Unit,
) {
    Box(modifier) {
        LazyColumn(Modifier.fillMaxSize().padding(end = 12.dp), state = state,
                   verticalArrangement = verticalArrangement, content = content)
        VerticalScrollbar(rememberScrollbarAdapter(state),
                          Modifier.align(Alignment.CenterEnd).fillMaxHeight().padding(vertical = 2.dp),
                          style = barStyle())
    }
}
