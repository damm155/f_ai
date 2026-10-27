package com.aicode.feature.agent.presentation.component

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.aicode.R
import com.aicode.core.theme.Radius
import com.aicode.core.theme.Spacing
import com.aicode.core.ui.AdaptiveModalBottomSheet
import com.aicode.feature.agent.domain.reverse.AnalysisOutputDirectory

@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun AnalysisOutputPicker(
    current: String?,
    available: List<AnalysisOutputDirectory>,
    loading: Boolean,
    error: String?,
    enabled: Boolean,
    onDismiss: () -> Unit,
    onRefresh: () -> Unit,
    onUnbind: () -> Unit,
    onPick: (String) -> Unit
) {
    AdaptiveModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = rememberModalBottomSheetState(),
        containerColor = MaterialTheme.colorScheme.surface
    ) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(horizontal = Spacing.lg).padding(bottom = Spacing.xl),
            verticalArrangement = Arrangement.spacedBy(Spacing.sm)
        ) {
            Text(stringResource(R.string.analysis_binding_action), style = MaterialTheme.typography.titleMedium)
            Text(
                text = if (current == null) stringResource(R.string.analysis_binding_none)
                else stringResource(R.string.analysis_binding_current, current),
                style = MaterialTheme.typography.bodyMedium
            )
            when {
                loading -> CircularProgressIndicator()
                error != null -> Text(
                    stringResource(R.string.analysis_binding_error, error),
                    color = MaterialTheme.colorScheme.error
                )
                available.isEmpty() -> Text(stringResource(R.string.analysis_binding_empty))
                else -> LazyColumn(
                    modifier = Modifier.fillMaxWidth().heightIn(max = 360.dp),
                    verticalArrangement = Arrangement.spacedBy(Spacing.xs)
                ) {
                    items(available, key = { it.path }) { entry ->
                        Surface(
                            modifier = Modifier.fillMaxWidth().clickable(enabled = enabled) { onPick(entry.path) },
                            shape = RoundedCornerShape(Radius.md),
                            color = if (entry.path == current) MaterialTheme.colorScheme.primaryContainer
                            else MaterialTheme.colorScheme.surface,
                            border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant)
                        ) {
                            Column(modifier = Modifier.padding(Spacing.md)) {
                                Text(entry.path, style = MaterialTheme.typography.bodyMedium)
                                Text(
                                    stringResource(
                                        if (entry.hasResults) R.string.analysis_binding_has_files
                                        else R.string.analysis_binding_no_files
                                    ),
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                        }
                    }
                }
            }
            Row(horizontalArrangement = Arrangement.spacedBy(Spacing.sm)) {
                TextButton(onClick = onRefresh, enabled = !loading) {
                    Text(stringResource(R.string.analysis_binding_refresh))
                }
                if (current != null) {
                    TextButton(onClick = onUnbind, enabled = enabled) {
                        Text(stringResource(R.string.analysis_binding_unbind))
                    }
                }
                TextButton(onClick = onDismiss) { Text(stringResource(R.string.common_cancel)) }
            }
        }
    }
}
