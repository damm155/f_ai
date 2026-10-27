package com.aicode.feature.agent.presentation.component

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.aicode.R
import com.aicode.core.theme.Radius
import com.aicode.core.theme.Spacing
import com.aicode.core.theme.semanticColors
import com.aicode.feature.agent.domain.reverse.ApkTargetKind

@Composable
internal fun ApkRouteDialog(
    fileName: String,
    detected: ApkTargetKind,
    enabled: Boolean,
    onDismiss: () -> Unit,
    onChoose: (ApkTargetKind) -> Unit
) {
    AlertDialog(
        onDismissRequest = { if (enabled) onDismiss() },
        containerColor = MaterialTheme.colorScheme.surface,
        tonalElevation = 0.dp,
        title = { Text(stringResource(R.string.apk_route_dialog_title)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(Spacing.sm)) {
                Text(fileName, style = MaterialTheme.typography.labelLarge)
                Text(
                    stringResource(
                        if (detected == ApkTargetKind.FLUTTER) R.string.apk_route_flutter_detected
                        else R.string.apk_route_native_detected
                    ),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.semanticColors.subtleText
                )
                RouteOptionCard(
                    title = stringResource(R.string.apk_route_flutter_title),
                    description = stringResource(R.string.apk_route_flutter_desc),
                    selected = detected == ApkTargetKind.FLUTTER,
                    enabled = enabled,
                    onClick = { onChoose(ApkTargetKind.FLUTTER) }
                )
                RouteOptionCard(
                    title = stringResource(R.string.apk_route_native_title),
                    description = stringResource(R.string.apk_route_native_desc),
                    selected = detected == ApkTargetKind.NATIVE,
                    enabled = enabled,
                    onClick = { onChoose(ApkTargetKind.NATIVE) }
                )
                if (!enabled) {
                    Text(stringResource(R.string.apk_route_staging), style = MaterialTheme.typography.bodySmall)
                }
            }
        },
        confirmButton = {},
        dismissButton = {
            TextButton(onClick = onDismiss, enabled = enabled) {
                Text(stringResource(R.string.common_cancel))
            }
        }
    )
}

@Composable
private fun RouteOptionCard(
    title: String,
    description: String,
    selected: Boolean,
    enabled: Boolean,
    onClick: () -> Unit
) {
    val colors = MaterialTheme.colorScheme
    Surface(
        modifier = Modifier.fillMaxWidth().clickable(enabled = enabled, role = Role.Button, onClick = onClick),
        shape = RoundedCornerShape(Radius.mdLarge),
        color = if (selected) colors.primaryContainer else colors.surface,
        border = BorderStroke(if (selected) 2.dp else 1.dp, if (selected) colors.primary else colors.outlineVariant)
    ) {
        Column(modifier = Modifier.padding(horizontal = Spacing.md, vertical = Spacing.sm)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    title,
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold,
                    color = if (selected) colors.onPrimaryContainer else colors.onSurface
                )
                if (selected) {
                    Spacer(Modifier.width(Spacing.sm))
                    Text(
                        stringResource(R.string.apk_route_recommended),
                        style = MaterialTheme.typography.labelSmall,
                        color = colors.primary
                    )
                }
            }
            Spacer(Modifier.height(Spacing.xs))
            Text(
                description,
                style = MaterialTheme.typography.bodySmall,
                color = if (selected) colors.onPrimaryContainer else MaterialTheme.semanticColors.subtleText
            )
        }
    }
}
