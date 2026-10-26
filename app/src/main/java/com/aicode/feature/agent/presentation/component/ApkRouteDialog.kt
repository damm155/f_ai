package com.aicode.feature.agent.presentation.component

import androidx.compose.foundation.BorderStroke
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
import androidx.compose.foundation.clickable
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.aicode.R
import com.aicode.core.theme.Radius
import com.aicode.core.theme.Spacing
import com.aicode.core.theme.semanticColors
import com.aicode.feature.agent.domain.reverse.ApkTargetKind

/**
 * APK 分析线路选择弹窗（对齐 FBox 的 `ApkRouteDialog`）。
 *
 * 上传 APK 后自动判定类型（见 [com.aicode.feature.agent.domain.reverse.ApkTypeDetector]），
 * 用本弹窗把结论告知用户并让其确认线路。**判定命中的那张卡片默认高亮并带「推荐」徽标**，
 * 也就是 FBox 里那圈"自动框选"的效果——它不是焦点逻辑，而是 `selected = (卡片类型 == 判定结果)`。
 *
 * 配色遵循本工程主题（`MaterialTheme.colorScheme` + [semanticColors]），
 * 未沿用 FBox 的 Cyan 硬编码色，理由见 `CLAUDE.md` 的主题硬规则。
 */
/**
 * 一次待确认的线路选择：判定结果 + 命中的附件。
 *
 * 放在 UI 层（而非 domain）是因为它绑定 Compose 状态与附件类型；
 * 判定本身在 [com.aicode.feature.agent.domain.reverse.ApkTypeDetector]。
 */
internal data class ApkRouteSelection(
    val fileName: String,
    val attachment: PendingUploadAttachment,
    val kind: ApkTargetKind
)

/** 选定线路后发给模型的路由指令：把结论与应读的技能写清楚，避免 AI 自己猜类型。 */
internal fun apkRouteInstructionText(fileName: String, kind: ApkTargetKind): String = when (kind) {
    ApkTargetKind.FLUTTER ->
        "已上传 APK「$fileName」，经检测为 Flutter 应用（libapp.so / libflutter.so / assets/flutter_assets 齐备）。" +
            "请读取 flutter-re 技能，按其流程分析该 APK。产物在 /root/out/-下；先查 /root/out 是否已有缓存结果，" +
            "有就直接读、不要重跑 aicode-blutter。"

    ApkTargetKind.NATIVE ->
        "已上传 APK「$fileName」，经检测为普通（非 Flutter）应用。" +
            "请读取 apk-re 技能，按其流程分析该 APK：AndroidManifest / DEX 查改，改动后用 aicode-apk rebuild " +
            "重打包、再用 apkSign 签名（否则产物装不上）。"
}

@Composable
internal fun ApkRouteDialog(
    fileName: String,
    detected: ApkTargetKind,
    onDismiss: () -> Unit,
    onChoose: (ApkTargetKind) -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = MaterialTheme.colorScheme.surface,
        tonalElevation = 0.dp,
        title = { Text(text = stringResource(R.string.apk_route_dialog_title)) },
        text = {
            Column(modifier = Modifier.fillMaxWidth()) {
                Text(
                    text = fileName,
                    style = MaterialTheme.typography.labelLarge,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(modifier = Modifier.height(Spacing.xs))
                Text(
                    text = stringResource(
                        if (detected == ApkTargetKind.FLUTTER) {
                            R.string.apk_route_flutter_detected
                        } else {
                            R.string.apk_route_native_detected
                        }
                    ),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.semanticColors.subtleText
                )
                Spacer(modifier = Modifier.height(Spacing.md))
                Column(verticalArrangement = Arrangement.spacedBy(Spacing.sm)) {
                    RouteOptionCard(
                        title = stringResource(R.string.apk_route_flutter_title),
                        description = stringResource(R.string.apk_route_flutter_desc),
                        selected = detected == ApkTargetKind.FLUTTER,
                        onClick = { onChoose(ApkTargetKind.FLUTTER) }
                    )
                    RouteOptionCard(
                        title = stringResource(R.string.apk_route_native_title),
                        description = stringResource(R.string.apk_route_native_desc),
                        selected = detected == ApkTargetKind.NATIVE,
                        onClick = { onChoose(ApkTargetKind.NATIVE) }
                    )
                }
            }
        },
        // 两张卡片自身就是操作入口，故不设 confirmButton，只留取消。
        confirmButton = {},
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.common_cancel)) }
        }
    )
}

/**
 * 线路选项卡片。[selected] 为真时=判定结果=推荐项：主色描边 + 主色容器底 + 「推荐」徽标。
 */
@Composable
private fun RouteOptionCard(
    title: String,
    description: String,
    selected: Boolean,
    onClick: () -> Unit
) {
    val colors = MaterialTheme.colorScheme
    Surface(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(role = Role.Button, onClick = onClick),
        shape = RoundedCornerShape(Radius.mdLarge),
        color = if (selected) colors.primaryContainer else colors.surface,
        border = BorderStroke(
            width = if (selected) 2.dp else 1.dp,
            color = if (selected) colors.primary else colors.outlineVariant
        )
    ) {
        Column(modifier = Modifier.padding(horizontal = Spacing.md, vertical = Spacing.sm)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = title,
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold,
                    color = if (selected) colors.onPrimaryContainer else colors.onSurface
                )
                if (selected) {
                    Spacer(modifier = Modifier.width(Spacing.sm))
                    Surface(
                        shape = RoundedCornerShape(Radius.pill),
                        color = colors.primary
                    ) {
                        Text(
                            text = stringResource(R.string.apk_route_recommended),
                            style = MaterialTheme.typography.labelSmall,
                            color = colors.onPrimary,
                            modifier = Modifier.padding(horizontal = Spacing.sm, vertical = 2.dp)
                        )
                    }
                }
            }
            Spacer(modifier = Modifier.height(Spacing.xs))
            Text(
                text = description,
                style = MaterialTheme.typography.bodySmall,
                color = if (selected) colors.onPrimaryContainer else MaterialTheme.semanticColors.subtleText
            )
        }
    }
}
