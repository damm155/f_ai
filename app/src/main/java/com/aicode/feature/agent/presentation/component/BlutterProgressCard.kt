package com.aicode.feature.agent.presentation.component

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.tween
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.aicode.R
import com.aicode.core.theme.Radius
import com.aicode.core.theme.Spacing
import com.aicode.core.theme.semanticColors
import com.aicode.core.ui.ExpandableChevronIcon
import com.aicode.feature.agent.domain.reverse.BlutterPhase
import com.aicode.feature.agent.domain.reverse.BlutterRoute
import com.aicode.feature.agent.domain.reverse.BlutterUiState

/**
 * Blutter 本地分析进度浮窗（输入框上方，对齐 FBox 的 LocalBlutterProgressCard）。
 *
 * **视觉与交互完全对齐 AiCode 的 [TodoDashboardBar]**（同一套任务浮窗语言）：
 * - 白底卡片：`surface.copy(0.98f)` + `outlineVariant` 1dp 边 + `Radius.lg`；
 * - 单行标题栏可点击折叠/展开，`ExpandableChevronIcon` 指示，`AnimatedVisibility` 动画；
 * - 阶段用主色胶囊徽章展示（对应 Todo 的进度胶囊）；
 * - 进行中显示细进度条；结束后显示结果摘要；右上 × 关闭（进行中=取消，结束=关闭）。
 *
 * 展开后的日志区用 `surfaceVariant` 读作终端输出，等宽字体、200dp 上限、自动滚到底。
 */
@Composable
internal fun BlutterProgressCard(
    state: BlutterUiState,
    sessionId: String,
    modifier: Modifier = Modifier,
    forceCollapse: Boolean = false,
    onDismiss: () -> Unit = {},
    onCancel: () -> Unit = {}
) {
    if (state.phase == BlutterPhase.IDLE) return
    // 按会话记忆展开状态，新会话默认收起（与 TodoDashboardBar 行为一致）
    var isExpanded by rememberSaveable(sessionId) { mutableStateOf(false) }
    val effectiveExpanded = isExpanded && !forceCollapse

    val colors = MaterialTheme.colorScheme
    val sem = MaterialTheme.semanticColors

    Surface(
        modifier = modifier
            .fillMaxWidth()
            .padding(bottom = Spacing.xs),
        shape = RoundedCornerShape(Radius.lg),
        color = colors.surface.copy(alpha = 0.98f),
        border = BorderStroke(1.dp, colors.outlineVariant)
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = Spacing.md, vertical = 8.dp)
        ) {
            // —— 单行标题栏（点击切换折叠/展开）——
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(Radius.sm))
                    .clickable(enabled = state.log.isNotBlank()) { isExpanded = !isExpanded }
                    .padding(vertical = 2.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                if (state.running) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(14.dp),
                        strokeWidth = 2.dp,
                        color = colors.primary
                    )
                } else {
                    Text(
                        text = if (state.isError) "✗" else "✓",
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.Bold,
                        color = if (state.isError) colors.error else colors.primary
                    )
                }
                Spacer(Modifier.width(Spacing.sm))

                // 阶段胶囊徽章（对应 Todo 的进度胶囊）
                Surface(
                    shape = RoundedCornerShape(4.dp),
                    color = when {
                        state.isError -> colors.errorContainer.copy(alpha = 0.6f)
                        state.finished -> colors.secondaryContainer.copy(alpha = 0.6f)
                        else -> colors.primaryContainer.copy(alpha = 0.5f)
                    }
                ) {
                    Text(
                        text = state.phase.label.ifBlank { stringResource(R.string.blutter_phase_ready) },
                        style = MaterialTheme.typography.labelSmall,
                        color = when {
                            state.isError -> colors.onErrorContainer
                            else -> colors.onSurfaceVariant
                        },
                        modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                    )
                }
                Spacer(Modifier.width(Spacing.xs))

                // 收起时显示 APK 名 · 路线 · 最近一行；展开时只留标题空间
                if (!effectiveExpanded) {
                    Text(
                        text = buildString {
                            append(state.apkName)
                            append(" · ")
                            append(routeLabel(state.route))
                            if (state.lastLine.isNotBlank()) {
                                append(" · ")
                                append(state.lastLine.takeLast(60))
                            }
                        },
                        style = MaterialTheme.typography.bodySmall,
                        color = colors.onSurfaceVariant,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.weight(1f)
                    )
                } else {
                    Spacer(Modifier.weight(1f))
                }

                ExpandableChevronIcon(
                    expanded = effectiveExpanded,
                    contentDescription = if (effectiveExpanded) {
                        stringResource(R.string.common_collapse_action)
                    } else {
                        stringResource(R.string.common_expand)
                    },
                    tint = colors.onSurfaceVariant,
                    size = 16.dp
                )

                // × 关闭：进行中=取消分析，结束=关掉浮窗
                IconButton(
                    onClick = { if (state.running) onCancel() else onDismiss() },
                    modifier = Modifier.size(20.dp)
                ) {
                    Icon(
                        imageVector = Icons.Filled.Close,
                        contentDescription = null,
                        tint = colors.onSurfaceVariant,
                        modifier = Modifier.size(14.dp)
                    )
                }
            }

            // —— 进行中的细进度条 ——
            if (state.running) {
                Spacer(Modifier.height(Spacing.xs))
                LinearProgressIndicator(
                    modifier = Modifier.fillMaxWidth(),
                    color = colors.primary,
                    trackColor = colors.surfaceVariant
                )
            }

            // —— 展开区（与 TodoDashboardBar 同款动画）——
            AnimatedVisibility(
                visible = effectiveExpanded,
                enter = fadeIn(tween(180)) + expandVertically(tween(220)),
                exit = fadeOut(tween(140)) + shrinkVertically(tween(180))
            ) {
                Column {
                    Spacer(Modifier.height(Spacing.xs))
                    Surface(
                        shape = RoundedCornerShape(Radius.sm),
                        color = colors.surfaceVariant,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text(
                            text = state.log.takeLast(8000),
                            style = MaterialTheme.typography.bodySmall,
                            fontFamily = FontFamily.Monospace,
                            color = colors.onSurfaceVariant,
                            modifier = Modifier
                                .padding(Spacing.sm)
                                .heightIn(max = 200.dp)
                                .verticalScroll(rememberScrollState())
                        )
                    }
                }
            }

            // —— 结束结果摘要（展开与否都显示）——
            if (state.finished && state.resultSummary.isNotBlank()) {
                Spacer(Modifier.height(Spacing.xs))
                Text(
                    text = state.resultSummary,
                    style = MaterialTheme.typography.bodySmall,
                    color = if (state.isError) colors.error else sem.success,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis
                )
            }
        }
    }
}

private fun routeLabel(route: BlutterRoute): String = when (route) {
    BlutterRoute.RUNNER_SO -> "内置 Runner So"
    BlutterRoute.CONTAINER_BUILD -> "容器编译"
}
