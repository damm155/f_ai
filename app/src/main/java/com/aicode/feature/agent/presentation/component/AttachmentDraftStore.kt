package com.aicode.feature.agent.presentation.component

import androidx.compose.runtime.mutableStateMapOf
import com.aicode.feature.agent.domain.reverse.ApkTargetKind

internal data class ApkRouteSelection(
    val attachment: PendingUploadAttachment,
    val detected: ApkTargetKind
)

internal data class AttachmentDraft(
    val attachments: List<PendingUploadAttachment> = emptyList(),
    val routeSelections: List<ApkRouteSelection> = emptyList()
)

internal class AttachmentDraftStore {
    private val drafts = mutableStateMapOf<String, AttachmentDraft>()

    operator fun get(sessionId: String?): AttachmentDraft = sessionId?.let { drafts[it] } ?: AttachmentDraft()

    fun addUpload(sessionId: String, attachment: PendingUploadAttachment, detected: ApkTargetKind?) {
        val draft = get(sessionId)
        drafts[sessionId] = if (detected == null) {
            draft.copy(attachments = (draft.attachments + attachment).distinctBy { it.containerPath })
        } else {
            draft.copy(
                routeSelections = (draft.routeSelections + ApkRouteSelection(attachment, detected))
                    .distinctBy { it.attachment.containerPath }
            )
        }
    }

    fun chooseRoute(sessionId: String, sourcePath: String, attachment: PendingUploadAttachment): Boolean {
        val draft = get(sessionId)
        if (draft.routeSelections.none { it.attachment.containerPath == sourcePath }) return false
        drafts[sessionId] = draft.copy(
            attachments = draft.attachments.filterNot { it.containerPath == attachment.containerPath } + attachment,
            routeSelections = draft.routeSelections.filterNot { it.attachment.containerPath == sourcePath }
        )
        return true
    }

    fun dismissRoute(sessionId: String, sourcePath: String) {
        val draft = get(sessionId)
        drafts[sessionId] = draft.copy(
            routeSelections = draft.routeSelections.filterNot { it.attachment.containerPath == sourcePath }
        )
    }

    fun replaceAttachments(sessionId: String, attachments: List<PendingUploadAttachment>) {
        drafts[sessionId] = get(sessionId).copy(attachments = attachments.distinctBy { it.containerPath })
    }

    fun removeAttachment(sessionId: String, path: String) {
        drafts[sessionId] = get(sessionId).copy(
            attachments = get(sessionId).attachments.filterNot { it.containerPath == path }
        )
    }

    fun consume(sessionId: String, sent: List<PendingUploadAttachment>) {
        val paths = sent.mapTo(mutableSetOf()) { it.containerPath }
        drafts[sessionId] = get(sessionId).copy(
            attachments = get(sessionId).attachments.filterNot { it.containerPath in paths }
        )
    }

    fun clear(sessionId: String) {
        drafts.remove(sessionId)
    }
}
