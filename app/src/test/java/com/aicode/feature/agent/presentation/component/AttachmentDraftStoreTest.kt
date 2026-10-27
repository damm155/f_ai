package com.aicode.feature.agent.presentation.component

import com.aicode.feature.agent.domain.reverse.ApkTargetKind
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AttachmentDraftStoreTest {
    private fun apk(name: String = "sample.apk") = PendingUploadAttachment(
        fileName = name,
        containerPath = "/root/uploads/$name",
        localPath = "/data/project/.aicode/attachments/$name",
        mimeType = "application/vnd.android.package-archive",
        sizeBytes = 128
    )

    @Test
    fun detectionOnlyQueuesChoiceAndDoesNotAttachOrSend() {
        val store = AttachmentDraftStore()
        store.addUpload("a", apk(), ApkTargetKind.NATIVE)
        assertTrue(store["a"].attachments.isEmpty())
        assertEquals(1, store["a"].routeSelections.size)
        assertEquals(ApkTargetKind.NATIVE, store["a"].routeSelections.single().detected)
    }

    @Test
    fun explicitSelectionOverridesDetectionAndSurvivesSessionSwitches() {
        val store = AttachmentDraftStore()
        val upload = apk()
        store.addUpload("a", upload, ApkTargetKind.FLUTTER)
        val selected = upload.copy(containerPath = "/root/apk/sample.apk", apkKind = ApkTargetKind.NATIVE)
        assertTrue(store.chooseRoute("a", upload.containerPath, selected))
        assertTrue(store["a"].routeSelections.isEmpty())
        assertTrue(store["b"].attachments.isEmpty())
        assertEquals(listOf(selected), store["a"].attachments)
    }

    @Test
    fun sendConsumesOnlySentAttachmentsOnceAndKeepsOtherSession() {
        val store = AttachmentDraftStore()
        val upload = apk()
        val selected = upload.copy(apkKind = ApkTargetKind.NATIVE)
        store.addUpload("a", upload, ApkTargetKind.NATIVE)
        store.chooseRoute("a", upload.containerPath, selected)
        store.addUpload("b", apk("second.apk"), ApkTargetKind.NATIVE)
        store.consume("a", store["a"].attachments)
        assertTrue(store["a"].attachments.isEmpty())
        assertEquals(1, store["b"].routeSelections.size)
        store.consume("a", listOf(selected))
        assertTrue(store["a"].attachments.isEmpty())
    }

    @Test
    fun cancellingOneChoiceDoesNotDropOtherUploads() {
        val store = AttachmentDraftStore()
        val first = apk()
        val second = apk("second.apk")
        store.addUpload("a", first, ApkTargetKind.NATIVE)
        store.addUpload("a", second, ApkTargetKind.FLUTTER)
        store.dismissRoute("a", first.containerPath)
        assertEquals(listOf(second), store["a"].routeSelections.map { it.attachment })
        assertTrue(store["a"].attachments.isEmpty())
        assertFalse(store.chooseRoute("a", first.containerPath, first.copy(apkKind = ApkTargetKind.NATIVE)))
    }

    @Test
    fun nonApkGoesStraightToPendingAndIsUnaffectedByApkSelection() {
        val store = AttachmentDraftStore()
        val log = apk("log.txt").copy(mimeType = "text/plain")
        store.addUpload("a", log, null)
        store.addUpload("a", apk(), ApkTargetKind.NATIVE)
        store.dismissRoute("a", apk().containerPath)
        assertEquals(listOf(log), store["a"].attachments)
    }

    @Test
    fun repeatedSelectionDoesNotAttachSamePathTwice() {
        val store = AttachmentDraftStore()
        val upload = apk()
        val selected = upload.copy(apkKind = ApkTargetKind.NATIVE)
        repeat(2) {
            store.addUpload("a", upload, ApkTargetKind.NATIVE)
            store.chooseRoute("a", upload.containerPath, selected)
        }
        assertEquals(listOf(selected), store["a"].attachments)
        store.removeAttachment("a", selected.containerPath)
        assertTrue(store["a"].attachments.isEmpty())
    }

    @Test
    fun choosingAnAttachedPathAgainUsesTheLatestUserChoice() {
        val store = AttachmentDraftStore()
        val upload = apk()
        store.replaceAttachments("a", listOf(upload.copy(apkKind = ApkTargetKind.FLUTTER)))
        store.addUpload("a", upload, ApkTargetKind.FLUTTER)
        store.chooseRoute("a", upload.containerPath, upload.copy(apkKind = ApkTargetKind.NATIVE))
        assertEquals(1, store["a"].attachments.size)
        assertEquals(ApkTargetKind.NATIVE, store["a"].attachments.single().apkKind)
    }

    @Test
    fun deletingSessionClearsAttachmentsAndUnconfirmedChoices() {
        val store = AttachmentDraftStore()
        store.addUpload("a", apk("log.txt"), null)
        store.addUpload("a", apk(), ApkTargetKind.NATIVE)
        store.clear("a")
        assertEquals(AttachmentDraft(), store["a"])
        assertEquals(AttachmentDraft(), store[null])
    }
}
