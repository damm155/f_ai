package com.aicode.feature.agent.domain.tool.reverse

import android.content.Context
import android.content.res.AssetManager
import com.aicode.core.util.FileLogger
import com.aicode.feature.agent.domain.tool.ToolResult
import com.aicode.feature.workspace.domain.WorkspacePathMapper
import com.android.apksig.ApkSigner
import com.android.apksig.ApkVerifier
import io.mockk.Runs
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.mockkConstructor
import io.mockk.mockkObject
import io.mockk.unmockkConstructor
import io.mockk.unmockkObject
import io.mockk.verify
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonPrimitive
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.file.Files
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Security
import java.security.cert.X509Certificate
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream

class ApkSignToolTest {

    @get:Rule
    val temporary = TemporaryFolder()

    private val context = mockk<Context>()
    private val assets = mockk<AssetManager>()
    private val pathMapper = mockk<WorkspacePathMapper>()
    private val tool = ApkSignTool(context, pathMapper)
    private val keystoreFile = File("src/main/assets/reverse/keystore/patch.keystore")
    private var addedProvider = false

    @Before
    fun setUp() {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(BouncyCastleProvider())
            addedProvider = true
        }
        mockkObject(FileLogger)
        every { FileLogger.i(any(), any()) } just Runs
        every { FileLogger.w(any(), any(), any()) } just Runs
        every { context.assets } returns assets
        every { assets.open("reverse/keystore/patch.keystore") } answers { keystoreFile.inputStream() }
        every { pathMapper.toHostFile(any()) } answers { File(firstArg<String>()) }
        every { pathMapper.toContainerPath(any()) } answers { firstArg<String>() }
    }

    @After
    fun tearDown() {
        unmockkObject(FileLogger)
        if (addedProvider) Security.removeProvider("BC")
    }

    @Test
    fun sign_minSdk29_verifiesV1V2WithoutV3_andPreservesContentsAndSigner() = runTest {
        val input = unsignedApk()
        val original = input.readBytes()
        val output = File(temporary.root, "signed.apk")

        val result = sign(input, output) as ToolResult.Success
        val data = result.data as JsonObject
        assertTrue(data.getValue("v1Verified").jsonPrimitive.boolean)
        assertTrue(data.getValue("v2Verified").jsonPrimitive.boolean)
        assertFalse(data.getValue("v3Verified").jsonPrimitive.boolean)
        assertEquals(output.absolutePath, data.getValue("apk").jsonPrimitive.content)
        assertEquals(output.absolutePath, data.getValue("hostPath").jsonPrimitive.content)
        assertEquals(output.length().toString(), data.getValue("bytes").jsonPrimitive.content)
        assertArrayEquals(original, input.readBytes())

        val comprehensive = ApkVerifier.Builder(output).build().verify()
        assertTrue(comprehensive.isVerified)
        assertFalse(comprehensive.isVerifiedUsingV3Scheme)
        val v1 = verifyFor(output, 23, 23)
        val v2 = verifyFor(output, 24, 28)
        assertTrue(v1.isVerified)
        assertTrue(v1.isVerifiedUsingV1Scheme)
        assertTrue(v2.isVerified)
        assertTrue(v2.isVerifiedUsingV2Scheme)

        val keyStore = bundledKeyStore()
        val alias = keyStore.aliases().nextElement()
        val certificate = keyStore.getCertificate(alias).encoded
        assertEquals(alias, data.getValue("signer").jsonPrimitive.content)
        for (verification in listOf(comprehensive, v1, v2)) {
            assertArrayEquals(certificate, verification.signerCertificates.single().encoded)
        }
        ZipFile(input).use { before ->
            ZipFile(output).use { after ->
                for (entry in before.entries().asSequence()) {
                    val signedEntry = after.getEntry(entry.name)
                    assertTrue("Missing signed entry: ${entry.name}", signedEntry != null)
                    val originalBytes = before.getInputStream(entry).use { it.readBytes() }
                    val signedBytes = after.getInputStream(signedEntry).use { it.readBytes() }
                    assertArrayEquals(originalBytes, signedBytes)
                }
            }
        }
        assertNoTemporaryOutputs()
    }

    @Test
    fun apksigDefault_minSdk29_skipsV1V2ChecksWhenV3Verifies() {
        val input = unsignedApk()
        val output = File(temporary.root, "default-builder.apk")
        ApkSigner.Builder(listOf(bundledSignerConfig()))
            .setInputApk(input)
            .setOutputApk(output)
            .setV1SigningEnabled(true)
            .setV2SigningEnabled(true)
            .build()
            .sign()

        val comprehensive = ApkVerifier.Builder(output).build().verify()
        assertTrue(comprehensive.isVerified)
        assertTrue(comprehensive.isVerifiedUsingV3Scheme)
        assertFalse(comprehensive.isVerifiedUsingV1Scheme)
        assertFalse(comprehensive.isVerifiedUsingV2Scheme)
        assertTrue(verifyFor(output, 23, 23).isVerifiedUsingV1Scheme)
        assertTrue(verifyFor(output, 24, 28).isVerifiedUsingV2Scheme)
    }

    @Test
    fun sign_defaultOutput_usesSignedSuffix() = runTest {
        val input = unsignedApk()
        val output = File(temporary.root, "unsigned-signed.apk")

        val result = sign(input) as ToolResult.Success
        assertEquals(
            output.absolutePath,
            (result.data as JsonObject).getValue("hostPath").jsonPrimitive.content
        )
        assertTrue(output.isFile)
        assertNoTemporaryOutputs()
    }

    @Test
    fun sign_sameCanonicalPath_rejectsDirectAndNormalizedAliases() = runTest {
        val input = unsignedApk()
        val original = input.readBytes()
        val nested = temporary.newFolder("nested")
        val aliases = listOf(
            input, File(temporary.root, "./${input.name}"), File(nested, "../${input.name}")
        )

        for (alias in aliases) {
            assertEquals("SAME_PATH", (sign(input, alias) as ToolResult.Error).code)
            assertArrayEquals(original, input.readBytes())
        }
        verify(exactly = 0) { assets.open(any()) }
        assertNoTemporaryOutputs()
    }

    @Test
    fun sign_symlinkToInput_rejectsWithoutChangingInputOrLink() = runTest {
        val input = unsignedApk()
        val original = input.readBytes()
        val output = File(temporary.root, "input-alias.apk")
        Files.createSymbolicLink(output.toPath(), input.toPath())

        assertEquals("SAME_PATH", (sign(input, output) as ToolResult.Error).code)
        assertArrayEquals(original, input.readBytes())
        assertTrue(Files.isSymbolicLink(output.toPath()))
        verify(exactly = 0) { assets.open(any()) }
        assertNoTemporaryOutputs()
    }

    @Test
    fun sign_mappedAliases_rejectsSameHostFile() = runTest {
        val input = unsignedApk()
        val original = input.readBytes()
        every { pathMapper.toHostFile("container-input") } returns input
        every { pathMapper.toHostFile("container-alias") } returns input

        val result = tool.execute(
            mapOf("apk" to JsonPrimitive("container-input"), "out" to JsonPrimitive("container-alias"))
        )
        assertEquals("SAME_PATH", (result as ToolResult.Error).code)
        assertArrayEquals(original, input.readBytes())
        verify(exactly = 0) { assets.open(any()) }
        assertNoTemporaryOutputs()
    }

    @Test
    fun sign_existingOutput_rejectsExplicitAndDefaultCollisions() = runTest {
        val input = unsignedApk()
        val original = input.readBytes()
        val output = temporary.newFile("existing.apk").apply { writeText("existing content") }
        val defaultOutput = temporary.newFile("unsigned-signed.apk").apply {
            writeText("default content")
        }

        assertEquals("FILE_ALREADY_EXISTS", (sign(input, output) as ToolResult.Error).code)
        assertEquals("FILE_ALREADY_EXISTS", (sign(input) as ToolResult.Error).code)
        assertEquals("existing content", output.readText())
        assertEquals("default content", defaultOutput.readText())
        assertArrayEquals(original, input.readBytes())
        verify(exactly = 0) { assets.open(any()) }
        assertNoTemporaryOutputs()
    }

    @Test
    fun sign_danglingOutputSymlink_rejectsWithoutCreatingTarget() = runTest {
        val input = unsignedApk()
        val output = File(temporary.root, "dangling.apk")
        val target = File(temporary.root, "absent.apk")
        Files.createSymbolicLink(output.toPath(), target.toPath())

        assertEquals("FILE_ALREADY_EXISTS", (sign(input, output) as ToolResult.Error).code)
        assertTrue(Files.isSymbolicLink(output.toPath()))
        assertFalse(target.exists())
        verify(exactly = 0) { assets.open(any()) }
        assertNoTemporaryOutputs()
    }

    @Test
    fun sign_outputCreatedDuringSigning_isNotOverwritten() = runTest {
        val input = unsignedApk()
        val original = input.readBytes()
        val output = File(temporary.root, "concurrent.apk")
        every { assets.open(any()) } answers {
            output.writeText("another writer")
            keystoreFile.inputStream()
        }

        assertEquals("FILE_ALREADY_EXISTS", (sign(input, output) as ToolResult.Error).code)
        assertEquals("another writer", output.readText())
        assertArrayEquals(original, input.readBytes())
        assertNoTemporaryOutputs()
    }

    @Test
    fun sign_invalidApk_leavesNoOutputOrTemporaryFile() = runTest {
        val input = temporary.newFile("invalid.apk").apply { writeText("not a ZIP") }
        val original = input.readBytes()
        val output = File(temporary.root, "invalid-signed.apk")

        assertEquals("SIGN_FAILED", (sign(input, output) as ToolResult.Error).code)
        assertArrayEquals(original, input.readBytes())
        assertFalse(output.exists())
        assertNoTemporaryOutputs()
    }

    @Test
    fun sign_failedOrSkippedVerification_leavesNoPublishedOutput() = runTest {
        val input = unsignedApk()
        val original = input.readBytes()
        mockkConstructor(ApkVerifier.Builder::class)
        try {
            val verificationResults = (0..4).flatMap { failedIndex ->
                (0..2).map { index ->
                    mockk<ApkVerifier> {
                        every { verify() } returns mockk<ApkVerifier.Result> {
                            every { isVerified } returns (index != failedIndex || failedIndex > 2)
                            every { isVerifiedUsingV1Scheme } returns (index != 1 || failedIndex != 3)
                            every { isVerifiedUsingV2Scheme } returns (index != 2 || failedIndex != 4)
                            every { errors } returns emptyList()
                        }
                    }
                }
            }
            every { anyConstructed<ApkVerifier.Builder>().build() } returnsMany verificationResults

            for (failedIndex in 0..4) {
                val output = File(temporary.root, "verification-$failedIndex.apk")
                assertEquals("VERIFY_FAILED", (sign(input, output) as ToolResult.Error).code)
                assertFalse(output.exists())
                assertArrayEquals(original, input.readBytes())
                assertNoTemporaryOutputs()
            }
            verify(exactly = 15) { anyConstructed<ApkVerifier.Builder>().build() }
        } finally {
            unmockkConstructor(ApkVerifier.Builder::class)
        }
    }

    @Test
    fun sign_failure_doesNotExposeExceptionDetailsOrStackTrace() = runTest {
        val input = unsignedApk()
        val output = File(temporary.root, "failed.apk")
        val messages = mutableListOf<String>()
        every { FileLogger.w(any(), capture(messages), any()) } just Runs
        every { assets.open(any()) } throws IOException("sensitive signing detail")

        val result = sign(input, output) as ToolResult.Error
        assertEquals("SIGN_FAILED", result.code)
        assertTrue(result.message.contains("IOException"))
        assertFalse(result.message.contains("sensitive signing detail"))
        assertTrue(messages.isNotEmpty())
        assertTrue(messages.none { it.contains("sensitive signing detail") })
        verify(exactly = 1) { FileLogger.w(any(), any(), isNull()) }
        assertFalse(output.exists())
        assertNoTemporaryOutputs()
    }

    @Test
    fun sign_cancellation_rethrowsAndRemovesTemporaryOutput() = runTest {
        val input = unsignedApk()
        val output = File(temporary.root, "cancelled.apk")
        val cancellation = CancellationException("signing cancelled")
        every { assets.open(any()) } throws cancellation

        val thrown = try {
            sign(input, output)
            null
        } catch (e: CancellationException) {
            e
        }
        assertSame(cancellation, thrown)
        assertFalse(output.exists())
        assertNoTemporaryOutputs()
    }

    @Test
    fun sign_pathMappingCancellation_isNotConvertedToErrorOrSuccess() = runTest {
        val input = unsignedApk()
        val output = File(temporary.root, "mapping-cancelled.apk")
        val cancellation = CancellationException("mapping cancelled")
        every { pathMapper.toContainerPath(any()) } throws cancellation

        val thrown = try {
            sign(input, output)
            null
        } catch (e: CancellationException) {
            e
        }
        assertSame(cancellation, thrown)
        assertFalse(output.exists())
        assertNoTemporaryOutputs()
    }

    private suspend fun sign(input: File, output: File? = null): ToolResult =
        tool.execute(buildMap {
            put("apk", JsonPrimitive(input.absolutePath))
            output?.let { put("out", JsonPrimitive(it.absolutePath)) }
        })

    private fun verifyFor(apk: File, minSdk: Int, maxSdk: Int): ApkVerifier.Result =
        ApkVerifier.Builder(apk)
            .setMinCheckedPlatformVersion(minSdk)
            .setMaxCheckedPlatformVersion(maxSdk)
            .build()
            .verify()

    private fun assertNoTemporaryOutputs() {
        assertTrue(temporary.root.walkTopDown().none { it.name.startsWith(".apksign-") })
    }

    private fun bundledKeyStore(): KeyStore {
        val source = File("src/main/java/com/aicode/feature/agent/domain/tool/reverse/ApkSignTool.kt").readText()
        val password = checkNotNull(Regex("const val KEYSTORE_PASSWORD = \"([^\"]+)\"").find(source))
            .groupValues[1].toCharArray()
        try {
            return KeyStore.getInstance("PKCS12").apply {
                keystoreFile.inputStream().use { load(it, password) }
            }
        } finally {
            password.fill('\u0000')
        }
    }

    private fun bundledSignerConfig(): ApkSigner.SignerConfig {
        val keyStore = bundledKeyStore()
        val source = File("src/main/java/com/aicode/feature/agent/domain/tool/reverse/ApkSignTool.kt").readText()
        val password = checkNotNull(Regex("const val KEYSTORE_PASSWORD = \"([^\"]+)\"").find(source))
            .groupValues[1].toCharArray()
        try {
            val alias = keyStore.aliases().nextElement()
            val key = keyStore.getKey(alias, password) as PrivateKey
            val certificate = keyStore.getCertificate(alias) as X509Certificate
            return ApkSigner.SignerConfig.Builder(alias, key, listOf(certificate)).build()
        } finally {
            password.fill('\u0000')
        }
    }

    private fun unsignedApk(): File = temporary.newFile("unsigned.apk").apply {
        ZipOutputStream(outputStream()).use { zip ->
            val entries = listOf(
                "AndroidManifest.xml" to binaryManifest(29),
                "assets/payload.bin" to byteArrayOf(0, 1, 2, 3, -1),
                "res/raw/content.txt" to "signed content".toByteArray()
            )
            for ((name, bytes) in entries) {
                zip.putNextEntry(ZipEntry(name))
                zip.write(bytes)
                zip.closeEntry()
            }
        }
    }

    private fun binaryManifest(minSdk: Int): ByteArray {
        val strings = listOf(
            "minSdkVersion", "targetSdkVersion", "versionCode", "manifest", "uses-sdk", "package",
            "com.aicode.signingfixture", "android", "http://schemas.android.com/apk/res/android"
        )
        val stringData = ByteArrayOutputStream()
        val offsets = strings.map { value ->
            val offset = stringData.size()
            stringData.write(
                ByteBuffer.allocate(2).order(ByteOrder.LITTLE_ENDIAN)
                    .putShort(value.length.toShort()).array()
            )
            stringData.write(value.toByteArray(Charsets.UTF_16LE))
            stringData.write(byteArrayOf(0, 0))
            offset
        }
        while (stringData.size() % 4 != 0) stringData.write(0)
        val pool = chunk(
            0x0001,
            ints(strings.size, 0, 0, 28 + strings.size * 4, 0),
            ints(*offsets.toIntArray()) + stringData.toByteArray()
        )
        val resourceMap = chunk(0x0180, body = ints(0x0101020c, 0x01010270, 0x0101021b))
        val nodeHeader = ints(1, -1)
        val namespaceStart = chunk(0x0100, nodeHeader, ints(7, 8))
        val namespaceEnd = chunk(0x0101, nodeHeader, ints(7, 8))
        val manifestStart = startElement(
            3, listOf(attribute(-1, 5, 3, 6), attribute(8, 2, 0x10, 1))
        )
        val sdkStart = startElement(
            4, listOf(attribute(8, 0, 0x10, minSdk), attribute(8, 1, 0x10, minSdk))
        )
        val sdkEnd = chunk(0x0103, nodeHeader, ints(-1, 4))
        val manifestEnd = chunk(0x0103, nodeHeader, ints(-1, 3))
        return chunk(
            0x0003,
            body = pool + resourceMap + namespaceStart + manifestStart + sdkStart + sdkEnd +
                manifestEnd + namespaceEnd
        )
    }

    private fun startElement(name: Int, attributes: List<ByteArray>): ByteArray {
        val element = ByteBuffer.allocate(20).order(ByteOrder.LITTLE_ENDIAN)
            .putInt(-1).putInt(name).putShort(20).putShort(20).putShort(attributes.size.toShort())
            .putShort(0).putShort(0).putShort(0).array()
        val encodedAttributes = attributes.fold(ByteArray(0)) { bytes, attribute -> bytes + attribute }
        return chunk(0x0102, ints(1, -1), element + encodedAttributes)
    }

    private fun attribute(namespace: Int, name: Int, type: Int, value: Int): ByteArray =
        ByteBuffer.allocate(20).order(ByteOrder.LITTLE_ENDIAN)
            .putInt(namespace).putInt(name).putInt(if (type == 3) value else -1)
            .putShort(8).put(0.toByte()).put(type.toByte()).putInt(value).array()

    private fun chunk(type: Int, header: ByteArray = ByteArray(0), body: ByteArray): ByteArray =
        ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN)
            .putShort(type.toShort()).putShort((8 + header.size).toShort())
            .putInt(8 + header.size + body.size).array() + header + body

    private fun ints(vararg values: Int): ByteArray =
        ByteBuffer.allocate(values.size * 4).order(ByteOrder.LITTLE_ENDIAN).apply {
            values.forEach { putInt(it) }
        }.array()
}
