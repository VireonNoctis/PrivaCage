package org.privacage.android

import com.android.apksig.ApkSigner
import com.android.apksig.ApkVerifier
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream
import java.nio.file.Files
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.util.concurrent.TimeUnit
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ApkSignatureVerifierTest {
    @Test
    fun malformedApkIsReportedAsVerificationError() {
        val apk = Files.createTempFile("privacage-invalid-apk-", ".apk").toFile()
        try {
            apk.writeBytes("not an apk".toByteArray(Charsets.US_ASCII))

            val result = ApkSignatureVerifier.verify(apk)

            assertEquals(ApkSignatureStatus.ERROR, result.status)
            assertFalse(result.errors.isEmpty())
        } finally {
            apk.delete()
        }
    }

    @Test
    fun missingApkIsReportedAsVerificationError() {
        val directory = Files.createTempDirectory("privacage-missing-apk-").toFile()
        val missing = File(directory, "missing.apk")
        try {
            val result = ApkSignatureVerifier.verify(missing)

            assertEquals(ApkSignatureStatus.ERROR, result.status)
            assertFalse(result.errors.isEmpty())
        } finally {
            directory.deleteRecursively()
        }
    }

    @Test
    fun unsignedApkWithAValidManifestIsInvalidRatherThanAnInspectionError() {
        val apk = createUnsignedApk(minSdkVersion = 26)
        try {
            val result = ApkSignatureVerifier.verify(apk)

            assertEquals(ApkSignatureStatus.INVALID, result.status)
        } finally {
            apk.delete()
        }
    }

    @Test
    fun validSignedApkIsVerifiedByTheProductionWrapper() {
        val signer = createSigner("valid-signature")
        val input = createUnsignedApk(minSdkVersion = 26)
        var signed: File? = null
        try {
            signed = signApk(input, 26, listOf(signer))

            val result = ApkSignatureVerifier.verify(signed)

            assertEquals(
                "Expected a valid generated APK signature; errors=${result.errors}, warnings=${result.warnings}",
                ApkSignatureStatus.VERIFIED,
                result.status
            )
            assertTrue(result.errors.isEmpty())
        } finally {
            signed?.delete()
            input.delete()
            signer.delete()
        }
    }

    @Test
    fun modifiedApkContentInvalidatesItsSignature() {
        val signer = createSigner("tamper")
        val input = createUnsignedApk(minSdkVersion = 26)
        var signed: File? = null
        try {
            signed = signApk(input, 26, listOf(signer))
            mutateZipEntry(signed, "classes.dex")

            val result = ApkSignatureVerifier.verify(signed)

            assertEquals(ApkSignatureStatus.INVALID, result.status)
        } finally {
            signed?.delete()
            input.delete()
            signer.delete()
        }
    }

    @Test
    fun malformedV2SignerCertificateIsInvalid() {
        val signer = createSigner("malformed-certificate")
        val input = createUnsignedApk(minSdkVersion = 26)
        var signed: File? = null
        try {
            signed = signApk(input, 26, listOf(signer))
            corruptSigningBlockCertificate(signed, signer.certificate.encoded)

            val result = ApkSignatureVerifier.verify(signed)

            assertEquals(ApkSignatureStatus.INVALID, result.status)
        } finally {
            signed?.delete()
            input.delete()
            signer.delete()
        }
    }

    @Test
    fun apkWithMultipleIndependentSignersCanVerify() {
        val firstSigner = createSigner("multiple-a")
        val secondSigner = createSigner("multiple-b")
        val input = createUnsignedApk(minSdkVersion = 26)
        var signed: File? = null
        try {
            signed = signApk(
                input,
                26,
                listOf(firstSigner, secondSigner),
                v1 = false,
                v2 = true,
                v3 = false
            )

            val result = verifyForPlatform(signed, API_24)

            assertTrue(
                "A v2 APK with multiple independent signers should verify on API 24; errors=${result.errors}",
                result.isVerified()
            )
            assertTrue(result.errors.isEmpty())
        } finally {
            signed?.delete()
            input.delete()
            firstSigner.delete()
            secondSigner.delete()
        }
    }

    @Test
    fun unknownSigningBlockSchemeCannotSubstituteForV2() {
        val signer = createSigner("unknown-scheme")
        val input = createUnsignedApk(minSdkVersion = 26)
        var signed: File? = null
        try {
            signed = signApk(input, 26, listOf(signer), v1 = false, v2 = true, v3 = false)
            replaceSigningBlockId(signed, V2_SIGNATURE_BLOCK_ID, UNKNOWN_SIGNATURE_BLOCK_ID)

            val result = ApkSignatureVerifier.verify(signed)

            assertEquals(ApkSignatureStatus.INVALID, result.status)
        } finally {
            signed?.delete()
            input.delete()
            signer.delete()
        }
    }

    @Test
    fun v2OnlySigningIsRejectedBelowApi24AndAcceptedFromApi24() {
        val signer = createSigner("platform-boundary")
        val api23Input = createUnsignedApk(minSdkVersion = 23)
        val api24Input = createUnsignedApk(minSdkVersion = 24)
        var api23Signed: File? = null
        var api24Signed: File? = null
        try {
            api23Signed = signApk(api23Input, 23, listOf(signer), v1 = false, v2 = true, v3 = false)
            api24Signed = signApk(api24Input, 24, listOf(signer), v1 = false, v2 = true, v3 = false)

            val api23Result = verifyForPlatform(api23Signed, API_23)
            val api24Result = verifyForPlatform(api24Signed, API_24)
            assertFalse(api23Result.isVerified())
            assertTrue(
                "A v2-only APK should verify on API 24; errors=${api24Result.errors}",
                api24Result.isVerified()
            )
        } finally {
            api23Signed?.delete()
            api24Signed?.delete()
            api23Input.delete()
            api24Input.delete()
            signer.delete()
        }
    }

    private fun verifyForPlatform(apk: File, apiLevel: Int) =
        ApkVerifier.Builder(apk)
            .setMinCheckedPlatformVersion(apiLevel)
            .setMaxCheckedPlatformVersion(apiLevel)
            .build()
            .verify()

    private data class SigningMaterial(
        val directory: File,
        val privateKey: PrivateKey,
        val certificate: X509Certificate
    ) {
        fun signerConfig(name: String) =
            ApkSigner.SignerConfig.Builder(name, privateKey, listOf(certificate)).build()

        fun delete() {
            directory.deleteRecursively()
        }
    }

    private fun createSigner(name: String): SigningMaterial {
        val directory = Files.createTempDirectory("privacage-apk-signer-").toFile()
        try {
            val keystoreFile = File(directory, "$name.p12")
            val windows = System.getProperty("os.name").orEmpty().startsWith("Windows", ignoreCase = true)
            val keytoolName = if (windows) "keytool.exe" else "keytool"
            val keytool = File(File(System.getProperty("java.home"), "bin"), keytoolName)
            assertTrue("A JDK keytool executable is required for signing fixtures.", keytool.isFile)

            val process = ProcessBuilder(
                keytool.absolutePath,
                "-genkeypair",
                "-alias", name,
                "-keystore", keystoreFile.absolutePath,
                "-storetype", "PKCS12",
                "-storepass", TEST_KEYSTORE_PASSWORD,
                "-keypass", TEST_KEYSTORE_PASSWORD,
                "-keyalg", "RSA",
                "-keysize", "2048",
                "-validity", "3650",
                "-dname", "CN=PrivaCage $name Test Signer,O=PrivaCage Test Only",
                "-noprompt"
            ).redirectErrorStream(true).start()

            val completed = process.waitFor(KEYTOOL_TIMEOUT_SECONDS, TimeUnit.SECONDS)
            if (!completed) {
                process.destroyForcibly()
                val output = process.inputStream.bufferedReader().use { it.readText() }
                throw AssertionError("keytool timed out while generating a test signer: $output")
            }
            val output = process.inputStream.bufferedReader().use { it.readText() }
            assertEquals("keytool could not generate a test signer: $output", 0, process.exitValue())

            val password = TEST_KEYSTORE_PASSWORD.toCharArray()
            try {
                val keyStore = KeyStore.getInstance("PKCS12")
                keystoreFile.inputStream().use { keyStore.load(it, password) }
                val privateKey = keyStore.getKey(name, password) as PrivateKey
                val certificate = keyStore.getCertificate(name) as X509Certificate
                return SigningMaterial(directory, privateKey, certificate)
            } finally {
                password.fill('\u0000')
            }
        } catch (exception: Exception) {
            directory.deleteRecursively()
            throw exception
        } catch (error: AssertionError) {
            directory.deleteRecursively()
            throw error
        }
    }

    private fun createUnsignedApk(minSdkVersion: Int): File {
        val apk = Files.createTempFile("privacage-unsigned-apk-", ".apk").toFile()
        ZipOutputStream(FileOutputStream(apk)).use { zip ->
            zip.putNextEntry(ZipEntry("AndroidManifest.xml"))
            zip.write(binaryAndroidManifest(minSdkVersion))
            zip.closeEntry()

            zip.putNextEntry(ZipEntry("classes.dex"))
            zip.write(byteArrayOf(0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x35, 0x00))
            zip.closeEntry()
        }
        return apk
    }

    private fun signApk(
        input: File,
        minSdkVersion: Int,
        signers: List<SigningMaterial>,
        v1: Boolean = true,
        v2: Boolean = true,
        v3: Boolean = true
    ): File {
        val output = Files.createTempFile("privacage-signed-apk-", ".apk").toFile()
        try {
            ApkSigner.Builder(signers.mapIndexed { index, signer -> signer.signerConfig("signer-$index") })
                .setInputApk(input)
                .setOutputApk(output)
                .setMinSdkVersion(minSdkVersion)
                .setV1SigningEnabled(v1)
                .setV2SigningEnabled(v2)
                .setV3SigningEnabled(v3)
                .build()
                .sign()
            return output
        } catch (exception: Exception) {
            output.delete()
            throw exception
        }
    }

    private data class ManifestAttribute(
        val namespaceIndex: Int,
        val nameIndex: Int,
        val dataType: Int,
        val data: Int
    )

    private fun binaryAndroidManifest(minSdkVersion: Int): ByteArray {
        val strings = listOf(
            "manifest",
            "uses-sdk",
            "http://schemas.android.com/apk/res/android",
            "minSdkVersion",
            "android",
            "package",
            "org.privacage.test"
        )
        val indexes = strings.withIndex().associate { it.value to it.index }
        val chunks = ByteArrayOutputStream()
        chunks.write(stringPoolChunk(strings))
        writeNamespace(chunks, RES_XML_START_NAMESPACE_TYPE, indexes.getValue("android"),
            indexes.getValue("http://schemas.android.com/apk/res/android"))
        writeStartElement(
            chunks,
            NO_INDEX,
            indexes.getValue("manifest"),
            listOf(
                ManifestAttribute(
                    namespaceIndex = NO_INDEX,
                    nameIndex = indexes.getValue("package"),
                    dataType = TYPE_STRING,
                    data = indexes.getValue("org.privacage.test")
                )
            )
        )
        writeStartElement(
            chunks,
            NO_INDEX,
            indexes.getValue("uses-sdk"),
            listOf(
                ManifestAttribute(
                    namespaceIndex = indexes.getValue("http://schemas.android.com/apk/res/android"),
                    nameIndex = indexes.getValue("minSdkVersion"),
                    dataType = TYPE_INT_DEC,
                    data = minSdkVersion
                )
            )
        )
        writeEndElement(chunks, NO_INDEX, indexes.getValue("uses-sdk"))
        writeEndElement(chunks, NO_INDEX, indexes.getValue("manifest"))
        writeNamespace(chunks, RES_XML_END_NAMESPACE_TYPE, indexes.getValue("android"),
            indexes.getValue("http://schemas.android.com/apk/res/android"))

        val output = ByteArrayOutputStream()
        writeShort(output, RES_XML_TYPE)
        writeShort(output, RES_XML_HEADER_SIZE)
        writeInt(output, RES_XML_HEADER_SIZE + chunks.size())
        chunks.writeTo(output)
        return output.toByteArray()
    }

    private fun stringPoolChunk(strings: List<String>): ByteArray {
        val stringData = ByteArrayOutputStream()
        val offsets = mutableListOf<Int>()
        strings.forEach { value ->
            val encoded = value.toByteArray(Charsets.UTF_8)
            require(value.length < 0x80 && encoded.size < 0x80) {
                "Test Android manifest strings must fit the compact UTF-8 length encoding."
            }
            offsets += stringData.size()
            stringData.write(value.length)
            stringData.write(encoded.size)
            stringData.write(encoded)
            stringData.write(0)
            while (stringData.size() % 4 != 0) stringData.write(0)
        }

        val headerSize = STRING_POOL_HEADER_SIZE
        val stringsStart = headerSize + offsets.size * INT_BYTES
        val size = stringsStart + stringData.size()
        val output = ByteArrayOutputStream()
        writeShort(output, RES_STRING_POOL_TYPE)
        writeShort(output, headerSize)
        writeInt(output, size)
        writeInt(output, strings.size)
        writeInt(output, 0)
        writeInt(output, UTF8_FLAG)
        writeInt(output, stringsStart)
        writeInt(output, 0)
        offsets.forEach { writeInt(output, it) }
        stringData.writeTo(output)
        return output.toByteArray()
    }

    private fun writeNamespace(output: ByteArrayOutputStream, type: Int, prefixIndex: Int, uriIndex: Int) {
        writeShort(output, type)
        writeShort(output, RES_XML_NODE_HEADER_SIZE)
        writeInt(output, RES_XML_NODE_HEADER_SIZE + NAMESPACE_EXT_SIZE)
        writeInt(output, 1)
        writeInt(output, NO_INDEX)
        writeInt(output, prefixIndex)
        writeInt(output, uriIndex)
    }

    private fun writeStartElement(
        output: ByteArrayOutputStream,
        namespaceIndex: Int,
        nameIndex: Int,
        attributes: List<ManifestAttribute>
    ) {
        writeShort(output, RES_XML_START_ELEMENT_TYPE)
        writeShort(output, RES_XML_NODE_HEADER_SIZE)
        writeInt(output, RES_XML_NODE_HEADER_SIZE + START_ELEMENT_EXT_SIZE + attributes.size * ATTRIBUTE_SIZE)
        writeInt(output, 1)
        writeInt(output, NO_INDEX)
        writeInt(output, namespaceIndex)
        writeInt(output, nameIndex)
        writeShort(output, START_ELEMENT_EXT_SIZE)
        writeShort(output, ATTRIBUTE_SIZE)
        writeShort(output, attributes.size)
        writeShort(output, 0)
        writeShort(output, 0)
        writeShort(output, 0)
        attributes.forEach { attribute ->
            writeInt(output, attribute.namespaceIndex)
            writeInt(output, attribute.nameIndex)
            writeInt(output, if (attribute.dataType == TYPE_STRING) attribute.data else NO_INDEX)
            writeShort(output, RES_VALUE_SIZE)
            output.write(0)
            output.write(attribute.dataType)
            writeInt(output, attribute.data)
        }
    }

    private fun writeEndElement(output: ByteArrayOutputStream, namespaceIndex: Int, nameIndex: Int) {
        writeShort(output, RES_XML_END_ELEMENT_TYPE)
        writeShort(output, RES_XML_NODE_HEADER_SIZE)
        writeInt(output, RES_XML_NODE_HEADER_SIZE + END_ELEMENT_EXT_SIZE)
        writeInt(output, 1)
        writeInt(output, NO_INDEX)
        writeInt(output, namespaceIndex)
        writeInt(output, nameIndex)
    }

    private fun writeShort(output: ByteArrayOutputStream, value: Int) {
        output.write(value and 0xff)
        output.write((value ushr 8) and 0xff)
    }

    private fun writeInt(output: ByteArrayOutputStream, value: Int) {
        output.write(value and 0xff)
        output.write((value ushr 8) and 0xff)
        output.write((value ushr 16) and 0xff)
        output.write((value ushr 24) and 0xff)
    }

    private fun mutateZipEntry(apk: File, entryName: String) {
        val bytes = apk.readBytes()
        var cursor = 0
        var dataOffset = -1
        while (cursor <= bytes.size - ZIP_LOCAL_HEADER_SIZE) {
            if (readInt(bytes, cursor) == ZIP_LOCAL_FILE_HEADER_SIGNATURE) {
                val nameLength = readShort(bytes, cursor + 26)
                val extraLength = readShort(bytes, cursor + 28)
                val nameStart = cursor + ZIP_LOCAL_HEADER_SIZE
                val nameEnd = nameStart + nameLength
                if (nameEnd <= bytes.size) {
                    val name = bytes.copyOfRange(nameStart, nameEnd).toString(Charsets.UTF_8)
                    if (name == entryName) {
                        dataOffset = nameEnd + extraLength
                        break
                    }
                }
            }
            cursor++
        }
        assertTrue("Could not locate ZIP entry $entryName in signed APK.", dataOffset >= 0 && dataOffset < bytes.size)
        bytes[dataOffset] = (bytes[dataOffset].toInt() xor 0x01).toByte()
        apk.writeBytes(bytes)
    }

    private fun corruptSigningBlockCertificate(apk: File, certificateDer: ByteArray) {
        val bytes = apk.readBytes()
        val (pairsStart, pairsEnd) = signingBlockBounds(bytes)
        val certificateOffset = indexOf(bytes, certificateDer, pairsStart, pairsEnd)
        assertTrue("The signing certificate was not found in the APK signing block.", certificateOffset >= 0)
        bytes[certificateOffset] = 0
        apk.writeBytes(bytes)
    }

    private fun replaceSigningBlockId(apk: File, oldId: Int, newId: Int) {
        val bytes = apk.readBytes()
        val (pairsStart, pairsEnd) = signingBlockBounds(bytes)
        var cursor = pairsStart
        var replaced = false
        while (cursor < pairsEnd) {
            val pairLength = readLong(bytes, cursor)
            assertTrue("APK signing block contains an invalid pair length.", pairLength >= INT_BYTES)
            val pairEnd = cursor + LONG_BYTES + pairLength.toInt()
            assertTrue("APK signing block pair extends beyond the block.", pairEnd <= pairsEnd)
            if (readInt(bytes, cursor + LONG_BYTES) == oldId) {
                writeInt(bytes, cursor + LONG_BYTES, newId)
                replaced = true
            }
            cursor = pairEnd
        }
        assertTrue("The requested APK signature scheme ID was not present.", replaced)
        apk.writeBytes(bytes)
    }

    private fun signingBlockBounds(bytes: ByteArray): Pair<Int, Int> {
        val eocdOffset = findEndOfCentralDirectory(bytes)
        val centralDirectoryOffset = readInt(bytes, eocdOffset + 16)
        val magicOffset = centralDirectoryOffset - APK_SIGNING_BLOCK_MAGIC.size
        assertTrue("APK signing block magic is missing.", magicOffset >= 0)
        assertTrue(
            "APK signing block magic is missing.",
            bytes.copyOfRange(magicOffset, centralDirectoryOffset).contentEquals(APK_SIGNING_BLOCK_MAGIC)
        )
        val blockSizeOffset = centralDirectoryOffset - APK_SIGNING_BLOCK_TRAILER_SIZE
        val blockSize = readLong(bytes, blockSizeOffset)
        val blockStart = centralDirectoryOffset - blockSize.toInt() - LONG_BYTES
        val pairsStart = blockStart + LONG_BYTES
        val pairsEnd = blockSizeOffset
        assertTrue("APK signing block bounds are invalid.", pairsStart <= pairsEnd && blockStart >= 0)
        return pairsStart to pairsEnd
    }

    private fun findEndOfCentralDirectory(bytes: ByteArray): Int {
        val earliestOffset = maxOf(0, bytes.size - ZIP_EOCD_MIN_SIZE - MAX_ZIP_COMMENT_BYTES)
        for (offset in bytes.size - ZIP_EOCD_MIN_SIZE downTo earliestOffset) {
            if (readInt(bytes, offset) != ZIP_EOCD_SIGNATURE) continue
            val commentLength = readShort(bytes, offset + ZIP_EOCD_COMMENT_LENGTH_OFFSET)
            if (offset + ZIP_EOCD_MIN_SIZE + commentLength == bytes.size) return offset
        }
        throw AssertionError("ZIP end-of-central-directory record was not found.")
    }

    private fun indexOf(bytes: ByteArray, needle: ByteArray, start: Int, end: Int): Int {
        if (needle.isEmpty() || end - start < needle.size) return -1
        for (offset in start..(end - needle.size)) {
            var matches = true
            for (index in needle.indices) {
                if (bytes[offset + index] != needle[index]) {
                    matches = false
                    break
                }
            }
            if (matches) return offset
        }
        return -1
    }

    private fun readShort(bytes: ByteArray, offset: Int): Int =
        (bytes[offset].toInt() and 0xff) or ((bytes[offset + 1].toInt() and 0xff) shl 8)

    private fun readInt(bytes: ByteArray, offset: Int): Int =
        readShort(bytes, offset) or (readShort(bytes, offset + 2) shl 16)

    private fun readLong(bytes: ByteArray, offset: Int): Long =
        (readInt(bytes, offset).toLong() and 0xffffffffL) or
            ((readInt(bytes, offset + INT_BYTES).toLong() and 0xffffffffL) shl 32)

    private fun writeInt(bytes: ByteArray, offset: Int, value: Int) {
        bytes[offset] = value.toByte()
        bytes[offset + 1] = (value ushr 8).toByte()
        bytes[offset + 2] = (value ushr 16).toByte()
        bytes[offset + 3] = (value ushr 24).toByte()
    }

    private companion object {
        const val TEST_KEYSTORE_PASSWORD = "privacage-test-only"
        const val API_23 = 23
        const val API_24 = 24
        const val KEYTOOL_TIMEOUT_SECONDS = 30L
        const val NO_INDEX = -1
        const val TYPE_STRING = 0x03
        const val TYPE_INT_DEC = 0x10
        const val RES_VALUE_SIZE = 8
        const val INT_BYTES = 4
        const val LONG_BYTES = 8
        const val RES_XML_TYPE = 0x0003
        const val RES_XML_HEADER_SIZE = 8
        const val RES_STRING_POOL_TYPE = 0x0001
        const val STRING_POOL_HEADER_SIZE = 28
        const val UTF8_FLAG = 0x100
        const val RES_XML_START_NAMESPACE_TYPE = 0x0100
        const val RES_XML_END_NAMESPACE_TYPE = 0x0101
        const val RES_XML_START_ELEMENT_TYPE = 0x0102
        const val RES_XML_END_ELEMENT_TYPE = 0x0103
        const val RES_XML_NODE_HEADER_SIZE = 16
        const val NAMESPACE_EXT_SIZE = 8
        const val START_ELEMENT_EXT_SIZE = 20
        const val END_ELEMENT_EXT_SIZE = 8
        const val ATTRIBUTE_SIZE = 20
        const val ZIP_LOCAL_FILE_HEADER_SIGNATURE = 0x04034b50
        const val ZIP_LOCAL_HEADER_SIZE = 30
        const val ZIP_EOCD_SIGNATURE = 0x06054b50
        const val ZIP_EOCD_MIN_SIZE = 22
        const val ZIP_EOCD_COMMENT_LENGTH_OFFSET = 20
        const val MAX_ZIP_COMMENT_BYTES = 0xffff
        const val APK_SIGNING_BLOCK_TRAILER_SIZE = 24
        const val V2_SIGNATURE_BLOCK_ID = 0x7109871a
        const val UNKNOWN_SIGNATURE_BLOCK_ID = 0x12345678
        val APK_SIGNING_BLOCK_MAGIC = "APK Sig Block 42".toByteArray(Charsets.US_ASCII)
    }
}
