package io.isaacgc.dpt_extractor

import io.isaacgc.dpt_extractor.signing.ApkSigningBlock
import io.isaacgc.dpt_extractor.signing.SigningKey
import io.isaacgc.dpt_extractor.signing.V1Signer
import io.isaacgc.dpt_extractor.signing.V4Signer
import java.io.ByteArrayOutputStream
import java.io.File
import java.util.zip.CRC32
import java.util.zip.Deflater
import java.util.zip.ZipEntry
import java.util.zip.ZipFile

class ZipAlign {

    companion object {
        // Uncompressed entries have to sit on a 4 byte boundary so android can mmap them,
        //      .so files want 4k (android 15+ is picky about that one)
        private const val DEFAULT_ALIGNMENT = 4
        private const val SO_ALIGNMENT = 4096

        // Already-compressed formats, deflating these again just wastes time and space
        private val STORED_EXTENSIONS = setOf("so", "arsc", "png", "jpg", "jpeg", "gif", "webp",
            "wav", "mp2", "mp3", "ogg", "aac", "mpg", "mpeg", "mid", "midi", "smf", "jet",
            "rtttl", "imy", "xmf", "mp4", "m4a", "m4v", "3gp", "3gpp", "3g2", "3gpp2", "amr",
            "awb", "wma", "wmv", "webm", "mkv")

        private const val LFH_SIG = 0x04034b50
        private const val CDH_SIG = 0x02014b50
        private const val EOCD_SIG = 0x06054b50

        private fun alignmentFor(name: String): Int =
            if (name.endsWith(".so")) SO_ALIGNMENT else DEFAULT_ALIGNMENT

        private fun shouldStore(name: String): Boolean {
            val ext = name.substringAfterLast('.', "").lowercase()
            return ext in STORED_EXTENSIONS || name == "resources.arsc"
        }
    }

    private class Entry(val name: String, val data: ByteArray, val stored: Boolean)

    /**
     * Rebuilds the apk with the restored dex files swapped in, then signs it.
     *
     * The zip gets written by hand instead of using ZipOutputStream -- we need to control the
     * exact byte offsets so stored entries land on their alignment boundary, and the java one
     * won't let us pad the extra field like that
     */
    fun rebuild(originalApk: File, restoredDexDir: File, outputApk: File,
                keystore: File? = null, storePass: String = "android",
                keyAlias: String? = null, keyPass: String = storePass,
                writeV4: Boolean = false): File {

        val restoredDexes = (restoredDexDir.listFiles() ?: emptyArray())
            .filter { it.isFile && it.name.matches(Regex("""classes\d*\.dex""")) }
            .associateBy { it.name }

        require(restoredDexes.isNotEmpty()) { "No restored dex files found in ${restoredDexDir.path}" }
        println("\n[+] Rebuilding apk with ${restoredDexes.size} restored dex file(s)")

        // The packer points <application> at its own proxy, so put the real class back or the
        //      rebuilt apk just boots the shell again
        val shellConfig = ShellConfig.read(originalApk)

        // 1. Pull everything out of the original, swapping in our dex files as we go.
        //      The old signature is dropped since the dex files changed (it can't verify anymore)
        val entries = mutableListOf<Entry>()
        ZipFile(originalApk).use { apk ->
            for (entry in apk.entries()) {
                if (entry.isDirectory) continue
                if (entry.name.startsWith("META-INF/") &&
                    entry.name.uppercase().matches(Regex("""META-INF/.*\.(RSA|DSA|EC|SF)"""))) continue
                if (entry.name == "META-INF/MANIFEST.MF") continue

                var data = restoredDexes[entry.name]?.readBytes()
                    ?: apk.getInputStream(entry).readBytes()

                if (entry.name == "AndroidManifest.xml" && shellConfig != null) {
                    data = ManifestPatcher.patch(data, shellConfig)
                }

                entries += Entry(entry.name, data, shouldStore(entry.name))
            }
        }
        println("[+] Collected ${entries.size} entries (dropped the old signature)")

        // 2. v1 signature files, these have to be in the zip before we can do v2
        val key = loadOrMakeKey(keystore, storePass, keyAlias, keyPass)
        val v1 = V1Signer.sign(entries.map { it.name to it.data }, key)
        entries.add(0, Entry("META-INF/MANIFEST.MF", v1.manifest, false))
        entries.add(1, Entry("META-INF/CERT.SF", v1.signatureFile, false))
        entries.add(2, Entry("META-INF/CERT.RSA", v1.pkcs7, false))
        println("[+] Added v1 signature (MANIFEST.MF / CERT.SF / CERT.RSA)")

        // 3. Write the aligned zip, splice in the v2/v3/v3.1 blocks, then drop the v4 idsig
        //      next to it (that one is a sidecar file, not part of the apk)
        writeAlignedZip(entries, outputApk)
        val signed = ApkSigningBlock.sign(outputApk, key)
        if (writeV4) {
            V4Signer.sign(outputApk, key, signed.digest, signed.contents, signed.centralDir, signed.eocd)
        }

        println("[+] Rebuilt apk: ${outputApk.absolutePath} (${outputApk.length()} bytes)")
        return outputApk
    }

    private fun loadOrMakeKey(keystore: File?, storePass: String, alias: String?, keyPass: String): SigningKey {
        return if (keystore != null && keystore.isFile) {
            SigningKey.fromKeyStore(keystore, storePass, alias, keyPass)
        } else {
            SigningKey.generateSelfSigned()
        }
    }

    /**
     * Writes out the zip with stored entries aligned.
     *
     * Padding goes in the local header's extra field, so the entry data itself starts on the
     * boundary we want
     */
    private fun writeAlignedZip(entries: List<Entry>, outputApk: File) {
        val out = ByteArrayOutputStream()
        val offsets = mutableListOf<Int>()
        val deflated = mutableListOf<ByteArray?>()

        for (entry in entries) {
            val nameBytes = entry.name.toByteArray(Charsets.UTF_8)
            val crc = CRC32().also { it.update(entry.data) }.value

            val payload = if (entry.stored) null else deflate(entry.data)
            deflated += payload

            // Pad the extra field so (header + name + extra) lands on the boundary
            var extra = 0
            if (entry.stored) {
                val align = alignmentFor(entry.name)
                val dataStart = out.size() + 30 + nameBytes.size
                extra = (align - (dataStart % align)) % align
            }

            offsets += out.size()
            out.write(u32(LFH_SIG)); out.write(u16(20)); out.write(u16(0))
            out.write(u16(if (entry.stored) 0 else 8))
            out.write(u16(0)); out.write(u16(0))                        // no timestamps, keeps it reproducible
            out.write(u32(crc.toInt()))
            out.write(u32((payload?.size ?: entry.data.size)))
            out.write(u32(entry.data.size))
            out.write(u16(nameBytes.size)); out.write(u16(extra))
            out.write(nameBytes)
            if (extra > 0) out.write(ByteArray(extra))
            out.write(payload ?: entry.data)
        }

        // Central directory
        val cdOffset = out.size()
        for ((i, entry) in entries.withIndex()) {
            val nameBytes = entry.name.toByteArray(Charsets.UTF_8)
            val crc = CRC32().also { it.update(entry.data) }.value

            out.write(u32(CDH_SIG)); out.write(u16(20)); out.write(u16(20)); out.write(u16(0))
            out.write(u16(if (entry.stored) 0 else 8))
            out.write(u16(0)); out.write(u16(0))
            out.write(u32(crc.toInt()))
            out.write(u32(deflated[i]?.size ?: entry.data.size))
            out.write(u32(entry.data.size))
            out.write(u16(nameBytes.size)); out.write(u16(0)); out.write(u16(0))
            out.write(u16(0)); out.write(u16(0)); out.write(u32(0))
            out.write(u32(offsets[i]))
            out.write(nameBytes)
        }
        val cdSize = out.size() - cdOffset

        out.write(u32(EOCD_SIG)); out.write(u16(0)); out.write(u16(0))
        out.write(u16(entries.size)); out.write(u16(entries.size))
        out.write(u32(cdSize)); out.write(u32(cdOffset)); out.write(u16(0))

        outputApk.writeBytes(out.toByteArray())
    }

    private fun deflate(data: ByteArray): ByteArray {
        val deflater = Deflater(Deflater.DEFAULT_COMPRESSION, true)      // raw, no zlib wrapper
        deflater.setInput(data)
        deflater.finish()

        val out = ByteArrayOutputStream()
        val buf = ByteArray(16 * 1024)
        while (!deflater.finished()) {
            val n = deflater.deflate(buf)
            out.write(buf, 0, n)
        }
        deflater.end()

        return out.toByteArray()
    }

    private fun u16(v: Int) = byteArrayOf((v and 0xFF).toByte(), ((v shr 8) and 0xFF).toByte())
    private fun u32(v: Int) = byteArrayOf(
        (v and 0xFF).toByte(), ((v shr 8) and 0xFF).toByte(),
        ((v shr 16) and 0xFF).toByte(), ((v ushr 24) and 0xFF).toByte()
    )
}
