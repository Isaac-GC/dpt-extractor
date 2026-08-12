package io.isaacgc.dpt_extractor.signing

import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest


object ApkSigningBlock {

    private const val BLOCK_MAGIC = "APK Sig Block 42"
    private const val CHUNK_SIZE = 1024 * 1024
    private const val EOCD_SIG = 0x06054b50

    // What v4 needs afterwards to build its idsig -- the digest plus the final file layout
    class Signed(val digest: ByteArray, val contents: ByteArray,
                 val centralDir: ByteArray, val eocd: ByteArray)

    // Rewrites `apk` in place with the v2, v3 and v3.1 blocks added
    fun sign(apk: File, key: SigningKey): Signed {
        val data = apk.readBytes()

        val eocdOff = findEocd(data) ?: error("No EOCD found, is ${apk.name} a zip?")
        val cdOff = readU32(data, eocdOff + 16).toInt()
        val cdSize = readU32(data, eocdOff + 12).toInt()

        val contents = data.copyOfRange(0, cdOff)                    // section 1: the entries
        val centralDir = data.copyOfRange(cdOff, cdOff + cdSize)     // section 2
        val eocd = data.copyOfRange(eocdOff, data.size)              // section 3

        val digest = computeDigest(contents, centralDir, eocd)

        val block = buildBlock(listOf(
            V2Signer.BLOCK_ID to V2Signer.blockValue(digest, key),
            V3Signer.BLOCK_ID to V3Signer.blockValue(digest, key,
                V3Signer.MIN_SDK, V3Signer.MIN_SDK_V31 - 1, rotationMinSdk = V3Signer.MIN_SDK_V31),
            V3Signer.BLOCK_ID_V31 to V3Signer.blockValue(digest, key,
                V3Signer.MIN_SDK_V31, V3Signer.MAX_SDK)
        ))

        val patchedEocd = eocd.copyOf()
        writeU32(patchedEocd, 16, (cdOff + block.size).toLong())

        ByteArrayOutputStream().use { out ->
            out.write(contents)
            out.write(block)
            out.write(centralDir)
            out.write(patchedEocd)
            apk.writeBytes(out.toByteArray())
        }

        println("[+] Added v2 + v3 + v3.1 signature blocks (${block.size} bytes)")

        // v4 hashes the file as it now sits on disk, so hand back the sections with the block in
        return Signed(digest, contents + block, centralDir, patchedEocd)
    }

    private fun buildBlock(pairs: List<Pair<Int, ByteArray>>): ByteArray {
        val body = ByteArrayOutputStream()
        for ((id, value) in pairs) {
            body.write(Blocks.u64((4 + value.size).toLong()))
            body.write(Blocks.u32(id))
            body.write(value)
        }

        val payload = body.toByteArray()
        val blockSize = (payload.size + 8 + 16).toLong() // trailing size + magic

        return ByteArrayOutputStream().apply {
            write(Blocks.u64(blockSize))
            write(payload)
            write(Blocks.u64(blockSize))
            write(BLOCK_MAGIC.toByteArray(Charsets.US_ASCII))
        }.toByteArray()
    }

    /**
     * Note for future: Chop all three sections into 1MB chunks, hash each one with a 0xa5 prefix, then hash the
     * concatenated chunk digests with a 0x5a prefix
     */
    private fun computeDigest(vararg sections: ByteArray): ByteArray {
        val md = MessageDigest.getInstance("SHA-256")
        val chunkDigests = ByteArrayOutputStream()
        var chunkCount = 0

        for (section in sections) {
            var off = 0
            while (off < section.size) {
                val size = minOf(CHUNK_SIZE, section.size - off)
                md.reset()
                md.update(0xa5.toByte())
                md.update(Blocks.u32(size))
                md.update(section, off, size)
                chunkDigests.write(md.digest())
                chunkCount++
                off += size
            }
        }

        md.reset()
        md.update(0x5a.toByte())
        md.update(Blocks.u32(chunkCount))
        md.update(chunkDigests.toByteArray())
        return md.digest()
    }

    private fun readU32(data: ByteArray, off: Int): Long =
        ByteBuffer.wrap(data, off, 4).order(ByteOrder.LITTLE_ENDIAN).int.toLong() and 0xFFFFFFFFL

    private fun writeU32(data: ByteArray, off: Int, value: Long) {
        ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN).putInt(off, value.toInt())
    }

    // Walks back from the end looking for the end-of-central-directory record
    private fun findEocd(data: ByteArray): Int? {
        val minOff = maxOf(0, data.size - 65557) // max comment length + the record itself
        for (i in data.size - 22 downTo minOff) {
            if (readU32(data, i).toInt() == EOCD_SIG) return i
        }
        return null
    }
}
