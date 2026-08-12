package io.isaacgc.dpt_extractor.signing

import java.io.ByteArrayOutputStream
import java.security.MessageDigest

internal object VerityTree {

    const val BLOCK_SIZE = 4096
    private const val DIGEST_SIZE = 32

   // Root hash over the given sections (they're treated as one continuous stream)
    fun rootHash(vararg sections: ByteArray): ByteArray {
        val data = ByteArrayOutputStream().apply { sections.forEach { write(it) } }.toByteArray()

        var level = hashBlocks(data)
        while (level.size > DIGEST_SIZE) {
            level = hashBlocks(level)
        }

        return level
    }

    fun verityDigest(rootHash: ByteArray, size: Long): ByteArray {
        val md = MessageDigest.getInstance("SHA-256")
        md.update(rootHash)
        md.update(Blocks.u64(size))
        return md.digest()
    }

    // Zero pads out to a block boundary, then hashes each block and concatenates the digests
    private fun hashBlocks(data: ByteArray): ByteArray {
        val md = MessageDigest.getInstance("SHA-256")
        val out = ByteArrayOutputStream()

        var off = 0
        while (off < data.size) {
            val size = minOf(BLOCK_SIZE, data.size - off)
            md.reset()
            md.update(data, off, size)
            if (size < BLOCK_SIZE) md.update(ByteArray(BLOCK_SIZE - size)) // pad the tail block
            out.write(md.digest())
            off += BLOCK_SIZE
        }

        return out.toByteArray()
    }
}
