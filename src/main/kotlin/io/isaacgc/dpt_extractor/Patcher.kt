package io.isaacgc.dpt_extractor

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.util.zip.Adler32

class Patcher(originalBytes: ByteArray) {

    companion object {
        private val DEX_MAGIC_BYTES = "dex\n".toByteArray()
    }

    fun getBytes(): ByteArray = buffer

    private val buffer: ByteArray = originalBytes.copyOf()

    private val methodToCodeOffset: Map<Int, Int> by lazy { buildMethodMap() }

    // ====================================================

    private fun isDex(data: ByteArray): Boolean {
        return data.size >= 4
                && data.copyOf(4).contentEquals(DEX_MAGIC_BYTES)
    }

    private fun readUleb128(pos: Int): Pair<Int, Int> {
        var result = 0
        var shift = 0
        var cur_pos = pos

        while (true) {
            val b = buffer[cur_pos++].toInt() and 0xFF
            result = result.or((b.and(0x7F) shl shift))
            if (b.and(0x80) == 0) break
            shift += 7
        }

        return result to cur_pos
    }

    private fun buildMethodMap(): Map<Int, Int> {
        val map = mutableMapOf<Int, Int>()
        val basicBlock = ByteBuffer.wrap(buffer).order(ByteOrder.LITTLE_ENDIAN)

        // This is based off of the dex file header items
        // https://source.android.com/docs/core/runtime/dex-format#header-item
        val classDefSize = basicBlock.getInt(96)
        val classDefOffset = basicBlock.getInt(100)

        for (clazz in 0 until classDefSize) {
            val base = classDefOffset + clazz * 32
            val classDataOff = basicBlock.getInt(base + 24)
            if (classDataOff == 0) continue

            var pos = classDataOff
            val (staticFieldsSize, p1) = readUleb128(pos); pos = p1
            val (instanceFieldsSize, p2) = readUleb128(pos); pos = p2
            val (directMethodsSize, p3) = readUleb128(pos); pos = p3
            val (virtualMethodsSize, p4) = readUleb128(pos); pos = p4

            repeat(staticFieldsSize + instanceFieldsSize) {
                val (_, p5) = readUleb128(pos); pos = p5 // field_idx_diff
                val (_, p6) = readUleb128(pos); pos = p6 // access flags
            }

            var methodIdx = 0
            repeat(directMethodsSize) {
                val (delta, p5) = readUleb128(pos); pos = p5; methodIdx += delta
                val (_, p6) = readUleb128(pos); pos = p6 // access flags
                val (codeOffset, p7) = readUleb128(pos); pos = p7

                // If codeOffset is 0,
                //      that means there is no code for the method
                if (codeOffset != 0) {
                    map[methodIdx] = codeOffset
                }
            }

            methodIdx = 0
            repeat(virtualMethodsSize) {
                val (delta, p5) = readUleb128(pos); pos = p5; methodIdx += delta
                val (_, p6) = readUleb128(pos); pos = p6 // access flags
                val (codeOffset, p7) = readUleb128(pos); pos = p7

                // If codeOffset is 0,
                //      that means there is no code for the method
                if (codeOffset != 0) {
                    map[methodIdx] = codeOffset
                }
            }
        }

        return map
    }

    fun applyBlock(block: DexCodeBlock, dexFileName: String): PatchResult {
        var numPatched = 0
        var numSkipped = 0

        for ((methodIdx, record) in block.records) {
            if (record.insnsSize == 0) {
                numSkipped++
                continue
            }


            val insnsOffset = if (record.offsetDexIdx != 0) {
                // v1
                record.offsetDexIdx
            } else {
                // v2
                val codeOffset = methodToCodeOffset[methodIdx]
                if (codeOffset == null) {
                    System.err.println("[X] Warning -- $dexFileName: method $methodIdx not found in DEX content")
                    numSkipped++
                    continue
                }
                codeOffset + 16
            }


            val insnsEnd = insnsOffset + record.insnsSize
            if (insnsEnd > buffer.size) {
                System.err.println("[X] Warning -- $dexFileName: method $methodIdx insns is out of bounds")
                numSkipped++
                continue
            }

            record.insnsData.copyInto(buffer, insnsOffset)
            numPatched++
        }

        return PatchResult(
            dexFileName,
            block.records.size,
            numPatched,
            numSkipped,
        )
    }

    fun fixHeader() {
        if (buffer.size < 36) return
        val sha1 = MessageDigest.getInstance("SHA-1").digest(buffer.copyOfRange(32, buffer.size))
        sha1.copyInto(buffer, destinationOffset = 12)

        val adler = Adler32().also {
            it.update(buffer, 12, buffer.size - 12)
        }

        ByteBuffer.wrap(buffer).order(ByteOrder.LITTLE_ENDIAN).putInt(8, adler.value.toInt())

    }

}