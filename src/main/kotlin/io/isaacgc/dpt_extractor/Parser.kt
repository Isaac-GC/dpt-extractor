package io.isaacgc.dpt_extractor

import java.nio.ByteBuffer
import java.nio.ByteOrder

// temp fix for dpt-shell variants
private enum class V2Layout {
    METHOD_FIRST,
    SIZE_FIRST,
}

object Parser {

    // Helpers (for sanity reasons)
    private fun u16(data: ByteArray, offset: Int): Int {
        return (data[offset].toInt().and(0xFF)) or ((data[offset + 1].toInt().and(0xFF)).shl(8))
    }

    private fun i32(data: ByteArray, offset: Int): Int {
        return ByteBuffer.wrap(data, offset, 4).order(ByteOrder.LITTLE_ENDIAN).int
    }

    private fun errorOutMisaligned(dexIdx: Int, recIdx: Int, methodCount: Int, pos: Int, detail: String): Nothing {
        error("Parser misaligned at dex[$dexIdx] record $recIdx/$methodCount: pos=$pos, $detail")
    }

    // Used as temp fix for dpt-shell variants
    private fun canWalkV2Block(data: ByteArray, blockOffset: Int, blockEnd: Int, layout: V2Layout): Boolean {
        if (blockOffset + 2 > data.size) return false
        val methodCount = (data[blockOffset].toInt() and 0xFF) or
                ((data[blockOffset + 1].toInt() and 0xFF) shl 8)
        var pos = blockOffset + 2 // try to align properly
        repeat(methodCount) {
            if (pos + 8 > blockEnd) return false
            val size = when (layout) {
                V2Layout.METHOD_FIRST -> ByteBuffer.wrap(data, pos + 4, 4).order(ByteOrder.LITTLE_ENDIAN).int
                V2Layout.SIZE_FIRST -> ByteBuffer.wrap(data, pos, 4).order(ByteOrder.LITTLE_ENDIAN).int
            }
            if (size < 0) return false
            pos += 8 + size
            if (pos > blockEnd) return false
        }
        return pos == blockEnd
    }

    private fun detectXorBS(blocks: List<DexCodeBlock>): Int {
        val freq = IntArray(256) // Just get all possible XOR keys (... at least ofr simple xor key implementations)
        var total = 0L
        for (block in blocks) {
            for (( _, rec ) in block.records) {
                for (b in rec.insnsData) {
                    freq[b.toInt().and(0xFF)]++
                    total++
                }
            }
        }
        if (total < 64) return 0
        val dominant = freq.indices.maxBy { freq[it] }
        return if (dominant != 0 && freq[dominant].toLong() * 10 >= total) dominant else 0
    }

    private fun readBlock(
        data: ByteArray,
        blockOffset: Int,
        blockEnd: Int,
        dexIdx: Int,
        version: Int,
        v2Layout: V2Layout?): Map<Int, InstructionRecord>  {

        val methodCount = u16(data, blockOffset)
        val records = mutableMapOf<Int, InstructionRecord>()
        var pos = blockOffset + 2

        repeat(methodCount) {
            val methodIdx: Int
            val offsetDexIdx: Int
            val insnsBytes: Int
            val isnsnStart: Int

            if (version == 1) {
                if (pos + 12 > blockEnd) errorOutMisaligned(dexIdx, it, methodCount, pos, "Header runs past block end")

                methodIdx = i32(data, pos)
                offsetDexIdx = i32(data, pos + 4)
                insnsBytes = i32(data, pos + 8)
                isnsnStart = i32(data, pos + 12)

            } else { // V2 crap
                if (pos + 8 > blockEnd) errorOutMisaligned(dexIdx, it, methodCount, pos, "Header runs past block end")

                offsetDexIdx = 0
                when (v2Layout!!) {
                    V2Layout.METHOD_FIRST -> {
                        methodIdx = i32(data, pos)
                        insnsBytes = i32(data, pos + 4)
                    }
                    V2Layout.SIZE_FIRST -> {
                        insnsBytes = i32(data, pos)
                        methodIdx = i32(data, pos + 4)
                    }
                }
                isnsnStart = pos + 8
            }

            val insnsEnd = isnsnStart + insnsBytes
            if (insnsBytes < 0 || insnsEnd > blockEnd) {
                errorOutMisaligned(dexIdx, it, methodCount, pos,
                    "methodIdx=$methodIdx insnsBytes=$insnsBytes insnsEnd=$insnsEnd (0x${"%x".format(insnsBytes)}) " +
                "reads past block end (insnsEnd=$insnsEnd, blockEnd=$blockEnd)")
            }

            records[methodIdx] = InstructionRecord(methodIdx, offsetDexIdx, insnsBytes, data.copyOfRange(isnsnStart, insnsEnd))
            pos = insnsEnd
        }
        return records
    }

    fun parse(data: ByteArray): List<DexCodeBlock> {
        // Dex files should always be assumed to be little endian (according to the documentation at least)
        val buffer = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN)

        val version = buffer.short.toInt().and(0xFFFF)
        val dexCount = buffer.short.toInt().and(0xFFFF)

        if (version != 1 && version != 2) {
            System.err.println("[X] Warning - Unexpected dex file version ${version}... continuing")
        }

        val offsets = IntArray(dexCount) {
            buffer.int
        }

        // Adding this in for temp fix (dpt-shell variant bs)
        val blockEnds = IntArray(dexCount) { i ->
            if (i + 1 < dexCount) offsets[i + 1]
            else data.size
        }

        val v2Layout: V2Layout? = if (version == 2) {
            val firstBlock = offsets[0]
            val firstEndBlock = blockEnds[0]
            listOf(V2Layout.METHOD_FIRST, V2Layout.SIZE_FIRST)
                .firstOrNull {
                    canWalkV2Block(data, firstBlock, firstEndBlock, it)
                } ?: error("Could not detect v2 record layout (blockOffset=${firstBlock})")
        } else null

        val blocks = mutableListOf<DexCodeBlock>()

        for (dexIdx in 0 until dexCount) {
            val records = readBlock(data, offsets[dexIdx], blockEnds[dexIdx], dexIdx, version, v2Layout)
            blocks += DexCodeBlock(dexIdx, records)
        }

        val xorKey = detectXorBS(blocks)
        if (xorKey != 0) {
            System.err.println("[-] Detected XOR encrypted instructions (key=0x%02x) -> decrypting...".format(xorKey))
            for (block in blocks) {
                for ((_, r) in block.records) {
                    val d = r.insnsData
                    for (i in d.indices) {
                        d[i] = (d[i].toInt().xor(xorKey)).toByte()
                    }
                }
            }
        }

        return blocks
    }

}