package io.isaacgc.dpt_extractor

import java.nio.ByteBuffer
import java.nio.ByteOrder

// temp fix for dpt-shell variants
private enum class V2Layout {
    METHOD_FIRST,
    SIZE_FIRST,
}

object Parser {

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

    fun parse(data: ByteArray): List<DexCodeBlock> {
        // Dex files should always be assumed to be little endian (according to the documentation at least)
        val buffer = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN)

        val version = buffer.short.toInt().and(0xFFFF)
        val dexCount = buffer.short.toInt().and(0xFFFF)

        if (version != 2) {
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
            val blockOffset = offsets[dexIdx]
            val methodCount = (data[blockOffset].toInt().and(0xFF))
                                .or((data[blockOffset + 1].toInt().and(0xFF)) shl 8)

            val records = mutableMapOf<Int, InstructionRecord>()
            var pos = blockOffset + 2

            repeat(methodCount) {
                val insnsStart: Int
                val insnsBytes: Int
                val offsetDexIdx: Int
                val methodIdx: Int

                if (version == 1) {
                    methodIdx = ByteBuffer.wrap(data, pos, 4).order(ByteOrder.LITTLE_ENDIAN).int
                    offsetDexIdx = ByteBuffer.wrap(data, pos + 4, 4).order(ByteOrder.LITTLE_ENDIAN).int
                    insnsBytes = ByteBuffer.wrap(data, pos + 8, 4).order(ByteOrder.LITTLE_ENDIAN).int
                    insnsStart = pos + 12

                } else {
                    // version 2
                    offsetDexIdx = 0


                    when (v2Layout!!) {
                        V2Layout.METHOD_FIRST -> {
                            methodIdx = ByteBuffer.wrap(data, pos, 4).order(ByteOrder.LITTLE_ENDIAN).int
                            insnsBytes = ByteBuffer.wrap(data, pos + 4, 4).order(ByteOrder.LITTLE_ENDIAN).int
                        }
                        V2Layout.SIZE_FIRST -> {
                            insnsBytes = ByteBuffer.wrap(data, pos, 4).order(ByteOrder.LITTLE_ENDIAN).int
                            methodIdx = ByteBuffer.wrap(data, pos + 4, 4).order(ByteOrder.LITTLE_ENDIAN).int
                        }
                    }
                    insnsStart = pos + 8
                }

                val insnsEnd = insnsStart + insnsBytes
                val insns = data.copyOfRange(insnsStart, insnsEnd)

                records[methodIdx] = InstructionRecord(methodIdx, offsetDexIdx, insnsBytes, insns)
                pos = insnsEnd
            }

            blocks += DexCodeBlock(dexIdx, records)
        }

        return blocks
    }

}