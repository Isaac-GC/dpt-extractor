package io.isaacgc.dpt_extractor

import io.isaacgc.dpt_extractor.DexCodeBlock
import java.nio.ByteBuffer
import java.nio.ByteOrder

object Parser {

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

        val blocks = mutableListOf<DexCodeBlock>()

        for (dexIdx in 0 until dexCount) {
            val blockOffset = offsets[dexIdx]
            val methodCount = (data[blockOffset].toInt().and(0xFF))
                                .or((data[blockOffset + 1].toInt().and(0xFF)) shl 8)

            val records = mutableMapOf<Int, InstructionRecord>()
            var pos = blockOffset + 2

            repeat(methodCount) {
                val methodIdx = ByteBuffer.wrap(data, pos, 4).order(ByteOrder.LITTLE_ENDIAN).int

                var verOffset = 0
                var offsetDexIdx = 0
                if (version == 1) {
                    verOffset += 4 // verOffset should be: v1 = 4, v2 = 0
                    offsetDexIdx = ByteBuffer.wrap(data, 4, 4).order(ByteOrder.LITTLE_ENDIAN).int
                }

                verOffset += 4 // v1 = 8, v2 = 4
                val insnsBytes = ByteBuffer.wrap(data, pos + verOffset, 4).order(ByteOrder.LITTLE_ENDIAN).int

                verOffset += 4 // v1 = 12, v2 = 8
                val insns = data.copyOfRange(pos + verOffset, pos + verOffset + insnsBytes)
                records[methodIdx] = InstructionRecord(methodIdx, offsetDexIdx, insnsBytes, insns)
                pos += (verOffset + insnsBytes)
            }

            blocks += DexCodeBlock(dexIdx, records)
        }

        return blocks
    }

}