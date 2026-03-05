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
                val insnsBytes = ByteBuffer.wrap(data, pos + 4, 4).order(ByteOrder.LITTLE_ENDIAN).int
//                val insnsBytes = insnsCodeUnits * 2

                val insns = data.copyOfRange(pos + 8, pos + 8 + insnsBytes)
                records[methodIdx] = InstructionRecord(methodIdx, insnsBytes, insns)
                pos += (8 + insnsBytes)
            }

            blocks += DexCodeBlock(dexIdx, records)
        }

        return blocks
    }

}