package io.isaacgc.dpt_extractor.signing

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

internal object Blocks {

    fun u32(v: Int): ByteArray =
        ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(v).array()

    fun u64(v: Long): ByteArray =
        ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(v).array()

    fun lenPrefixed(data: ByteArray): ByteArray = u32(data.size) + data

    fun lenPrefixedSeq(items: List<ByteArray>): ByteArray {
        val inner = ByteArrayOutputStream()
        items.forEach { inner.write(lenPrefixed(it)) }
        return lenPrefixed(inner.toByteArray())
    }

    fun algPair(sigAlgId: Int, data: ByteArray): ByteArray = u32(sigAlgId) + lenPrefixed(data)
}
