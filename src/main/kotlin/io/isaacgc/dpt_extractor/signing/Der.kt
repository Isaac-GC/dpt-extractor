package io.isaacgc.dpt_extractor.signing

import java.io.ByteArrayOutputStream

object Der {

    // Tags we actually use
    const val INTEGER = 0x02
    const val BIT_STRING = 0x03
    const val OCTET_STRING = 0x04
    const val NULL = 0x05
    const val OID = 0x06
    const val UTF8_STRING = 0x0C
    const val PRINTABLE_STRING = 0x13
    const val UTC_TIME = 0x17
    const val SEQUENCE = 0x30
    const val SET = 0x31

    // [n] context specific, constructed
    fun contextTag(n: Int): Int = 0xA0 or n

    /**
     * Wraps content in a tag-length-value.
     *
     * Lengths under 128 go in a single byte, anything bigger uses
     *      (0x80 or byteCount, then the length itself is big endian)
     */
    fun tlv(tag: Int, content: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(tag)

        if (content.size < 0x80) {
            out.write(content.size)
        } else {
            val lenBytes = mutableListOf<Byte>()
            var v = content.size
            while (v > 0) {
                lenBytes.add(0, (v and 0xFF).toByte())
                v = v ushr 8
            }
            out.write(0x80 or lenBytes.size)
            out.write(lenBytes.toByteArray())
        }

        out.write(content)
        return out.toByteArray()
    }

    fun seq(vararg parts: ByteArray): ByteArray = tlv(SEQUENCE, parts.concat())
    fun set(vararg parts: ByteArray): ByteArray = tlv(SET, parts.concat())
    fun explicit(n: Int, vararg parts: ByteArray): ByteArray = tlv(contextTag(n), parts.concat())

    fun int(value: Int): ByteArray {
        var v = value
        val bytes = mutableListOf<Byte>()

        do {
            bytes.add(0, (v and 0xFF).toByte())
            v = v shr 8
        } while (v != 0 && v != -1)

        // A leading high bit would read as negative, pad it out
        if (value > 0 && (bytes[0].toInt() and 0x80) != 0) bytes.add(0, 0)

        return tlv(INTEGER, bytes.toByteArray())
    }

    fun int(value: ByteArray): ByteArray {
        // Same padding rule, used for serial numbers that don't fit in an Int
        val bytes = if ((value[0].toInt() and 0x80) != 0) byteArrayOf(0) + value else value
        return tlv(INTEGER, bytes)
    }

    fun bitString(data: ByteArray): ByteArray = tlv(BIT_STRING, byteArrayOf(0) + data) // 0 unused bits
    fun octetString(data: ByteArray): ByteArray = tlv(OCTET_STRING, data)
    fun nullValue(): ByteArray = tlv(NULL, ByteArray(0))
    fun printableString(s: String): ByteArray = tlv(PRINTABLE_STRING, s.toByteArray(Charsets.US_ASCII))
    fun utcTime(s: String): ByteArray = tlv(UTC_TIME, s.toByteArray(Charsets.US_ASCII))

    fun oid(dotted: String): ByteArray {
        val arcs = dotted.split('.').map { it.toLong() }
        val out = ByteArrayOutputStream()
        out.write((arcs[0] * 40 + arcs[1]).toInt())

        for (i in 2 until arcs.size) {
            var v = arcs[i]
            val chunk = mutableListOf<Byte>()
            chunk.add((v and 0x7F).toByte())
            v = v ushr 7

            while (v > 0) {
                chunk.add(0, ((v and 0x7F) or 0x80).toByte())
                v = v ushr 7
            }
            out.write(chunk.toByteArray())
        }

        return tlv(OID, out.toByteArray())
    }

    fun algId(dottedOid: String, withNullParam: Boolean = true): ByteArray {
        return if (withNullParam) seq(oid(dottedOid), nullValue()) else seq(oid(dottedOid))
    }

    private fun Array<out ByteArray>.concat(): ByteArray {
        val out = ByteArrayOutputStream()
        forEach { out.write(it) }
        return out.toByteArray()
    }
}
