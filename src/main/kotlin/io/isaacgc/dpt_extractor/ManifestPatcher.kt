package io.isaacgc.dpt_extractor

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder


object ManifestPatcher {

    private const val CHUNK_STRING_POOL = 0x0001
    private const val CHUNK_START_ELEMENT = 0x0102

    private const val FLAG_UTF8 = 0x100

    fun patch(manifest: ByteArray, config: ShellConfig): ByteArray {
        if (config.appName.isNullOrBlank()) return manifest

        val pool = readStringPool(manifest) ?: run {
            System.err.println("[X] Warning -- couldn't read the manifest string pool, leaving it alone")
            return manifest
        }

        // Find what <application android:name> currently points at
        val appNameIdx = findApplicationAttr(manifest, pool, "name")
        if (appNameIdx == null) {
            System.err.println("[X] Warning -- no <application android:name> found, leaving the manifest alone")
            return manifest
        }

        val current = pool.strings[appNameIdx]
        if (current == config.appName) {
            println("[+] Manifest already points at ${config.appName}")
            return manifest
        }

        val replacements = mutableMapOf(appNameIdx to config.appName)
        println("[+] Manifest: application $current --> ${config.appName}")

        // The component factory gets hijacked the same way on newer builds
        if (!config.acfName.isNullOrBlank()) {
            findApplicationAttr(manifest, pool, "appComponentFactory")?.let { idx ->
                if (pool.strings[idx] != config.acfName) {
                    println("[+] Manifest: appComponentFactory ${pool.strings[idx]} --> ${config.acfName}")
                    replacements[idx] = config.acfName
                }
            }
        }

        return rewriteStringPool(manifest, pool, replacements)
    }

    private class StringPool(val offset: Int, val size: Int, val strings: MutableList<String>,
                             val isUtf8: Boolean, val styleCount: Int, val stylesStart: Int,
                             val stringsStart: Int)

    private fun readStringPool(data: ByteArray): StringPool? {
        val bb = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN)
        if (data.size < 8) return null

        // The pool is the first chunk after the file header
        var off = 8
        while (off + 8 <= data.size) {
            val type = bb.getShort(off).toInt() and 0xFFFF
            val size = bb.getInt(off + 4)
            if (size <= 0 || off + size > data.size) return null

            if (type == CHUNK_STRING_POOL) {
                val count = bb.getInt(off + 8)
                val styleCount = bb.getInt(off + 12)
                val flags = bb.getInt(off + 16)
                val stringsStart = bb.getInt(off + 20)
                val stylesStart = bb.getInt(off + 24)
                val utf8 = (flags and FLAG_UTF8) != 0

                val strings = mutableListOf<String>()
                for (i in 0 until count) {
                    val strOff = off + stringsStart + bb.getInt(off + 28 + i * 4)
                    strings += if (utf8) readUtf8(data, strOff) else readUtf16(data, bb, strOff)
                }
                return StringPool(off, size, strings, utf8, styleCount, stylesStart, stringsStart)
            }
            off += size
        }
        return null
    }

    private fun readUtf8(data: ByteArray, off: Int): String {
        var p = off
        // Two length fields (chars then bytes), each one or two bytes depending on the high bit
        if ((data[p].toInt() and 0x80) != 0) p += 2 else p += 1
        var len = data[p].toInt() and 0xFF
        if ((len and 0x80) != 0) {
            len = ((len and 0x7F) shl 8) or (data[p + 1].toInt() and 0xFF)
            p += 2
        } else {
            p += 1
        }
        return String(data, p, len, Charsets.UTF_8)
    }

    private fun readUtf16(data: ByteArray, bb: ByteBuffer, off: Int): String {
        var len = bb.getShort(off).toInt() and 0xFFFF
        var p = off + 2
        if ((len and 0x8000) != 0) {
            len = ((len and 0x7FFF) shl 16) or (bb.getShort(off + 2).toInt() and 0xFFFF)
            p += 2
        }
        return String(data, p, len * 2, Charsets.UTF_16LE)
    }

    /**
     * Walks the xml chunks looking for <application> and returns the string index its attribute
     * points at (that's the value we want to swap)
     */
    private fun findApplicationAttr(data: ByteArray, pool: StringPool, attrName: String): Int? {
        val bb = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN)
        var off = 8

        while (off + 8 <= data.size) {
            val type = bb.getShort(off).toInt() and 0xFFFF
            val size = bb.getInt(off + 4)
            if (size <= 0 || off + size > data.size) return null

            if (type == CHUNK_START_ELEMENT) {
                val nameIdx = bb.getInt(off + 20)
                if (pool.strings.getOrNull(nameIdx) == "application") {
                    val attrStart = bb.getShort(off + 24).toInt() and 0xFFFF
                    val attrSize = bb.getShort(off + 26).toInt() and 0xFFFF
                    val attrCount = bb.getShort(off + 28).toInt() and 0xFFFF

                    for (i in 0 until attrCount) {
                        // attributeStart counts from the attrExt struct, which itself starts
                        //      16 bytes into the chunk (past the node header)
                        val a = off + 16 + attrStart + i * attrSize
                        val aName = bb.getInt(a + 4)
                        val aRawValue = bb.getInt(a + 8)
                        if (pool.strings.getOrNull(aName) != attrName) continue

                        if (aRawValue >= 0) return aRawValue

                        // Some builds leave rawValue unset and only fill in the typed value
                        val dataType = (bb.get(a + 15).toInt() and 0xFF)
                        if (dataType == 0x03) return bb.getInt(a + 16)     // TYPE_STRING
                    }
                }
            }
            off += size
        }
        return null
    }

    /**
     * Rebuilds the string pool with the swapped strings.
     *
     * Everything after the pool shifts, so the file header size has to be fixed up too. The
     * offsets inside the pool all get recalculated since the new strings are a different length
     */
    private fun rewriteStringPool(data: ByteArray, pool: StringPool,
                                  replacements: Map<Int, String>): ByteArray {
        val strings = pool.strings.toMutableList()
        for ((idx, value) in replacements) strings[idx] = value

        // Encode the strings back out, keeping whatever encoding the pool was using
        val body = ByteArrayOutputStream()
        val offsets = IntArray(strings.size)
        for ((i, s) in strings.withIndex()) {
            offsets[i] = body.size()
            if (pool.isUtf8) {
                val bytes = s.toByteArray(Charsets.UTF_8)
                body.write(encodeLen8(s.length))
                body.write(encodeLen8(bytes.size))
                body.write(bytes)
                body.write(0)
            } else {
                val bytes = s.toByteArray(Charsets.UTF_16LE)
                body.write(encodeLen16(s.length))
                body.write(bytes)
                body.write(0); body.write(0)
            }
        }

        // Pool has to stay 4 byte aligned
        while (body.size() % 4 != 0) body.write(0)

        val stringsStart = 28 + strings.size * 4 + pool.styleCount * 4
        val newPoolSize = stringsStart + body.size()

        val pb = ByteBuffer.allocate(newPoolSize).order(ByteOrder.LITTLE_ENDIAN)
        pb.putShort(CHUNK_STRING_POOL.toShort())
        pb.putShort(28) // header size
        pb.putInt(newPoolSize)
        pb.putInt(strings.size)
        pb.putInt(pool.styleCount)
        pb.putInt(if (pool.isUtf8) FLAG_UTF8 else 0)
        pb.putInt(stringsStart)
        pb.putInt(if (pool.styleCount > 0) newPoolSize else 0)
        offsets.forEach { pb.putInt(it) }
        repeat(pool.styleCount) { pb.putInt(0) }
        pb.put(body.toByteArray())

        val out = ByteArrayOutputStream()
        out.write(data, 0, pool.offset)
        out.write(pb.array())
        out.write(data, pool.offset + pool.size, data.size - (pool.offset + pool.size))

        val result = out.toByteArray()
        ByteBuffer.wrap(result).order(ByteOrder.LITTLE_ENDIAN).putInt(4, result.size)  // file size
        return result
    }

    private fun encodeLen8(len: Int): ByteArray =
        if (len > 0x7F) byteArrayOf((((len shr 8) or 0x80).toByte()), (len and 0xFF).toByte())
        else byteArrayOf(len.toByte())

    private fun encodeLen16(len: Int): ByteArray =
        if (len > 0x7FFF) {
            byteArrayOf((((len shr 16) or 0x8000) and 0xFF).toByte(), ((len shr 24) and 0xFF).toByte(),
                (len and 0xFF).toByte(), ((len shr 8) and 0xFF).toByte())
        } else {
            byteArrayOf((len and 0xFF).toByte(), ((len shr 8) and 0xFF).toByte())
        }
}
