package io.isaacgc.dpt_extractor

import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.zip.ZipFile
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec


class ShellConfig(val appName: String?, val acfName: String?) {

    companion object {
        // Older builds just drop these in as plain text files
        private const val PLAIN_APP_NAME = "assets/app_name"
        private const val PLAIN_ACF_NAME = "assets/app_acf"

        // Reads whatever config the apk happens to be using, or null if there isn't one
        fun read(apkFile: File): ShellConfig? {
            ZipFile(apkFile).use { apk ->
                // Old builds: two plain text assets, nothing to decrypt
                val plainApp = apk.getEntry(PLAIN_APP_NAME)?.let {
                    apk.getInputStream(it).readBytes().toString(Charsets.UTF_8).trim()
                }
                if (!plainApp.isNullOrBlank()) {
                    val plainAcf = apk.getEntry(PLAIN_ACF_NAME)?.let {
                        apk.getInputStream(it).readBytes().toString(Charsets.UTF_8).trim()
                    }
                    println("[+] Shell config (plain): app_name=$plainApp")
                    return ShellConfig(plainApp, plainAcf)
                }

                // Newer builds: a json blob encrypted with the key exported by the shell .so
                val key = findShellKey(apk) ?: return null
                val json = decryptConfig(apk, key) ?: return null

                val appName = jsonString(json, "app_name")
                val acfName = jsonString(json, "acf_name")
                println("[+] Shell config (decrypted): app_name=$appName")
                return ShellConfig(appName, acfName)
            }
        }

        // Pulls the 16 byte DPT_*_DATA symbol out of the packer's .so
        private fun findShellKey(apk: ZipFile): ByteArray? {
            for (entry in apk.entries()) {
                if (!entry.name.startsWith("assets/") || !entry.name.endsWith(".so")) continue
                val elf = apk.getInputStream(entry).readBytes()
                readKeySymbol(elf)?.let {
                    println("[+] Shell key from ${entry.name}: ${it.joinToString("") { b -> "%02x".format(b) }}")
                    return it
                }
            }
            return null
        }

        private fun readKeySymbol(elf: ByteArray): ByteArray? {
            if (elf.size < 64 || elf[0] != 0x7F.toByte() || elf[4].toInt() != 2) return null   // ELF64 only
            val bb = ByteBuffer.wrap(elf).order(ByteOrder.LITTLE_ENDIAN)

            val shoff = bb.getLong(0x28).toInt()
            val shentsize = bb.getShort(0x3A).toInt()
            val shnum = bb.getShort(0x3C).toInt()
            val shstrndx = bb.getShort(0x3E).toInt()
            if (shoff <= 0 || shnum <= 0 || shstrndx >= shnum) return null

            fun sectionName(idx: Int): Int = bb.getInt(shoff + idx * shentsize)
            fun sectionOff(idx: Int): Int = bb.getLong(shoff + idx * shentsize + 0x18).toInt()
            fun sectionSize(idx: Int): Int = bb.getLong(shoff + idx * shentsize + 0x20).toInt()
            fun sectionType(idx: Int): Int = bb.getInt(shoff + idx * shentsize + 4)
            fun sectionAddr(idx: Int): Int = bb.getLong(shoff + idx * shentsize + 0x10).toInt()

            val shstr = sectionOff(shstrndx)
            fun nameAt(base: Int, off: Int): String {
                var end = base + off
                while (end < elf.size && elf[end].toInt() != 0) end++
                return String(elf, base + off, end - (base + off), Charsets.US_ASCII)
            }

            var dynsym = -1
            var dynstr = -1
            for (i in 0 until shnum) {
                when (nameAt(shstr, sectionName(i))) {
                    ".dynsym" -> dynsym = i
                    ".dynstr" -> dynstr = i
                }
            }
            if (dynsym < 0 || dynstr < 0) return null

            // vaddr -> file offset, the key lives in .data so the two don't line up
            fun vaddrToOffset(va: Int): Int? {
                for (i in 0 until shnum) {
                    val addr = sectionAddr(i)
                    if (addr != 0 && sectionType(i) != 8 && va >= addr && va < addr + sectionSize(i)) {
                        return sectionOff(i) + (va - addr)
                    }
                }
                return null
            }

            val symOff = sectionOff(dynsym)
            for (i in 0 until sectionSize(dynsym) / 24) {
                val base = symOff + i * 24
                val nameIdx = bb.getInt(base)
                val value = bb.getLong(base + 8).toInt()
                val size = bb.getLong(base + 16).toInt()
                if (value == 0 || size < 16) continue

                val symName = nameAt(sectionOff(dynstr), nameIdx)
                if (symName.matches(Regex("""DPT_[A-Z0-9_]*DATA"""))) {
                    val off = vaddrToOffset(value) ?: continue
                    return elf.copyOfRange(off, off + 16)
                }
            }
            return null
        }

        /**
         * The config asset name gets randomized on some builds, so we just try every small
         * 16-aligned asset and keep whichever one decrypts to json (i.e bruteforce the crap out of it)
         */
        private fun decryptConfig(apk: ZipFile, key: ByteArray): String? {
            val iv = key.copyOf().also { it[3] = 0x2f; it[9] = 0x76 }   // KeyUtils.generateIV

            for (entry in apk.entries()) {
                if (!entry.name.startsWith("assets/")) continue
                val data = apk.getInputStream(entry).readBytes()
                if (data.isEmpty() || data.size % 16 != 0 || data.size > 0x10000) continue

                try {
                    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
                    cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
                    val plain = String(cipher.doFinal(data), Charsets.UTF_8)
                    if (plain.startsWith("{")) return plain
                } catch (_: Exception) {
                    // wrong asset, keep looking
                }
            }
            return null
        }

        // Tiny json field grab, not worth pulling in a whole parser for two strings
        private fun jsonString(json: String, field: String): String? {
            val m = Regex(""""$field"\s*:\s*"([^"]*)"""").find(json) ?: return null
            return m.groupValues[1].ifBlank { null }
        }
    }
}
