package io.isaacgc.dpt_extractor

import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.zip.ZipFile

class ApkExtractor {

    companion object {
        private const val PACKED_DEX_FILE = "assets/OoooooOooo"
        private const val OUTER_DEX_FILE = "classes.dex"

        fun dexIndex(filename: String): Int {
            val base = File(filename).name
            val m = Regex("""classes(\d*)\.dex""").find(base) ?: return -1
            val num = m.groupValues[1]

            return if (num.isEmpty()) 0 else num.toInt() - 1
        }
    }

    private fun Int.humanSize() = when {
        this >= 1_048_576 -> "%.1f MB".format(this / 1_048_576.0)
        this >= 1_024 -> "%.1f KB".format(this / 1_024.0)
        else -> "$this B"
    }

    private fun extractInnerZip(outerDex: ByteArray): ByteArray {
        val zipfileLen = ByteBuffer.wrap(outerDex, outerDex.size - 4, 4)
            .order(ByteOrder.BIG_ENDIAN).int
        require(zipfileLen > 0 && zipfileLen + 4 <= outerDex.size) {
            "Invalid Inner ZIP length: $zipfileLen (classes.dex size ${outerDex.size})"
        }
        val zipStart = outerDex.size - zipfileLen - 4
        return outerDex.copyOfRange(zipStart, zipStart + zipfileLen)
    }

    fun extractApk(apkFile: File, outputDir: File): List<PatchResult> {
        println("[+] Opening ${apkFile.absolutePath}")
        outputDir.mkdirs()

        return ZipFile(apkFile).use { apk ->
            val packedDexEntry = apk.getEntry(PACKED_DEX_FILE) ?: error("$PACKED_DEX_FILE not found")
            val packedDexData  = apk.getInputStream(packedDexEntry).readBytes()
            println("[+] Found packed dex file: $PACKED_DEX_FILE")

            val blocks   = Parser.parse(packedDexData)
            val blockMap = blocks.associateBy { it.dexIndex }
            println("[*] Packed dex file covers ${blocks.size} DEX slot(s):")
            blocks.forEach { block ->
                val name  = if (block.dexIndex == 0) "classes.dex" else "classes${block.dexIndex + 1}.dex"
                val bytes = block.records.values.map { it.insnsSize }.sum()
                println("\tdex[${block.dexIndex}] ($name): ${block.records.size} methods, ${bytes.humanSize()} insns")
            }

            var outerDexEntry = apk.getEntry(OUTER_DEX_FILE) ?: error("$OUTER_DEX_FILE not found in the APK")
            val outerDex      = apk.getInputStream(outerDexEntry).readBytes()
            val innerZipData  = extractInnerZip(outerDex)

            val results = mutableListOf<PatchResult>()
            val tmpZip = File.createTempFile("dpt_inner_", ".zip").also {
                it.deleteOnExit()
                it.writeBytes(innerZipData)
            }

            ZipFile(tmpZip).use { inner ->
                val dexEntries = inner.entries().asSequence()
                    .filter { it.name.endsWith(".dex") }
                    .sortedBy { dexIndex(it.name) }
                    .toList()

                println("[+] Inner zip contains ${dexEntries.size} dex file(s)\n")
                for (entry in dexEntries) {
                    val idx = dexIndex(entry.name)
                    val dexBytes = inner.getInputStream(entry).readBytes()
                    val block = blockMap[idx]

                    println("[+] ${entry.name} (idx=$idx) ${dexBytes.size.humanSize()}" +
                            if (block != null) " -> ${block.records.size} patch(es)"
                            else " -> no patches")

                    val patcher = Patcher(dexBytes)
                    val result = if (block != null) {
                        patcher.applyBlock(block, entry.name).also { result ->
                            println("\tApplied ${result.patchedCount}/${result.totalRecords} patches" +
                                if (result.skippedCount > 0) " (${result.skippedCount} skipped)"
                                else "")
                        }
                    } else {
                        // Return empty patch result --> TODO: Find a better alternative
                        PatchResult(entry.name, 0, 0, 0)
                    }

                    patcher.fixHeader()
                    val outFile = File(outputDir, entry.name)
                    outFile.writeBytes(patcher.getBytes())
                    println("\tSaved: ${outFile.path} (${patcher.getBytes().size.humanSize()}")

                    results += result
                }
            }

            println("\n=== | Summary | ===")
            val total = results.map { it.patchedCount }.sum()
            for (res in results ) {
                if (res.totalRecords > 0) {
                    val patchedPercent = (res.patchedCount * 100) / res.totalRecords
                    println("\t${res.dexFilename}: ${res.patchedCount}/${res.totalRecords} methods restored ($patchedPercent%)")
                } else {
                    println("\t${res.dexFilename}: no patches needed or were applied")
                }
            }

            println("[+] $total total patches applied")
            println("[+] Output: ${outputDir.absolutePath}")
            results
        }
    }


}