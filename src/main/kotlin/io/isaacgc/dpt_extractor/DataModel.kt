package io.isaacgc.dpt_extractor

data class DexCodeBlock(
    /**
     * dexIndex:
     *      0 = classes.dex
     *      1 = classes2.dex
     *      N = classes(N + 1).dex
     */
    val dexIndex: Int,

    // method patches keyed via the method_idx for O(1) lookup
    val records: Map<Int, InstructionRecord>,
)

// Result of patching a single dex file
data class PatchResult(
    val dexFilename: String,
    val totalRecords: Int,
    val patchedCount: Int,
    val skippedCount: Int,
)

data class InstructionRecord(
    // u32 - methodIndex
    val methodIndex: Int,
    // u32 insnsDataSize
    val insnsSize: Int,
    // u8 insnsData[insnsSize] --> should be all the instructions
    val insnsData: ByteArray,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is InstructionRecord) return false

        return methodIndex == other.methodIndex
                && insnsSize == other.insnsSize
                && insnsData.contentEquals(other.insnsData)
    }

    override fun hashCode(): Int {
        var r = methodIndex
        r = 31 * r + insnsSize
        r = 31 * r + insnsData.contentHashCode()
        return r
    }

    override fun toString(): String {
        return "io.isaacgc.dpt_extractor.InstructionRecord(methodIndex=$methodIndex, insnsSize=$insnsSize)"
    }
}