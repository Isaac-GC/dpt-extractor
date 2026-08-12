package io.isaacgc.dpt_extractor.signing

import java.io.ByteArrayOutputStream
import java.io.File


// Reference: https://source.android.com/docs/security/features/apksigning/v4
object V4Signer {

    private const val VERSION = 2
    private const val HASH_ALGORITHM_SHA256 = 1
    private const val LOG2_BLOCK_SIZE = 12 // 4096

    /**
     * Writes the idsig next to the apk.
     *
     * `apkDigest` is the chunked digest from the signing block, it's how the idsig gets matched
     * back up with the apk it belongs to
     */
    fun sign(apk: File, key: SigningKey, apkDigest: ByteArray,
             contents: ByteArray, centralDir: ByteArray, eocd: ByteArray): File {

        val rootHash = VerityTree.rootHash(contents, centralDir, eocd)
        val size = (contents.size + centralDir.size + eocd.size).toLong()

        val hashingInfo = ByteArrayOutputStream().apply {
            write(Blocks.u32(HASH_ALGORITHM_SHA256))
            write(LOG2_BLOCK_SIZE)
            write(bytes(ByteArray(0))) // no salt
            write(bytes(rootHash))
        }.toByteArray()

        // What actually gets signed: the file size, the hashing info and everything in the
        //      signing info except the signature itself
        val signedData = ByteArrayOutputStream().apply {
            write(Blocks.u64(size))
            write(Blocks.u32(HASH_ALGORITHM_SHA256))
            write(LOG2_BLOCK_SIZE)
            write(bytes(ByteArray(0))) // salt
            write(bytes(rootHash))
            write(bytes(apkDigest))
            write(bytes(key.certDer))
            write(bytes(ByteArray(0))) // additional data
        }.toByteArray()

        val signature = key.sign(signedData)

        val signingInfo = ByteArrayOutputStream().apply {
            write(bytes(apkDigest))
            write(bytes(key.certDer))
            write(bytes(ByteArray(0))) // additional data
            write(bytes(key.publicKeyDer))
            write(Blocks.u32(SigningKey.SIG_ALG_RSA_PKCS1_SHA256))
            write(bytes(signature))
        }.toByteArray()

        val idsig = File(apk.parentFile, "${apk.name}.idsig")
        idsig.writeBytes(ByteArrayOutputStream().apply {
            write(Blocks.u32(VERSION))
            write(bytes(hashingInfo))
            write(bytes(signingInfo))
        }.toByteArray())

        println("[+] Wrote v4 signature: ${idsig.name} (${idsig.length()} bytes)")
        return idsig
    }

    private fun bytes(data: ByteArray): ByteArray = Blocks.u32(data.size) + data
}
