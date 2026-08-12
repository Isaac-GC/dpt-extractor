package io.isaacgc.dpt_extractor.signing


// Reference: https://source.android.com/docs/security/features/apksigning/v3
object V3Signer {

    const val BLOCK_ID = 0xf05368c0.toInt()
    const val BLOCK_ID_V31 = 0x1b93ad61
    const val MIN_SDK = 28
    const val MIN_SDK_V31 = 33

    const val MAX_SDK = Int.MAX_VALUE

    // Tells a v13+ verifier that rotation kicks in at some sdk, ie. go look for the v3.1 block
    private const val ATTR_ROTATION_MIN_SDK = 0x559f8b02

    fun blockValue(digest: ByteArray, key: SigningKey, minSdk: Int, maxSdk: Int,
                   rotationMinSdk: Int? = null): ByteArray {
        val digests = Blocks.lenPrefixedSeq(listOf(
            Blocks.algPair(SigningKey.SIG_ALG_RSA_PKCS1_SHA256, digest)
        ))
        val certs = Blocks.lenPrefixedSeq(listOf(key.certDer))

        val attrs = if (rotationMinSdk != null) {
            Blocks.lenPrefixedSeq(listOf(Blocks.u32(ATTR_ROTATION_MIN_SDK) + Blocks.u32(rotationMinSdk)))
        } else {
            Blocks.u32(0)
        }

        // signed data = digests + certificates + minSdk + maxSdk + additional attributes
        val signedData = digests + certs + Blocks.u32(minSdk) + Blocks.u32(maxSdk) + attrs

        val signatures = Blocks.lenPrefixedSeq(listOf(
            Blocks.algPair(SigningKey.SIG_ALG_RSA_PKCS1_SHA256, key.sign(signedData))
        ))

        val signer = Blocks.lenPrefixed(signedData) +
                Blocks.u32(minSdk) + Blocks.u32(maxSdk) +
                signatures + Blocks.lenPrefixed(key.publicKeyDer)

        return Blocks.lenPrefixedSeq(listOf(signer))
    }
}
