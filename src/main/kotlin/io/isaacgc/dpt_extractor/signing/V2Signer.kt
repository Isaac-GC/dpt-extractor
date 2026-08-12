package io.isaacgc.dpt_extractor.signing

 // Reference: https://source.android.com/docs/security/features/apksigning/v2
object V2Signer {

    const val BLOCK_ID = 0x7109871a

    fun blockValue(digest: ByteArray, key: SigningKey): ByteArray {
        val digests = Blocks.lenPrefixedSeq(listOf(
            Blocks.algPair(SigningKey.SIG_ALG_RSA_PKCS1_SHA256, digest)
        ))
        val certs = Blocks.lenPrefixedSeq(listOf(key.certDer))

        // signed data = digests + certificates + additional attributes (we have none)
        val signedData = digests + certs + Blocks.u32(0)

        val signatures = Blocks.lenPrefixedSeq(listOf(
            Blocks.algPair(SigningKey.SIG_ALG_RSA_PKCS1_SHA256, key.sign(signedData))
        ))

        val signer = Blocks.lenPrefixed(signedData) + signatures + Blocks.lenPrefixed(key.publicKeyDer)
        return Blocks.lenPrefixedSeq(listOf(signer))
    }
}
