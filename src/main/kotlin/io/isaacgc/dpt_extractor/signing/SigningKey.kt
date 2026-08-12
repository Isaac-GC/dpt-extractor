package io.isaacgc.dpt_extractor.signing

import java.io.File
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.Signature
import java.security.cert.X509Certificate
import java.text.SimpleDateFormat
import java.util.Date
import java.util.TimeZone

class SigningKey(val privateKey: PrivateKey, val certDer: ByteArray, val publicKeyDer: ByteArray) {

    companion object {
        // sha256WithRSAEncryption / rsaEncryption
        const val OID_SHA256_RSA = "1.2.840.113549.1.1.11"
        const val OID_SHA256 = "2.16.840.1.101.3.4.2.1"
        const val SIG_ALG_RSA_PKCS1_SHA256 = 0x0103

        private const val OID_COMMON_NAME = "2.5.4.3"

        // Pulls a key + cert out of a normal java keystore (jks/pkcs12)
        fun fromKeyStore(keystore: File, storePass: String, alias: String?, keyPass: String): SigningKey {
            val ks = KeyStore.getInstance(if (keystore.extension.lowercase() == "p12") "PKCS12" else "JKS")
            keystore.inputStream().use { ks.load(it, storePass.toCharArray()) }

            val useAlias = alias ?: ks.aliases().asSequence().firstOrNull()
            ?: error("Keystore ${keystore.name} has no aliases")

            val key = ks.getKey(useAlias, keyPass.toCharArray()) as? PrivateKey
                ?: error("Alias '$useAlias' has no private key")
            val cert = ks.getCertificate(useAlias) as? X509Certificate
                ?: error("Alias '$useAlias' has no x509 certificate")

            println("[+] Signing with keystore ${keystore.name} (alias: $useAlias)")
            return SigningKey(key, cert.encoded, cert.publicKey.encoded)
        }

        fun generateSelfSigned(commonName: String = "dpt-extractor"): SigningKey {
            val kpg = KeyPairGenerator.getInstance("RSA")
            kpg.initialize(2048, SecureRandom())
            val kp: KeyPair = kpg.generateKeyPair()

            val cert = buildSelfSignedCert(kp, commonName)
            println("[+] Generated a throwaway self-signed key (CN=$commonName)")

            return SigningKey(kp.private, cert, kp.public.encoded)
        }

        private fun buildSelfSignedCert(kp: KeyPair, commonName: String): ByteArray {
            val fmt = SimpleDateFormat("yyMMddHHmmss'Z'").also { it.timeZone = TimeZone.getTimeZone("UTC") }
            val now = System.currentTimeMillis()
            val notBefore = fmt.format(Date(now - 86_400_000L))            // yesterday, avoids clock skew
            val notAfter = fmt.format(Date(now + 10_000L * 86_400_000L))   // ~27 years

            val name = Der.seq(Der.set(Der.seq(Der.oid(OID_COMMON_NAME), Der.printableString(commonName))))
            val serial = Der.int(BigInteger(64, SecureRandom()).toByteArray())
            val sigAlg = Der.algId(OID_SHA256_RSA)

            // The public key is already a DER SubjectPublicKeyInfo, so drop it straight in
            val tbs = Der.seq(
                Der.explicit(0, Der.int(2)),                               // version v3
                serial,
                sigAlg,
                name,                                                       // issuer == subject (self signed)
                Der.seq(Der.utcTime(notBefore), Der.utcTime(notAfter)),
                name,
                kp.public.encoded
            )

            val sig = Signature.getInstance("SHA256withRSA").run {
                initSign(kp.private)
                update(tbs)
                sign()
            }

            return Der.seq(tbs, sigAlg, Der.bitString(sig))
        }
    }

    fun issuerAndSerial(): ByteArray {
        val cert = java.security.cert.CertificateFactory.getInstance("X.509")
            .generateCertificate(certDer.inputStream()) as X509Certificate

        val issuer = cert.issuerX500Principal.encoded            // already DER
        val serial = Der.int(cert.serialNumber.toByteArray())
        return Der.seq(issuer, serial)
    }

    fun sign(data: ByteArray): ByteArray {
        return Signature.getInstance("SHA256withRSA").run {
            initSign(privateKey)
            update(data)
            sign()
        }
    }
}
