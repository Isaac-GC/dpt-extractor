package io.isaacgc.dpt_extractor.signing

import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.util.Base64

object V1Signer {

    // pkcs7 / signed data oids
    private const val OID_PKCS7_DATA = "1.2.840.113549.1.7.1"
    private const val OID_PKCS7_SIGNED_DATA = "1.2.840.113549.1.7.2"
    private const val OID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1"

    private const val CRLF = "\r\n"

    class Result(val manifest: ByteArray, val signatureFile: ByteArray, val pkcs7: ByteArray)

    /**
     * Builds the three META-INF files for the given entries.
     *
     * `entries` is every file in the apk that isn't already under META-INF/ (those get skipped,
     * same as jarsigner does)
     */
    fun sign(entries: List<Pair<String, ByteArray>>, key: SigningKey): Result {
        val sha256 = MessageDigest.getInstance("SHA-256")
        val b64 = Base64.getEncoder()

        // 1. MANIFEST.MF -- a digest of every entry
        val manifestOut = ByteArrayOutputStream()
        manifestOut.write(("Manifest-Version: 1.0${CRLF}Created-By: dpt-extractor${CRLF}${CRLF}").toByteArray())

        // Keep each entry's own section around, CERT.SF digests them individually
        val perEntrySection = LinkedHashMap<String, ByteArray>()
        for ((name, data) in entries) {
            val digest = b64.encodeToString(sha256.digest(data))
            val section = (wrap("Name: $name") + CRLF + wrap("SHA-256-Digest: $digest") + CRLF + CRLF).toByteArray()
            perEntrySection[name] = section
            manifestOut.write(section)
        }
        val manifest = manifestOut.toByteArray()

        // 2. CERT.SF -- digests of the manifest as a whole and of each section in it
        val sfOut = ByteArrayOutputStream()
        sfOut.write(("Signature-Version: 1.0${CRLF}Created-By: dpt-extractor${CRLF}" +
                wrap("SHA-256-Digest-Manifest: " + b64.encodeToString(sha256.digest(manifest))) +
                CRLF + CRLF).toByteArray())

        for ((name, section) in perEntrySection) {
            val digest = b64.encodeToString(sha256.digest(section))
            sfOut.write((wrap("Name: $name") + CRLF + wrap("SHA-256-Digest: $digest") + CRLF + CRLF).toByteArray())
        }
        val signatureFile = sfOut.toByteArray()

        // 3. CERT.RSA -- pkcs7 detached signature over CERT.SF
        return Result(manifest, signatureFile, buildPkcs7(signatureFile, key))
    }

    /**
     * pkcs7 SignedData wrapping the signature of the .SF file.
     *
     * We skip authenticatedAttributes, so encryptedDigest is just the signature over the
     * content itself -- that's the simple (and still valid) shape
     */
    private fun buildPkcs7(content: ByteArray, key: SigningKey): ByteArray {
        val digestAlg = Der.algId(SigningKey.OID_SHA256)
        val signature = key.sign(content)

        val signerInfo = Der.seq(
            Der.int(1),                                     // version
            key.issuerAndSerial(),
            digestAlg,
            Der.algId(OID_RSA_ENCRYPTION),
            Der.octetString(signature)                      // encryptedDigest
        )

        val signedData = Der.seq(
            Der.int(1),                                     // version
            Der.set(digestAlg),                             // digestAlgorithms
            Der.seq(Der.oid(OID_PKCS7_DATA)),               // contentInfo, detached so no content
            Der.explicit(0, key.certDer),                   // [0] certificates
            Der.set(signerInfo)
        )

        return Der.seq(Der.oid(OID_PKCS7_SIGNED_DATA), Der.explicit(0, signedData))
    }

    /**
     * Manifest lines cap out at 72 bytes, anything longer continues on the next line with a
     * single leading space
     */
    private fun wrap(line: String): String {
        if (line.toByteArray().size <= 72) return line

        val bytes = line.toByteArray()
        val sb = StringBuilder()
        var pos = 0
        var limit = 72

        while (pos < bytes.size) {
            val take = minOf(limit, bytes.size - pos)
            if (pos > 0) sb.append(CRLF).append(' ')
            sb.append(String(bytes, pos, take))
            pos += take
            limit = 71 // continuation lines lose one byte to the leading space
        }

        return sb.toString()
    }
}
