package io.mosip.vercred.vcverifier.keyResolver.types.x509

import io.mosip.vercred.vcverifier.exception.PublicKeyNotFoundException
import okhttp3.OkHttpClient
import okhttp3.Request
import java.io.ByteArrayInputStream
import java.net.URI
import java.security.PublicKey
import java.security.cert.CertificateFactory
import java.util.logging.Logger

class X5uPublicKeyResolver {

    private val logger = Logger.getLogger(X5uPublicKeyResolver::class.java.name)

    // Until trust anchor checks exist, x5u must live on the same host as iss, so a token cannot point at an arbitrary certificate.
    private fun requireSameHostAsIssuer(x5u: String, issuer: URI) {
        val x5uHost = try {
            URI(x5u).host
        } catch (e: Exception) {
            null
        }
        if (x5uHost.isNullOrBlank() || issuer.host.isNullOrBlank() || !x5uHost.equals(issuer.host, ignoreCase = true)) {
            throw PublicKeyNotFoundException("x5u host must match the issuer (iss) host")
        }
    }

    fun resolve(uri: String, issuer: URI): PublicKey {
        requireSameHostAsIssuer(uri, issuer)
        return try {
            val client = OkHttpClient.Builder().build()
            val request = Request.Builder().url(uri).get().build()

            client.newCall(request).execute().use { response ->
                if (!response.isSuccessful) {
                    throw PublicKeyNotFoundException("x5u fetch failed with HTTP ${response.code} for $uri")
                }
                val certBytes = response.body?.bytes()
                    ?: throw PublicKeyNotFoundException("x5u response body was empty for $uri")

                val certFactory = CertificateFactory.getInstance("X.509")
                certFactory.generateCertificate(ByteArrayInputStream(certBytes)).publicKey
            }
        } catch (exception: Exception) {
            logger.severe("Error while resolving public key from x5u certificate: ${exception.message}")
            throw PublicKeyNotFoundException(
                "Unable to extract public key from x5u certificate: ${exception.message}"
            )
        }
    }
}