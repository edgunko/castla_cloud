package com.castla.mirror.server

import android.content.Context
import android.util.Log
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.GeneralNames
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.io.File
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Security
import java.security.cert.X509Certificate
import java.util.Date
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLServerSocketFactory

/**
 * Produces an [SSLServerSocketFactory] backed by a self-signed certificate,
 * so MirrorServer can serve https:// / wss:// instead of plain http:// / ws://.
 *
 * Background: as of mid-2026, Chromium's Local Network Access restrictions
 * (and HTTPS-First Mode) started blocking or auto-upgrading requests from a
 * page to a *local* WebSocket/HTTP address — which is exactly what Tesla's
 * in-car browser does when it loads Castla's control page and connects back
 * to the phone. Serving TLS avoids the upgrade/block entirely.
 *
 * This is deliberately self-signed rather than a CA-issued certificate: the
 * phone has no stable public hostname to issue one against, and issuing one
 * per-session over ACME would need reliable internet + add real latency/
 * failure modes to every connect. A self-signed cert means the browser will
 * show a one-time "connection is not private" warning that the user has to
 * click through (Tesla's browser is a real Chromium browser, so — unlike a
 * true headless kiosk — this is expected to be tappable, but hasn't been
 * confirmed on-vehicle).
 *
 * The keystore is cached in the app's private storage and only regenerated
 * when the set of local IPv4 addresses it needs to cover changes (e.g. the
 * phone joined a different hotspot) or the cert is close to expiring.
 */
object SelfSignedTls {
    private const val TAG = "SelfSignedTls"
    private const val ALIAS = "castla-mirror"
    private const val KEYSTORE_FILE = "castla_tls_keystore.p12"

    // Self-signed, local-only cert: this password only protects the on-disk
    // PKCS12 container format, not the key's secrecy (an attacker with
    // filesystem access already has the private key file itself).
    private const val KEYSTORE_PASSWORD = "castla-local-tls"

    private const val VALIDITY_YEARS = 10L
    private val RENEW_IF_EXPIRING_WITHIN_MS = 7L * 24 * 60 * 60 * 1000 // 7 days

    init {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(BouncyCastleProvider())
        }
    }

    /**
     * Returns a server socket factory whose certificate's Subject Alternative
     * Names cover every address in [hosts] (plus "localhost"). Reuses the
     * cached certificate on disk when it already covers those hosts and
     * isn't close to expiring; otherwise mints a new one.
     */
    @Synchronized
    fun getServerSocketFactory(context: Context, hosts: List<String>): SSLServerSocketFactory {
        val keyStore = loadOrCreateKeyStore(context, hosts)
        val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
        kmf.init(keyStore, KEYSTORE_PASSWORD.toCharArray())
        val sslContext = SSLContext.getInstance("TLS")
        sslContext.init(kmf.keyManagers, null, null)
        return sslContext.serverSocketFactory
    }

    private fun loadOrCreateKeyStore(context: Context, hosts: List<String>): KeyStore {
        val file = File(context.filesDir, KEYSTORE_FILE)
        if (file.exists()) {
            try {
                val ks = KeyStore.getInstance("PKCS12")
                file.inputStream().use { ks.load(it, KEYSTORE_PASSWORD.toCharArray()) }
                val cert = ks.getCertificate(ALIAS) as? X509Certificate
                if (cert != null && coversAllHosts(cert, hosts) && !isExpiringSoon(cert)) {
                    Log.i(TAG, "Reusing cached self-signed certificate (covers $hosts)")
                    return ks
                }
                Log.i(TAG, "Cached certificate doesn't cover $hosts (or is expiring soon) — regenerating")
            } catch (e: Exception) {
                Log.w(TAG, "Failed to load cached TLS keystore — regenerating", e)
            }
        }
        return generateAndSave(context, hosts)
    }

    private fun coversAllHosts(cert: X509Certificate, hosts: List<String>): Boolean {
        val sanValues = try {
            cert.subjectAlternativeNames?.mapNotNull { it.getOrNull(1)?.toString() }?.toSet()
        } catch (e: Exception) {
            null
        } ?: return false
        return hosts.all { it in sanValues }
    }

    private fun isExpiringSoon(cert: X509Certificate): Boolean {
        val threshold = Date(System.currentTimeMillis() + RENEW_IF_EXPIRING_WITHIN_MS)
        return cert.notAfter.before(threshold)
    }

    private fun isIpAddress(host: String): Boolean =
        host.matches(Regex("^\\d{1,3}(\\.\\d{1,3}){3}$"))

    private fun generateAndSave(context: Context, hosts: List<String>): KeyStore {
        Log.i(TAG, "Generating new self-signed TLS certificate for $hosts")

        val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
        keyPairGenerator.initialize(2048)
        val keyPair = keyPairGenerator.generateKeyPair()

        val now = Date()
        val notAfter = Date(now.time + VALIDITY_YEARS * 365 * 24 * 60 * 60 * 1000)
        val serial = BigInteger.valueOf(System.currentTimeMillis())
        val subject = X500Name("CN=Castla Local Mirror")

        val allHosts = (hosts + "localhost").distinct()
        val generalNames = GeneralNames(
            allHosts.map { host ->
                GeneralName(
                    if (isIpAddress(host)) GeneralName.iPAddress else GeneralName.dNSName,
                    host
                )
            }.toTypedArray()
        )

        val certBuilder = JcaX509v3CertificateBuilder(
            subject, serial, now, notAfter, subject, keyPair.public
        )
            .addExtension(Extension.subjectAlternativeName, false, generalNames)
            .addExtension(Extension.basicConstraints, true, BasicConstraints(false))
            .addExtension(
                Extension.keyUsage, true,
                KeyUsage(KeyUsage.digitalSignature or KeyUsage.keyEncipherment)
            )

        val signer = JcaContentSignerBuilder("SHA256WithRSA")
            .setProvider(BouncyCastleProvider.PROVIDER_NAME)
            .build(keyPair.private)
        val certHolder = certBuilder.build(signer)
        val cert = JcaX509CertificateConverter()
            .setProvider(BouncyCastleProvider.PROVIDER_NAME)
            .getCertificate(certHolder)

        val keyStore = KeyStore.getInstance("PKCS12")
        keyStore.load(null, null)
        keyStore.setKeyEntry(ALIAS, keyPair.private, KEYSTORE_PASSWORD.toCharArray(), arrayOf<java.security.cert.Certificate>(cert))

        val file = File(context.filesDir, KEYSTORE_FILE)
        file.outputStream().use { keyStore.store(it, KEYSTORE_PASSWORD.toCharArray()) }
        Log.i(TAG, "Saved new TLS keystore to ${file.absolutePath}")

        return keyStore
    }
}
