package vpn.zerotrust.app

import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * The Shadowsocks AEAD packet format (aes-256-gcm), as the desktop client and
 * the node relay speak it.
 *
 * This is a second implementation of a format the Go package
 * `client/internal/obfs` already implements, which is a cost worth naming:
 * two implementations can disagree, and a disagreement here is a tunnel that
 * silently will not come up. It exists because the Android app cannot run the
 * Go binary — wireguard-android brings the tunnel up in this process, and the
 * relay has to live in the same process to sit in front of it.
 *
 * The mitigation for having two is that they are tested AGAINST EACH OTHER,
 * not each against itself: `tests/emulation/test_obfs.py` compiles this file
 * on the JVM and pushes real packets through the real `0trust-obfs` binary.
 * Nothing here is checked by reading it.
 *
 * Deliberately no Android imports anywhere in this file or [ObfsRelay]. That
 * is what makes the above possible: on a machine with no Android SDK these
 * two classes still compile and run, so the part of the feature that carries
 * customer packets is executed by CI rather than merely parsed.
 *
 * What this is and is not: see the package comment on the Go side. Briefly —
 * it removes WireGuard's protocol fingerprint, it is not authentication (the
 * key is shared by every customer on a node), it is not traffic-analysis
 * resistance, and it does not survive a block on UDP itself.
 */
object ObfsCrypto {

    const val KEY_LEN = 32
    const val SALT_LEN = 32
    private const val TAG_LEN = 16
    private const val ADDR_LEN_V4 = 7      // ATYP + 4 + port
    private const val ADDR_LEN_V6 = 19     // ATYP + 16 + port

    private const val ATYP_IPV4 = 1
    private const val ATYP_DOMAIN = 3
    private const val ATYP_IPV6 = 4

    /**
     * Bytes this transport adds to every datagram. Must equal `obfs.Overhead`
     * in the Go package; a test asserts the two agree by measuring a real
     * packet rather than comparing constants.
     */
    const val OVERHEAD = SALT_LEN + ADDR_LEN_V4 + TAG_LEN   // 55

    private val rng = SecureRandom()

    /**
     * Decode and size-check a base64 pre-shared key.
     *
     * `java.util.Base64` rather than `android.util.Base64`, which is not a
     * style preference: an android.* reference here would stop this file
     * compiling on a machine without the SDK, and compiling there is the
     * whole reason this class is separate — it is how the interop test runs
     * the real code against the real Go relay. minSdk is 26, where
     * java.util.Base64 is present on every supported device.
     */
    fun parseKey(b64: String): ByteArray {
        val raw = java.util.Base64.getDecoder().decode(b64.trim())
        require(raw.size == KEY_LEN) { "obfs: key is ${raw.size} bytes, want $KEY_LEN" }
        return raw
    }

    /**
     * RFC 5869 extract-and-expand over SHA-1, which is what the Shadowsocks
     * AEAD spec calls for. SHA-1's collision weakness does not reach
     * HMAC-SHA1 used as a KDF, and the choice is the packet format's, not
     * ours.
     */
    private fun hkdfSha1(secret: ByteArray, salt: ByteArray, info: ByteArray, n: Int): ByteArray {
        val ext = Mac.getInstance("HmacSHA1")
        ext.init(SecretKeySpec(salt, "HmacSHA1"))
        val prk = ext.doFinal(secret)

        val out = ByteArray(n)
        var filled = 0
        var prev = ByteArray(0)
        var counter = 1
        while (filled < n) {
            val h = Mac.getInstance("HmacSHA1")
            h.init(SecretKeySpec(prk, "HmacSHA1"))
            h.update(prev)
            h.update(info)
            h.update(counter.toByte())
            prev = h.doFinal()
            val take = minOf(prev.size, n - filled)
            System.arraycopy(prev, 0, out, filled, take)
            filled += take
            counter++
        }
        return out
    }

    private fun cipherFor(psk: ByteArray, salt: ByteArray, mode: Int): Cipher {
        val sub = hkdfSha1(psk, salt, "ss-subkey".toByteArray(Charsets.US_ASCII), KEY_LEN)
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        // Twelve zero bytes, which is correct here and would be a catastrophe
        // anywhere else: the subkey is derived from a fresh random salt on
        // every packet, so no (key, nonce) pair is ever reused. That is the
        // spec's design and the reason the salt is not optional.
        c.init(mode, SecretKeySpec(sub, "AES"), GCMParameterSpec(TAG_LEN * 8, ByteArray(12)))
        return c
    }

    private fun appendAddr(dst: InetSocketAddress): ByteArray {
        val a = dst.address
        val body: ByteArray = when (a) {
            is Inet4Address -> byteArrayOf(ATYP_IPV4.toByte()) + a.address
            is Inet6Address -> byteArrayOf(ATYP_IPV6.toByte()) + a.address
            else -> throw IllegalArgumentException("obfs: unsupported address $a")
        }
        val p = dst.port
        return body + byteArrayOf((p ushr 8).toByte(), (p and 0xff).toByte())
    }

    /** Destination and payload read out of an opened packet. */
    data class Opened(val dst: InetSocketAddress, val payload: ByteArray)

    private fun parseAddr(b: ByteArray): Opened {
        require(b.isNotEmpty()) { "obfs: packet too short" }
        return when (b[0].toInt() and 0xff) {
            ATYP_IPV4 -> {
                require(b.size >= ADDR_LEN_V4) { "obfs: packet too short" }
                val ip = InetAddress.getByAddress(b.copyOfRange(1, 5))
                val port = ((b[5].toInt() and 0xff) shl 8) or (b[6].toInt() and 0xff)
                Opened(InetSocketAddress(ip, port), b.copyOfRange(ADDR_LEN_V4, b.size))
            }
            ATYP_IPV6 -> {
                require(b.size >= ADDR_LEN_V6) { "obfs: packet too short" }
                val ip = InetAddress.getByAddress(b.copyOfRange(1, 17))
                val port = ((b[17].toInt() and 0xff) shl 8) or (b[18].toInt() and 0xff)
                Opened(InetSocketAddress(ip, port), b.copyOfRange(ADDR_LEN_V6, b.size))
            }
            // Refused outright, exactly as on the Go side. The only
            // destination this transport ever carries is a node's own
            // loopback WireGuard port, so a hostname has no legitimate use —
            // and accepting one would mean resolving on behalf of whoever
            // sent the packet.
            ATYP_DOMAIN -> throw IllegalArgumentException(
                "obfs: hostname destinations are not carried")
            else -> throw IllegalArgumentException("obfs: unknown address type ${b[0]}")
        }
    }

    /** Seal one datagram addressed to [dst]. */
    fun pack(psk: ByteArray, dst: InetSocketAddress, data: ByteArray): ByteArray {
        val salt = ByteArray(SALT_LEN).also { rng.nextBytes(it) }
        val plain = appendAddr(dst) + data
        val sealed = cipherFor(psk, salt, Cipher.ENCRYPT_MODE).doFinal(plain)
        return salt + sealed
    }

    /**
     * Open one datagram. Throws on anything that does not authenticate;
     * callers must drop it without replying, so an unauthenticated prober
     * learns nothing from the difference between a wrong key and a closed
     * port.
     */
    fun unpack(psk: ByteArray, pkt: ByteArray, len: Int = pkt.size): Opened {
        require(len >= SALT_LEN + TAG_LEN) { "obfs: packet too short" }
        val salt = pkt.copyOfRange(0, SALT_LEN)
        val body = pkt.copyOfRange(SALT_LEN, len)
        val plain = cipherFor(psk, salt, Cipher.DECRYPT_MODE).doFinal(body)
        return parseAddr(plain)
    }
}
