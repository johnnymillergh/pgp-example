package com.jmsoftware.pgpexample.util

import com.google.common.collect.Lists
import com.jmsoftware.pgpexample.util.PgpUtil.Companion.decryptCipher
import com.jmsoftware.pgpexample.util.PgpUtil.Companion.encryptPlaintext
import com.jmsoftware.pgpexample.util.PgpUtil.Companion.readPublicKey
import com.jmsoftware.pgpexample.util.PgpUtil.Companion.readSecretKey
import com.jmsoftware.pgpexample.util.PgpUtil.Companion.signMessage
import com.jmsoftware.pgpexample.util.PgpUtil.Companion.verifySignature
import org.apache.commons.io.IOUtils
import org.apache.commons.lang3.SystemUtils
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPSecretKey
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertDoesNotThrow
import org.junit.jupiter.api.parallel.Execution
import org.junit.jupiter.api.parallel.ExecutionMode
import java.io.ByteArrayInputStream
import java.io.File
import java.io.File.separator
import java.io.FileOutputStream
import java.util.*
import kotlin.concurrent.timerTask

/**
 * # PgpUtilTest
 *
 * @author Johnny Miller, email: johnnysviva@outlook.com, date: 3/26/2023 4:01 PM
 **/
@Execution(ExecutionMode.CONCURRENT)
class PgpUtilTest {
    companion object {
        private val log = logger()
        private val CLASS_LOADER = PgpUtilTest::class.java.classLoader
        private const val PGP_MESSAGE_HEADER = "-----BEGIN PGP MESSAGE-----"
        private val PGP_MESSAGE_FOOTER = "-----END PGP MESSAGE-----${System.lineSeparator()}"

        private fun output(outputFileName: String, outputBytes: ByteArray) {
            log.info("Current OS is: {}", SystemUtils.OS_NAME)
            val tmpPath = SystemUtils.getJavaIoTmpDir().absolutePath
            assertNotNull(tmpPath)
            log.info("tmpPath: {}", tmpPath)
            val outputFile = File("$tmpPath$separator$outputFileName")
            assertNotNull(outputFile)
            FileOutputStream(outputFile).use {
                assertDoesNotThrow { IOUtils.write(outputBytes, it) }
            }
            log.info("Done writing sign-encrypted data file [{}]", outputFile.absolutePath)
        }
    }

    @BeforeEach
    fun setUp() {
        log.info("Finished setting up for ${this.javaClass.simpleName}")
        log.info("PGP_MESSAGE_HEADER: $PGP_MESSAGE_HEADER")
        log.info("PGP_MESSAGE_FOOTER: $PGP_MESSAGE_FOOTER")
    }

    @AfterEach
    fun tearDown() {
        log.info("Finished deconstructing for ${this.javaClass.simpleName}")
    }


    @Test
    fun encrypt_decryptSignature_whenSecretAndPublicKeysAreAPair_notArmor() {
        val plaintext = "Hello world!"
        assertNotNull(plaintext)
        assertFalse(plaintext.isBlank())
        log.info("The input plaintext is: $plaintext")
        val alicePgpSecretKey: PGPSecretKey
        CLASS_LOADER.getResourceAsStream("pgp-keys/Johnny Miller's PGP Example - Alice_0x3A9AA381_SECRET.asc")!!
            .use {
                alicePgpSecretKey = assertDoesNotThrow { readSecretKey(it) }
            }
        log.info(
            """
            Done reading Alice PGP secret key: $alicePgpSecretKey
            Is Signing Key: ${alicePgpSecretKey.isSigningKey}
            Key Owner: ${Lists.newArrayList(alicePgpSecretKey.userIDs)}
            Key Encryption Algorithm: ${alicePgpSecretKey.keyEncryptionAlgorithm}
            """.trimIndent()
        )

        // 1. Encrypting signature
        val alicePgpPublicKey: PGPPublicKey
        CLASS_LOADER.getResourceAsStream("pgp-keys/Johnny Miller's PGP Example - Alice_0x3A9AA381_public.asc")!!
            .use {
                alicePgpPublicKey = assertDoesNotThrow { readPublicKey(it) }
            }
        val ciphertextBytes = assertDoesNotThrow {
            encryptPlaintext(plaintext.toByteArray(), alicePgpPublicKey, armor = false, withIntegrityCheck = true)
        }
        assertNotNull(ciphertextBytes)
        val ciphertext = String(ciphertextBytes)
        assertNotNull(ciphertext)
        assertFalse(ciphertext.isBlank())
        assertFalse(ciphertext.startsWith(PGP_MESSAGE_HEADER))
        assertFalse(ciphertext.endsWith(PGP_MESSAGE_FOOTER))
        log.info("Ciphertext:\n$ciphertext")
        output(
            "${this.javaClass.simpleName}-${Thread.currentThread().stackTrace[1].methodName}.txt",
            ciphertextBytes
        )

        // 2. Decrypting
        val decryptedMessageBytes: ByteArray
        CLASS_LOADER.getResourceAsStream("pgp-keys/Johnny Miller's PGP Example - Alice_0x3A9AA381_SECRET.asc")!!
            .use { it1 ->
                ByteArrayInputStream(ciphertextBytes).use { it2 ->
                    decryptedMessageBytes = assertDoesNotThrow { decryptCipher(it2, it1, "".toCharArray()) }
                }
            }
        assertNotNull(decryptedMessageBytes)
        val decryptedMessage = String(decryptedMessageBytes)
        log.info("Decrypted message: $decryptedMessage")
        assertNotNull(decryptedMessage)
        assertFalse(decryptedMessage.startsWith(PGP_MESSAGE_HEADER))
        assertFalse(decryptedMessage.endsWith(PGP_MESSAGE_FOOTER))
        assertEquals(plaintext, decryptedMessage)
    }

    @Test
    fun decrypt_when_then() {
        val ciphertext =
            """
            -----BEGIN PGP MESSAGE-----
            Version: BCPG v1.72.2

            hQGMA81hBm06mqOBAQwAtjJUTOIj1E/0sMRUxWLbfRZmUCyZd+EIIQ8hPC1GMgo3
            ZYIJAIMx9cRoXSKyeh/g7jVoa3ajf9YY1exQB07H8rB8lWSL/aBFr/dqJD2zblpv
            asRVCHoqwtu3J9ycj/mBRGqY2PJ44WMnOFrLuPHNCneq+rFczC/RZH8yPcGecqnP
            JNywuu8Qh9rKeyaxtrjOvjv9Uzffz0/qMAVUiG9ZZ+TtVa9yLwG59w/+D6tvmRoQ
            Fzqa4f0w20sOBa/+l5uoVE+LN+DGDpkK0DneEQRNU7ZLc5CSKLWBquB3wYCrbTD5
            sxIIW/zlTi1196puAjE23fsfUOoNdqsdxYszaxgVn0tgeneeNU5VO8eHj6ncKT5B
            MxBKQpsrbjuyNQfngRg1XnKnynJyeJoaLfgyNkNh7MlsuA5ftKXI8wnRnfhcSTBG
            VriYQjUUj/c6bj0751WiMk2BMmRsGXez8u6XU0KL5lCVmIh4VjE+Fs6UpDgZmRXr
            iiHhL4Ob6QXO11xt3cBF0sIKAX3JKf/DQPl+MbjNgfbMzK5Gky/1waz3jsyh0ZJI
            NOZKNJ0tYDSKdIvQO+O1NAHbJ67w+sVRIGa9ly75nALL6NmZwymMaKY2KiYXsc+1
            ANRmk2iWQR2sK99AL2S3wxPWZkZyhK/cyZLBPs5YQtxBlbCsHDoMjU2F1IT/M4fb
            0MhxitkHxeWEvfaVBPLvMNnJaruGpNFAqKGn3l4ZBdHTiNQt9n5NB0y1nZGsYtp/
            xj7YRQsyscTkMS6MVGm/Dc9P0Tbr+TbwMXVwn4dyfBBI8dx/MuxPpns4LeknyOU5
            7CDxvw1uzOJUQ/1MFUfenRkRvBArOmyi7GDqdhlLu1dmLEaElGmLFqngLPTdC2N8
            bHcadWx5zdoUEEjM3JRwqj9y/JGs31IuwGbT9YAxl8YALFP1emkyjMFjE52LM430
            owu94vcUIwGp49N4kX02xefTsGOLf+75fMGdVMXr6DepLQ4GoRP6hsT5fzCeqjOi
            Xg/WPNszEJiFxiHsZOQcHk4gCg5DrS3qGPxcuCXAGe1aaYYTH3j3fatkz1f3foy9
            zqQzbdD2FsNFz4FbWc3BlZsOos/pYjbAyEtFP9WWkwMWuURCKZsuUWllrpYkWPca
            BYhjQz0m0e7o/RzZToCdEgMmUmTXANTcvb456NnSKVyFzpbD8oNNfmLDyBukQbyU
            B6RMLZ36j40VupuKQEElsxJptAq63a4LS0f3RYoBITzm3nmXb2hBVV0sGlI31RcX
            OmbgYacWFmFaEmDnu9jYt8qnLKePhSe57xC2f8JgTbaDr3J57TlHSICXVpkjZi7+
            S1VuNCyZH0Gw8xY0dHmJoWfILZVGSEA3rTJS45Ukk5w338J2+sRk1MShh6hGz/qM
            fDu1cVn4vjIpk6CLtqjceEgNGNe1Z9i7gbKdkgZ4nFSz78Nh004GFoDYd8Qwi5Vh
            kirZzRQxC+uHmiFu
            =C8cs
            -----END PGP MESSAGE-----
            """.trimIndent()
        val aliceSecretKeyIn2 =
            CLASS_LOADER.getResourceAsStream("pgp-keys/Johnny Miller's PGP Example - Alice_0x3A9AA381_SECRET.asc")!!
        val decryptedMessageBytes = assertDoesNotThrow {
            decryptCipher(
                ByteArrayInputStream(ciphertext.toByteArray()),
                aliceSecretKeyIn2,
                "".toCharArray()
            )
        }
        assertNotNull(decryptedMessageBytes)
    }

    //    @Test
    fun performanceTest_infinitiveLoop() {
        var loopCount = 0L
        var loop = true
        val timer = Timer("Stop Timer")
        timer.schedule(
            timerTask {
                loop = false
                log.warn("Stopping the loop")
            },
            2 * 60 * 1000L
        )
        while (loop) {
            log.info("Looping #${loopCount + 1}")
            assertDoesNotThrow {
                signAndEncrypt_decryptAndVerify_whenSecretAndPublicKeysAreAPair_notArmor()
            }
            loopCount++
        }
        @Suppress("KotlinConstantConditions")
        log.info("Done looping for ${loopCount + 1} times")
    }

    @Test
    fun signAndEncrypt_decryptAndVerify_whenSecretAndPublicKeysAreAPair_notArmor() {
        val plaintext = "Hello world!"
        assertNotNull(plaintext)
        assertFalse(plaintext.isBlank())
        log.info("The input plaintext is: $plaintext")
        val alicePgpSecretKey: PGPSecretKey
        CLASS_LOADER.getResourceAsStream("pgp-keys/Johnny Miller's PGP Example - Alice_0x3A9AA381_SECRET.asc")!!
            .use {
                alicePgpSecretKey = assertDoesNotThrow { readSecretKey(it) }
            }
        log.info(
            """
            Done reading Alice PGP secret key: $alicePgpSecretKey
            Is Signing Key: ${alicePgpSecretKey.isSigningKey}
            Key Owner: ${Lists.newArrayList(alicePgpSecretKey.userIDs)}
            Key Encryption Algorithm: ${alicePgpSecretKey.keyEncryptionAlgorithm}
            """.trimIndent()
        )

        // 1. Signing
        val signatureBytes =
            assertDoesNotThrow { signMessage(plaintext.toByteArray(), alicePgpSecretKey, "".toCharArray(), false) }
        val signature = String(signatureBytes)
        assertNotNull(signatureBytes)
        log.info("Signature:\n$signature")
        assertNotNull(signature)
        assertFalse(signature.startsWith(PGP_MESSAGE_HEADER))
        assertFalse(signature.endsWith(PGP_MESSAGE_FOOTER))

        // 2. Encrypting signature
        val alicePgpPublicKey: PGPPublicKey
        CLASS_LOADER.getResourceAsStream("pgp-keys/Johnny Miller's PGP Example - Alice_0x3A9AA381_public.asc")!!
            .use {
                alicePgpPublicKey = assertDoesNotThrow { readPublicKey(it) }
            }
        val ciphertextBytes = assertDoesNotThrow {
            encryptPlaintext(signatureBytes, alicePgpPublicKey, armor = false, withIntegrityCheck = true)
        }
        assertNotNull(ciphertextBytes)
        val ciphertext = String(ciphertextBytes)
        assertNotNull(ciphertext)
        assertFalse(ciphertext.isBlank())
        assertFalse(ciphertext.startsWith(PGP_MESSAGE_HEADER))
        assertFalse(ciphertext.endsWith(PGP_MESSAGE_FOOTER))
        log.info("Ciphertext:\n$ciphertext")
        output(
            "${this.javaClass.simpleName}-${Thread.currentThread().stackTrace[1].methodName}.txt",
            ciphertextBytes
        )

        // 3. Decrypting
        val decryptedMessageBytes: ByteArray
        val aliceSecretKeyIn2 =
            CLASS_LOADER.getResourceAsStream("pgp-keys/Johnny Miller's PGP Example - Alice_0x3A9AA381_SECRET.asc")!!
        decryptedMessageBytes = assertDoesNotThrow {
            decryptCipher(
                ByteArrayInputStream(ciphertextBytes),
                aliceSecretKeyIn2,
                "".toCharArray()
            )
        }
        assertNotNull(decryptedMessageBytes)
        val decryptedMessage = String(decryptedMessageBytes)
        assertNotNull(decryptedMessage)
        assertFalse(decryptedMessage.startsWith(PGP_MESSAGE_HEADER))
        assertFalse(decryptedMessage.endsWith(PGP_MESSAGE_FOOTER))

        // 4. Verifying signature
        val verifiedSignatureBytes = assertDoesNotThrow {
            verifySignature(ByteArrayInputStream(decryptedMessageBytes), alicePgpPublicKey)
        }
        assertNotNull(verifiedSignatureBytes)
        val verifiedSignature = String(verifiedSignatureBytes)
        log.info("Verified signature: $verifiedSignature")
        assertNotNull(verifiedSignature)
        assertFalse(verifiedSignature.isBlank())
        assertEquals(plaintext, verifiedSignature)
    }

    @Test
    fun signAndEncrypt_decryptAndVerify_whenSecretAndPublicKeysAreAPair_Armor() {
        val plaintext = "Hello world!"
        assertNotNull(plaintext)
        assertFalse(plaintext.isBlank())
        log.info("The input plaintext is: $plaintext")
        val alicePgpSecretKey: PGPSecretKey
        CLASS_LOADER.getResourceAsStream("pgp-keys/Johnny Miller's PGP Example - Alice_0x3A9AA381_SECRET.asc")!!
            .use {
                alicePgpSecretKey = assertDoesNotThrow { readSecretKey(it) }
            }
        log.info(
            """
            Done reading Alice PGP secret key: $alicePgpSecretKey
            Is Signing Key: ${alicePgpSecretKey.isSigningKey}
            Key Owner: ${Lists.newArrayList(alicePgpSecretKey.userIDs)}
            Key Encryption Algorithm: ${alicePgpSecretKey.keyEncryptionAlgorithm}
            """.trimIndent()
        )

        // 1. Signing
        val signatureBytes =
            assertDoesNotThrow { signMessage(plaintext.toByteArray(), alicePgpSecretKey, "".toCharArray(), true) }
        val signature = String(signatureBytes)
        assertNotNull(signatureBytes)
        log.info("Signature:\n$signature")
        assertNotNull(signature)
        assertTrue(signature.startsWith(PGP_MESSAGE_HEADER))
        assertTrue(signature.endsWith(PGP_MESSAGE_FOOTER))

        // 2. Encrypting signature
        val alicePgpPublicKey: PGPPublicKey
        CLASS_LOADER.getResourceAsStream("pgp-keys/Johnny Miller's PGP Example - Alice_0x3A9AA381_public.asc")!!
            .use {
                alicePgpPublicKey = assertDoesNotThrow { readPublicKey(it) }
            }
        val ciphertextBytes = assertDoesNotThrow {
            encryptPlaintext(signatureBytes, alicePgpPublicKey, armor = true, withIntegrityCheck = true)
        }
        assertNotNull(ciphertextBytes)
        val ciphertext = String(ciphertextBytes)
        assertNotNull(ciphertext)
        assertFalse(ciphertext.isBlank())
        assertTrue(ciphertext.startsWith(PGP_MESSAGE_HEADER))
        assertTrue(ciphertext.endsWith(PGP_MESSAGE_FOOTER))
        log.info("Ciphertext:\n$ciphertext")
        output(
            "${this.javaClass.simpleName}-${Thread.currentThread().stackTrace[1].methodName}.txt",
            ciphertextBytes
        )

        // 3. Decrypting
        val decryptedMessageBytes: ByteArray
        val aliceSecretKeyIn2 =
            CLASS_LOADER.getResourceAsStream("pgp-keys/Johnny Miller's PGP Example - Alice_0x3A9AA381_SECRET.asc")!!
        decryptedMessageBytes = assertDoesNotThrow {
            decryptCipher(
                ByteArrayInputStream(ciphertextBytes),
                aliceSecretKeyIn2,
                "".toCharArray()
            )
        }
        assertNotNull(decryptedMessageBytes)
        val decryptedMessage = String(decryptedMessageBytes)
        assertNotNull(decryptedMessage)
        assertTrue(decryptedMessage.startsWith(PGP_MESSAGE_HEADER))
        assertTrue(decryptedMessage.endsWith(PGP_MESSAGE_FOOTER))

        // 4. Verifying signature
        val verifiedSignatureBytes = assertDoesNotThrow {
            verifySignature(ByteArrayInputStream(decryptedMessageBytes), alicePgpPublicKey)
        }
        assertNotNull(verifiedSignatureBytes)
        val verifiedSignature = String(verifiedSignatureBytes)
        log.info("Verified signature: $verifiedSignature")
        assertNotNull(verifiedSignature)
        assertFalse(verifiedSignature.isBlank())
        assertEquals(plaintext, verifiedSignature)
    }
}
