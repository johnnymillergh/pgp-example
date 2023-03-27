package com.jmsoftware.pgpexample.util

import com.google.common.collect.Lists
import com.jmsoftware.pgpexample.util.PgpUtil.Companion.decryptCipher
import com.jmsoftware.pgpexample.util.PgpUtil.Companion.decryptVerify
import com.jmsoftware.pgpexample.util.PgpUtil.Companion.encryptPlaintext
import com.jmsoftware.pgpexample.util.PgpUtil.Companion.readPublicKey
import com.jmsoftware.pgpexample.util.PgpUtil.Companion.readSecretKey
import com.jmsoftware.pgpexample.util.PgpUtil.Companion.signEncryptInOnePass
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
import java.io.*
import java.io.File.separator
import java.nio.charset.StandardCharsets.UTF_8
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

    // @Test
    @Suppress("unused")
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
                aliceSendMessageToBob_signEncrypt_decryptVerify_whenSecretAndPublicKeysAreNotAPair_armor()
            }
            loopCount++
        }
        @Suppress("KotlinConstantConditions")
        log.info("Done looping for ${loopCount + 1} times")
    }

    @Test
    fun encrypt_decrypt_whenSecretAndPublicKeysAreAPair_notArmor() {
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
    fun aliceEncryptsForHerself_signEncrypt_decryptVerify_whenSecretAndPublicKeysAreAPair_armor() {
        val plaintext = "Hello world!"
        assertNotNull(plaintext)
        assertFalse(plaintext.isBlank())
        log.info("The input plaintext is: $plaintext")
        val alicePgpPublicKey: PGPPublicKey
        CLASS_LOADER.getResourceAsStream("pgp-keys/Johnny Miller's PGP Example - Alice_0x3A9AA381_public.asc")!!
            .use {
                alicePgpPublicKey = assertDoesNotThrow { readPublicKey(it) }
            }
        val alicePgpSecretKey: PGPSecretKey
        CLASS_LOADER.getResourceAsStream("pgp-keys/Johnny Miller's PGP Example - Alice_0x3A9AA381_SECRET.asc")!!
            .use {
                alicePgpSecretKey = assertDoesNotThrow { readSecretKey(it) }
            }

        // 1. Sign and encrypt
        val plaintextIn = IOUtils.toBufferedInputStream(plaintext.byteInputStream())
        val signEncryptedOut = ByteArrayOutputStream()
        assertDoesNotThrow {
            signEncryptInOnePass(
                plaintextIn,
                signEncryptedOut,
                "${this.javaClass.simpleName}-${Thread.currentThread().stackTrace[1].methodName}-enc.txt",
                "${this.javaClass.simpleName}-${Thread.currentThread().stackTrace[1].methodName}-plaintext.txt",
                "",
                alicePgpSecretKey,
                alicePgpPublicKey,
                armor = true,
                withIntegrityCheck = true
            )
        }
        val signEncryptedText = signEncryptedOut.toString()
        assertNotNull(signEncryptedText)
        assertFalse(signEncryptedText.isBlank())
        assertTrue(signEncryptedText.startsWith(PGP_MESSAGE_HEADER))
        assertTrue(signEncryptedText.endsWith(PGP_MESSAGE_FOOTER))
        log.info("Ciphertext:\n$signEncryptedText")

        // 2. Decrypt and verify
        val ciphertextIn = IOUtils.toBufferedInputStream(IOUtils.toInputStream(signEncryptedText, UTF_8))
        val alicePgpPublicKeyIn =
            CLASS_LOADER.getResourceAsStream("pgp-keys/Johnny Miller's PGP Example - Alice_0x3A9AA381_public.asc")!!
        val alicePgpSecretKeyIn =
            CLASS_LOADER.getResourceAsStream("pgp-keys/Johnny Miller's PGP Example - Alice_0x3A9AA381_SECRET.asc")!!
        val decryptVerifiedOut = ByteArrayOutputStream()
        assertDoesNotThrow {
            decryptVerify(ciphertextIn, alicePgpPublicKeyIn, alicePgpSecretKeyIn, "", decryptVerifiedOut)
        }.also {
            alicePgpPublicKeyIn.close()
            alicePgpSecretKeyIn.close()
        }
        val decryptVerifiedText = decryptVerifiedOut.toString()
        assertNotNull(decryptVerifiedText)
        assertFalse(decryptVerifiedText.isBlank())
        assertEquals(plaintext, decryptVerifiedText)
        log.info("Decrypt verified: $decryptVerifiedText")
    }

    @Test
    fun aliceSendMessageToBob_signEncrypt_decryptVerify_whenSecretAndPublicKeysAreNotAPair_armor() {
        val plaintext = "Hello world!"
        assertNotNull(plaintext)
        assertFalse(plaintext.isBlank())
        log.info("The input plaintext is: $plaintext")
        val bobPgpPublicKey: PGPPublicKey
        CLASS_LOADER.getResourceAsStream("pgp-keys/Johnny Miller's PGP Example - Bob_0xAF34CAD3_public.asc")!!
            .use {
                bobPgpPublicKey = assertDoesNotThrow { readPublicKey(it) }
            }
        val alicePgpSecretKey: PGPSecretKey
        CLASS_LOADER.getResourceAsStream("pgp-keys/Johnny Miller's PGP Example - Alice_0x3A9AA381_SECRET.asc")!!
            .use {
                alicePgpSecretKey = assertDoesNotThrow { readSecretKey(it) }
            }

        // 1. Sign and encrypt
        val plaintextIn = IOUtils.toBufferedInputStream(plaintext.byteInputStream())
        val signEncryptedOut = ByteArrayOutputStream()
        assertDoesNotThrow {
            signEncryptInOnePass(
                plaintextIn,
                signEncryptedOut,
                "${this.javaClass.simpleName}-${Thread.currentThread().stackTrace[1].methodName}-enc.txt",
                "${this.javaClass.simpleName}-${Thread.currentThread().stackTrace[1].methodName}-plaintext.txt",
                "",
                alicePgpSecretKey,
                bobPgpPublicKey,
                armor = true,
                withIntegrityCheck = true
            )
        }
        val signEncryptedText = signEncryptedOut.toString()
        assertNotNull(signEncryptedText)
        assertFalse(signEncryptedText.isBlank())
        assertTrue(signEncryptedText.startsWith(PGP_MESSAGE_HEADER))
        assertTrue(signEncryptedText.endsWith(PGP_MESSAGE_FOOTER))
        log.info("Ciphertext:\n$signEncryptedText")

        // 2. Decrypt and verify
        val ciphertextIn = IOUtils.toBufferedInputStream(IOUtils.toInputStream(signEncryptedText, UTF_8))
        val alicePgpPublicKeyIn =
            CLASS_LOADER.getResourceAsStream("pgp-keys/Johnny Miller's PGP Example - Alice_0x3A9AA381_public.asc")!!
        val bobPgpSecretKeyIn =
            CLASS_LOADER.getResourceAsStream("pgp-keys/Johnny Miller's PGP Example - Bob_0xAF34CAD3_SECRET.asc")!!
        val decryptVerifiedOut = ByteArrayOutputStream()
        assertDoesNotThrow {
            decryptVerify(ciphertextIn, alicePgpPublicKeyIn, bobPgpSecretKeyIn, "", decryptVerifiedOut)
        }.also {
            alicePgpPublicKeyIn.close()
            bobPgpSecretKeyIn.close()
        }
        val decryptVerifiedText = decryptVerifiedOut.toString()
        assertNotNull(decryptVerifiedText)
        assertFalse(decryptVerifiedText.isBlank())
        assertEquals(plaintext, decryptVerifiedText)
        log.info("Decrypt verified: $decryptVerifiedText")
    }

    @Test
    fun signAndVerify() {
        val plaintext = "Hello world!"
        val alicePgpSecretKey: PGPSecretKey
        CLASS_LOADER.getResourceAsStream("pgp-keys/Johnny Miller's PGP Example - Alice_0x3A9AA381_SECRET.asc")!!
            .use {
                alicePgpSecretKey = assertDoesNotThrow { readSecretKey(it) }
            }
        val passcode = "passcode"
        val signatureBytes = signMessage(plaintext.toByteArray(), alicePgpSecretKey, passcode.toCharArray(), true)
        assertNotNull(signatureBytes)
        val signature = String(signatureBytes)
        assertNotNull(signature)
        assertFalse(signature.isBlank())
        assertTrue(signature.startsWith(PGP_MESSAGE_HEADER))
        assertTrue(signature.endsWith(PGP_MESSAGE_FOOTER))
        log.info("Signature:\n$signature")

        val alicePgpPublicKey: PGPPublicKey
            CLASS_LOADER.getResourceAsStream("pgp-keys/Johnny Miller's PGP Example - Alice_0x3A9AA381_public.asc")!!
                .use {
                    alicePgpPublicKey = assertDoesNotThrow { readPublicKey(it) }
                }
        val verifiedSignatureBytes = verifySignature(signature.byteInputStream(), alicePgpPublicKey)
        assertNotNull(verifiedSignatureBytes)
        val verifiedSignature = String(verifiedSignatureBytes)
        assertEquals(plaintext, verifiedSignature)
        log.info("Verified signature:\n$verifiedSignature")
    }
}
