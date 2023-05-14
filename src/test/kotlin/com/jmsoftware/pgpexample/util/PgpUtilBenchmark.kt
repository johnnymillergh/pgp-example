package com.jmsoftware.pgpexample.util

/**
 * # PgpUtilBenchmark
 *
 * Change description here.
 *
 * @author Johnny Miller (锺俊), email: johnnysviva@outlook.com, 5/14/23 9:27 AM
 **/
@State(Scope.Benchmark)
@Fork(1)
@Warmup(iterations = 0)
@Measurement(iterations = 1, time = 1, timeUnit = TimeUnit.SECONDS)
class PgpUtilBenchmark {
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
        output(
            "${this.javaClass.simpleName}-${Thread.currentThread().stackTrace[1].methodName}-enc.txt",
            signEncryptedOut.toByteArray()
        )

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
}
