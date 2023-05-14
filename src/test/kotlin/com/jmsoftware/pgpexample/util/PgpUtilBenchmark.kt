package com.jmsoftware.pgpexample.util

import org.apache.commons.io.IOUtils
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPSecretKey
import org.openjdk.jmh.annotations.*
import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets
import java.util.concurrent.TimeUnit

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
@BenchmarkMode(Mode.Throughput)
class PgpUtilBenchmark {
    companion object {
        internal val log = logger()
    }

    @Benchmark
    fun aliceSendMessageToBob_signEncrypt_whenSecretAndPublicKeysAreNotAPair_armor() {
        val plaintext = "Hello world!"
        //log.info("The input plaintext is: $plaintext")
        val bobPgpPublicKey: PGPPublicKey
        CLASS_LOADER.getResourceAsStream("pgp-keys/Johnny Miller's PGP Example - Bob_0xAF34CAD3_public.asc")!!
            .use {
                bobPgpPublicKey = readPublicKey(it)
            }
        val alicePgpSecretKey: PGPSecretKey
        CLASS_LOADER.getResourceAsStream("pgp-keys/Johnny Miller's PGP Example - Alice_0x3A9AA381_SECRET.asc")!!
            .use {
                alicePgpSecretKey = readSecretKey(it)
            }

        // 1. Sign and encrypt
        val plaintextIn = IOUtils.toBufferedInputStream(plaintext.byteInputStream())
        val signEncryptedOut = ByteArrayOutputStream()
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

    //@Benchmark
    fun aliceSendMessageToBob_signEncrypt_decryptVerify_whenSecretAndPublicKeysAreNotAPair_armor() {
        val plaintext = "Hello world!"
        //log.info("The input plaintext is: $plaintext")
        val bobPgpPublicKey: PGPPublicKey
        CLASS_LOADER.getResourceAsStream("pgp-keys/Johnny Miller's PGP Example - Bob_0xAF34CAD3_public.asc")!!
            .use {
                bobPgpPublicKey = readPublicKey(it)
            }
        val alicePgpSecretKey: PGPSecretKey
        CLASS_LOADER.getResourceAsStream("pgp-keys/Johnny Miller's PGP Example - Alice_0x3A9AA381_SECRET.asc")!!
            .use {
                alicePgpSecretKey = readSecretKey(it)
            }

        // 1. Sign and encrypt
        val plaintextIn = IOUtils.toBufferedInputStream(plaintext.byteInputStream())
        val signEncryptedOut = ByteArrayOutputStream()
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
        val signEncryptedText = signEncryptedOut.toString()
        //log.info("Ciphertext:\n$signEncryptedText")

        // 2. Decrypt and verify
        val ciphertextIn = IOUtils.toBufferedInputStream(
            IOUtils.toInputStream(
                signEncryptedText,
                StandardCharsets.UTF_8
            )
        )
        val alicePgpPublicKeyIn =
            CLASS_LOADER.getResourceAsStream("pgp-keys/Johnny Miller's PGP Example - Alice_0x3A9AA381_public.asc")!!
        val bobPgpSecretKeyIn =
            CLASS_LOADER.getResourceAsStream("pgp-keys/Johnny Miller's PGP Example - Bob_0xAF34CAD3_SECRET.asc")!!
        val decryptVerifiedOut = ByteArrayOutputStream()
        decryptVerify(ciphertextIn, alicePgpPublicKeyIn, bobPgpSecretKeyIn, "", decryptVerifiedOut).also {
            alicePgpPublicKeyIn.close()
            bobPgpSecretKeyIn.close()
        }
        val decryptVerifiedText = decryptVerifiedOut.toString()
        //log.info("Decrypt verified: $decryptVerifiedText")
    }
}
