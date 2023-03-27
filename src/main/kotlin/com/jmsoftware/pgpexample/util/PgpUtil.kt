package com.jmsoftware.pgpexample.util

import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.bcpg.BCPGOutputStream
import org.bouncycastle.bcpg.CompressionAlgorithmTags
import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openpgp.*
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import org.bouncycastle.openpgp.operator.jcajce.*
import org.bouncycastle.util.io.Streams
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.security.SecureRandom
import java.security.Security
import java.util.*

/**
 * # PGP Utilities
 *
 * @author Johnny Miller, date: 3/21/2023 7:29 PM
 * @see org.bouncycastle.openpgp.examples.KeyBasedFileProcessor A simple utility class that encrypts/decrypts public key based encryption files.
 * @see org.bouncycastle.openpgp.examples.SignedFileProcessor A simple utility class that signs and verifies files.
 * @see
 * <a href='https://github.com/jordanbaucke/PGP-Sign-and-Encrypt/blob/master/src/SignAndEncrypt.java'>Inspired by GitHub repo: jordanbaucke / PGP-Sign-and-Encrypt</a>
 * @see <a href='https://mvnrepository.com/artifact/org.bouncycastle/bcpg-jdk18on/1.72.2'>Bouncy Castle OpenPGP API » 1.72.2</a>
 */
class PgpUtil {
    companion object {
        private val log = logger()

        init {
            // add provider only if it's not in the JVM
            if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
                // Bouncy JCE Provider, http://bouncycastle.org/latest_releases.html
                Security.insertProviderAt(BouncyCastleProvider(), 0)
                log.warn("BouncyCastle Provider was added")
            }
        }

        /**
         * A simple routine that opens a key ring file and loads the first available key
         * suitable for encryption.
         *
         * @param input data stream containing the public key data
         * @return the first public key found.
         * @see org.bouncycastle.openpgp.examples.PGPExampleUtil.readPublicKey
         * @see org.bouncycastle.openpgp.examples.PGPExampleUtil
         */
        @Suppress("DuplicatedCode")
        fun readPublicKey(input: InputStream?): PGPPublicKey {
            val pgpPub = PGPPublicKeyRingCollection(
                PGPUtil.getDecoderStream(input), JcaKeyFingerprintCalculator()
            )

            //
            // we just loop through the collection till we find a key suitable for encryption,
            // in the real world you would probably want to be a bit smarter about this.
            //
            val keyRingIter = pgpPub.keyRings
            while (keyRingIter.hasNext()) {
                val keyIter = keyRingIter.next().publicKeys
                while (keyIter.hasNext()) {
                    val key = keyIter.next()
                    if (key.isEncryptionKey) {
                        return key
                    }
                }
            }
            throw IllegalArgumentException("Can't find encryption key in key ring.")
        }

        /**
         * A simple routine that opens a key ring file and loads the first available
         * key suitable for signature generation.
         *
         * @param input stream to read the secret key ring collection from.
         * @return a secret key.
         * @see org.bouncycastle.openpgp.examples.PGPExampleUtil.readSecretKey
         * @see org.bouncycastle.openpgp.examples.PGPExampleUtil
         */
        @Suppress("DuplicatedCode")
        fun readSecretKey(input: InputStream): PGPSecretKey {
            val pgpSec = PGPSecretKeyRingCollection(
                PGPUtil.getDecoderStream(input), BcKeyFingerprintCalculator()
            )

            //
            // we just loop through the collection till we find a key suitable for encryption,
            // in the real world you would probably want to be a bit smarter about this.
            //
            val keyRingIter = pgpSec.keyRings
            while (keyRingIter.hasNext()) {
                val keyIter = keyRingIter.next().secretKeys
                while (keyIter.hasNext()) {
                    val key = keyIter.next()
                    if (key.isSigningKey) {
                        return key
                    }
                }
            }
            throw IllegalArgumentException("Can't find signing key in key ring.")
        }

        /**
         * Search a secret key ring collection for a secret key corresponding to keyId if it
         * exists.
         *
         * @param pgpSec a secret key ring collection.
         * @param keyId  keyId we want.
         * @param pass   passphrase to decrypt secret key with.
         * @return the private key.
         * @throws PGPException the pgp exception
         * @see org.bouncycastle.openpgp.examples.PGPExampleUtil.findSecretKey
         * @see org.bouncycastle.openpgp.examples.PGPExampleUtil
         */
        private fun findSecretKey(pgpSec: PGPSecretKeyRingCollection, keyId: Long, pass: CharArray): PGPPrivateKey? {
            val pgpSecKey = pgpSec.getSecretKey(keyId) ?: return null
            return pgpSecKey.extractPrivateKey(JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(pass))
        }

        /**
         * Encrypt plaintext.
         *
         * @param plaintextByteArray the plaintext bytes
         * @param encKey             the enc key
         * @param armor              the armor
         * @param withIntegrityCheck the with integrity check
         * @return the string
         * @see org.bouncycastle.openpgp.examples.KeyBasedFileProcessor.encryptFile(java.io.OutputStream, java.lang.String, org.bouncycastle.openpgp.PGPPublicKey, boolean, boolean)
         * @see org.bouncycastle.openpgp.examples.KeyBasedFileProcessor PGP Sample utilities class from Bouncy Castle
         */
        fun encryptPlaintext(
            plaintextByteArray: ByteArray,
            encKey: PGPPublicKey,
            armor: Boolean,
            withIntegrityCheck: Boolean
        ): ByteArray {
            val encOut = ByteArrayOutputStream()
            var out: OutputStream = encOut
            if (armor) {
                out = ArmoredOutputStream(out)
            }
            val bOut = ByteArrayOutputStream()
            val comData = PGPCompressedDataGenerator(CompressionAlgorithmTags.ZIP)
            // open it with the final
            val cos = comData.open(bOut)
            val lData = PGPLiteralDataGenerator()
            val pOut = lData.open(
                cos,
                PGPLiteralData.BINARY,
                PGPLiteralData.CONSOLE,
                // length of the message
                plaintextByteArray.size.toLong(),
                // current time
                Date()
            )
            pOut.write(plaintextByteArray)
            lData.close()
            comData.close()
            val encGen = PGPEncryptedDataGenerator(
                JcePGPDataEncryptorBuilder(encKey.algorithm)
                    .setWithIntegrityPacket(withIntegrityCheck)
                    .setSecureRandom(SecureRandom())
                    .setProvider("BC")
            )
            encGen.addMethod(JcePublicKeyKeyEncryptionMethodGenerator(encKey).setProvider("BC"))
            val bytes = bOut.toByteArray()
            val cOut: OutputStream = encGen.open(out, bytes.size.toLong())
            cOut.write(bytes)
            cOut.close()
            if (armor) {
                out.close()
            }
            return encOut.toByteArray()
        }

        /**
         * decrypt the passed in message stream
         *
         * @param cipherIn        the in
         * @param pgpPrivateKeyIn the key in
         * @param passwd          the passwd
         * @return string
         * @see org.bouncycastle.openpgp.examples.KeyBasedFileProcessor.decryptFile(java.io.InputStream, java.io.InputStream, char[], java.lang.String)
         * @see org.bouncycastle.openpgp.examples.KeyBasedFileProcessor BC PGP sample utilities class
         */
        fun decryptCipher(
            cipherIn: InputStream,
            pgpPrivateKeyIn: InputStream,
            passwd: CharArray
        ): ByteArray {
            val pgpF = JcaPGPObjectFactory(PGPUtil.getDecoderStream(cipherIn))
            val enc: PGPEncryptedDataList
            val o = pgpF.nextObject()
            //
            // the first object might be a PGP marker packet.
            //
            enc = if (o is PGPEncryptedDataList) o else pgpF.nextObject() as PGPEncryptedDataList

            //
            // find the secret key
            //
            val it = enc.encryptedDataObjects
            var sKey: PGPPrivateKey? = null
            var pbe: PGPPublicKeyEncryptedData? = null
            val pgpSec = PGPSecretKeyRingCollection(
                PGPUtil.getDecoderStream(pgpPrivateKeyIn), JcaKeyFingerprintCalculator()
            )
            while (sKey == null && it.hasNext()) {
                pbe = it.next() as PGPPublicKeyEncryptedData
                sKey = findSecretKey(pgpSec, pbe.keyID, passwd)
            }
            requireNotNull(sKey) { "secret key for message not found." }
            val clear = pbe!!.getDataStream(JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(sKey))
            val plainFact = JcaPGPObjectFactory(clear)
            var message = plainFact.nextObject()
            if (message is PGPCompressedData) {
                val cData = message
                val pgpFact = JcaPGPObjectFactory(cData.dataStream)
                message = pgpFact.nextObject()
            }
            if (pbe.isIntegrityProtected) {
                if (!pbe.verify()) {
                    log.error("Message failed integrity check")
                } else {
                    log.info("Message integrity check passed")
                }
            } else {
                log.warn("No message integrity check")
            }

            return when (message) {
                is PGPLiteralData -> {
                    log.info("PGPLiteralData's file name: ${message.fileName}, modificationTime: ${message.modificationTime}")
                    val uncOut = ByteArrayOutputStream()
                    Streams.pipeAll(message.dataStream, uncOut, 8192)
                    uncOut.toByteArray()
                }

                is PGPOnePassSignatureList -> {
                    throw PGPException("Encrypted message contains a signed message - not literal data.")
                }

                else -> {
                    throw PGPException("Message is not a simple encrypted file - type unknown.")
                }
            }
        }

        /**
         * Sign the message with a PGP secret key.
         *
         * @param messageByteArray the message to be signed
         * @param pgpSecretKey     the pgp secret key
         * @param pass             the pass
         * @param armor            the armor
         * @return the signature
         * @see org.bouncycastle.openpgp.examples.SignedFileProcessor.signFile
         * @see org.bouncycastle.openpgp.examples.SignedFileProcessor A simple utility class that signs and verifies files.
         */
        fun signMessage(
            messageByteArray: ByteArray,
            pgpSecretKey: PGPSecretKey,
            pass: CharArray?,
            armor: Boolean
        ): ByteArray {
            val encOut = ByteArrayOutputStream()
            var out: OutputStream = encOut
            if (armor) {
                out = ArmoredOutputStream(out)
            }

            // Unlock the private key using the password
            val pgpPrivateKey =
                pgpSecretKey.extractPrivateKey(JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(pass))

            // Signature generator, we can generate the public key from the private
            // key! Nifty!
            val sGen = PGPSignatureGenerator(
                JcaPGPContentSignerBuilder(
                    pgpSecretKey.publicKey.algorithm,
                    HashAlgorithmTags.SHA1
                ).setProvider("BC")
            )
            sGen.init(PGPSignature.BINARY_DOCUMENT, pgpPrivateKey)
            val it = pgpSecretKey.publicKey.userIDs
            if (it.hasNext()) {
                val spGen = PGPSignatureSubpacketGenerator()
                spGen.addSignerUserID(false, it.next() as String)
                sGen.setHashedSubpackets(spGen.generate())
            }
            val comData = PGPCompressedDataGenerator(CompressionAlgorithmTags.ZLIB)
            val bOut = BCPGOutputStream(comData.open(out))
            sGen.generateOnePassVersion(false).encode(bOut)
            val lGen = PGPLiteralDataGenerator()
            val lOut =
                lGen.open(bOut, PGPLiteralData.BINARY, PGPLiteralData.CONSOLE, messageByteArray.size.toLong(), Date())
            for (aByte in messageByteArray) {
                lOut.write(aByte.toInt())
                sGen.update(aByte)
            }
            lOut.close()
            lGen.close()
            sGen.generate().encode(bOut)
            comData.close()
            out.close()
            return encOut.toByteArray()
        }

        /**
         * verify the passed in file as being correctly signed.
         *
         * @param messageIn    the message input
         * @param pgpPublicKey the pgp public key
         * @return the string
         * @see org.bouncycastle.openpgp.examples.SignedFileProcessor.verifyFile
         * @see org.bouncycastle.openpgp.examples.SignedFileProcessor A simple utility class that signs and verifies files.
         */
        fun verifySignature(
            messageIn: InputStream?,
            pgpPublicKey: PGPPublicKey?
        ): ByteArray {
            val messageIn = PGPUtil.getDecoderStream(messageIn)
            var pgpFact = JcaPGPObjectFactory(messageIn)
            val c1 = pgpFact.nextObject() as PGPCompressedData
            pgpFact = JcaPGPObjectFactory(c1.dataStream)
            val p1 = pgpFact.nextObject() as PGPOnePassSignatureList
            val ops = p1.get(0)
            val p2 = pgpFact.nextObject() as PGPLiteralData
            val dIn = p2.inputStream
            var ch: Int
            val out = ByteArrayOutputStream()
            ops.init(JcaPGPContentVerifierBuilderProvider().setProvider("BC"), pgpPublicKey)
            while (dIn.read().also { ch = it } >= 0) {
                ops.update(ch.toByte())
                out.write(ch)
            }
            out.close()
            val p3 = pgpFact.nextObject() as PGPSignatureList
            if (ops.verify(p3.get(0))) {
                log.info("Signature verified.")
                return out.toByteArray()
            }
            log.error("Signature verification failed.")
            throw PGPException("Signature verification failed")
        }
    }
}
