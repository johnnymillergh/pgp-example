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
import java.io.File
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

        /**
         * The constant BUFFER_SIZE.
         *
         * should always be the power of 2 (one shifted bitwise 16 places)
         */
        private const val BUFFER_SIZE = 1 shl 16

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

        /**
         * This is the primary function that will create encrypt a file and sign it
         * with a one-pass signature. This leans on C# example by John Opincar
         *
         * @param contentStream       the content stream
         * @param signEncryptedOut    The stream for the encrypted target file
         * @param targetFileName      file name on drive systems that will contain encrypted content
         * @param embeddedFileName    the original file name before encryption
         * @param secretKeyPassphrase The private key password for the key retrieved from collection used for signing
         * @param secretKey           the secret key
         * @param publicKey           the public key
         * @param armor               the armor
         * @param withIntegrityCheck  the with integrity check
         * @author Bilal Soylu
         * @see
         * <a href='http://boncode.blogspot.com/2012/01/java-implementing-pgp-single-pass-sign.html'>Java: Implementing PGP Single Pass Sign and Encrypt using League of Bouncy Castle library</a>
         * @see
         * <a href='https://docs.oracle.com/cd/E55956_01/doc.11123/user_guide/content/encryption_pgp_enc.html#:~:text=Encrypt%20and%20Sign%20in%20One%20Pass'>Encrypt and Sign in One Pass</a>
         */
        fun signEncryptInOnePass(
            contentStream: InputStream,
            signEncryptedOut: OutputStream,
            targetFileName: String,
            embeddedFileName: String,
            secretKeyPassphrase: String,
            secretKey: PGPSecretKey,
            publicKey: PGPPublicKey,
            armor: Boolean,
            withIntegrityCheck: Boolean
        ) {
            // need to convert the password to a character array
            var out = signEncryptedOut
            val password = secretKeyPassphrase.toCharArray()

            // armor stream if set
            if (armor) {
                out = ArmoredOutputStream(out)
            }

            // Init encrypted data generator
            val encryptedDataGenerator = PGPEncryptedDataGenerator(
                JcePGPDataEncryptorBuilder(publicKey.algorithm)
                    .setWithIntegrityPacket(withIntegrityCheck)
                    .setSecureRandom(SecureRandom())
                    .setProvider("BC")
            )
            encryptedDataGenerator.addMethod(JcePublicKeyKeyEncryptionMethodGenerator(publicKey).setProvider("BC"))
            val encryptedOut = encryptedDataGenerator.open(out, ByteArray(BUFFER_SIZE))

            // start compression
            val compressedDataGenerator = PGPCompressedDataGenerator(CompressionAlgorithmTags.ZIP)
            val compressedOut = compressedDataGenerator.open(encryptedOut)

            // start signature
            val pgpPrivKey = secretKey
                .extractPrivateKey(JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(password))
            val signatureGenerator = PGPSignatureGenerator(
                JcaPGPContentSignerBuilder(secretKey.publicKey.algorithm, HashAlgorithmTags.SHA1).setProvider("BC")
            )
            signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, pgpPrivKey)
            // iterate to find first signature to use
            val i = secretKey.publicKey.userIDs
            while (i.hasNext()) {
                val userId = i.next()
                val spGen = PGPSignatureSubpacketGenerator()
                spGen.addSignerUserID(false, userId)
                signatureGenerator.setHashedSubpackets(spGen.generate())
                // Just the first one!
                break
            }
            signatureGenerator.generateOnePassVersion(false).encode(compressedOut)

            // Create the Literal Data generator output stream
            val literalDataGenerator = PGPLiteralDataGenerator()
            // get file handle
            val targetFile = File(targetFileName)
            // create output stream
            val literalOut = literalDataGenerator.open(
                compressedOut,
                PGPLiteralData.BINARY,
                embeddedFileName,
                Date(targetFile.lastModified()), ByteArray(BUFFER_SIZE)
            )

            // read input file and write to target file using a buffer
            val buf = ByteArray(BUFFER_SIZE)
            var len: Int
            while (contentStream.read(buf, 0, buf.size).also { len = it } > 0) {
                literalOut.write(buf, 0, len)
                signatureGenerator.update(buf, 0, len)
            }
            // close everything down we are done
            literalOut.close()
            literalDataGenerator.close()
            signatureGenerator.generate().encode(compressedOut)
            compressedOut.close()
            compressedDataGenerator.close()
            encryptedOut.close()
            encryptedDataGenerator.close()
            if (armor) {
                out.close()
            }
        }

        /**
         * decryptVerify will decrypt a file that was encrypted using public key,
         * then signed with a private key as one pass signature based the example of verifyAndDecrypt() by Raul
         *
         * @param encryptedIn         the encrypted input stream
         * @param publicKeyIn         the sign public key input stream
         * @param secretKeyIn         the secret key input stream
         * @param secretKeyPassphrase the secret key passphrase
         * @param decryptVerifiedOut  the target stream
         * @author Bilal Soylu
         * @see
         * <a href='http://boncode.blogspot.com/2012/01/java-implementing-pgp-single-pass-sign.html'>Java: Implementing PGP Single Pass Sign and Encrypt using League of Bouncy Castle library</a>
         * @see
         * <a href='https://docs.oracle.com/cd/E55956_01/doc.11123/user_guide/content/encryption_pgp_enc.html#:~:text=Encrypt%20and%20Sign%20in%20One%20Pass'>Encrypt and Sign in One Pass</a>
         */
        fun decryptVerify(
            encryptedIn: InputStream,
            publicKeyIn: InputStream,
            secretKeyIn: InputStream,
            secretKeyPassphrase: String,
            decryptVerifiedOut: OutputStream
        ) {
            // The decrypted results.
            // StringBuffer result = new StringBuffer();
            // The private key we use to decrypt contents.
            var privateKey: PGPPrivateKey? = null
            // The PGP encrypted object representing the data to decrypt.
            var encryptedData: PGPPublicKeyEncryptedData? = null

            // Get the list of encrypted objects in the message. The first object in
            // the message might be a PGP marker, however, so we skip it if necessary.
            var objectFactory = PGPObjectFactory(
                PGPUtil.getDecoderStream(encryptedIn),
                JcaKeyFingerprintCalculator()
            )
            val firstObject = objectFactory.nextObject()
            val dataList =
                (if (firstObject is PGPEncryptedDataList) firstObject else objectFactory.nextObject()) as PGPEncryptedDataList

            // Find the encrypted object associated with a private key in our key ring.
            val dataObjectsIterator = dataList.getEncryptedDataObjects()
            val secretKeyCollection = PGPSecretKeyRingCollection(
                PGPUtil.getDecoderStream(secretKeyIn), JcaKeyFingerprintCalculator()
            )
            while (dataObjectsIterator.hasNext()) {
                encryptedData = dataObjectsIterator.next() as PGPPublicKeyEncryptedData
                privateKey = findSecretKey(
                    secretKeyCollection, encryptedData.keyID,
                    secretKeyPassphrase.toCharArray()
                )
                break
            }
            if (privateKey == null) {
                throw RuntimeException("secret key for message not found")
            }

            // Get a handle to the decrypted data as an input stream
            val clearDataInputStream = encryptedData?.getDataStream(
                JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(privateKey)
            )
            val clearObjectFactory = PGPObjectFactory(clearDataInputStream, JcaKeyFingerprintCalculator())
            var message = clearObjectFactory.nextObject()

            // Handle case where the data is compressed
            if (message is PGPCompressedData) {
                val compressedData = message
                objectFactory = PGPObjectFactory(compressedData.dataStream, JcaKeyFingerprintCalculator())
                message = objectFactory.nextObject()
            }
            var calculatedSignature: PGPOnePassSignature? = null
            if (message is PGPOnePassSignatureList) {
                calculatedSignature = message[0]
                val publicKeyRingCollection = PGPPublicKeyRingCollection(
                    PGPUtil.getDecoderStream(publicKeyIn),
                    JcaKeyFingerprintCalculator()
                )
                val signPublicKey = publicKeyRingCollection.getPublicKey(calculatedSignature.keyID)
                calculatedSignature.init(JcaPGPContentVerifierBuilderProvider().setProvider("BC"), signPublicKey)
                message = objectFactory.nextObject()
            }

            // We should only have literal data, from which we can finally read the
            // decrypted message.
            if (message is PGPLiteralData) {
                val literalDataInputStream = message.inputStream
                var nextByte: Int
                while (literalDataInputStream.read().also { nextByte = it } >= 0) {
                    // InputStream.read guarantees to return a byte (range 0-255),
                    // so we can safely cast to char.
                    // also update
                    calculatedSignature?.update(nextByte.toByte())
                    // calculated one pass signature
                    // result.append((char) nextByte);
                    // add to file instead of StringBuffer
                    decryptVerifiedOut.write(nextByte.toChar().code)
                }
                decryptVerifiedOut.close()
            } else {
                throw RuntimeException("unexpected message type " + message.javaClass.simpleName)
            }
            if (calculatedSignature != null) {
                val signatureList = objectFactory.nextObject() as PGPSignatureList
                log.info("signature list ({} sigs) is {}", signatureList.size(), signatureList)
                val messageSignature = signatureList.get(0)
                if (!calculatedSignature.verify(messageSignature)) {
                    throw RuntimeException("signature verification failed")
                }
            }
            if (encryptedData!!.isIntegrityProtected) {
                if (encryptedData.verify()) {
                    log.info("message integrity protection verification succeeded")
                } else {
                    throw RuntimeException("message failed integrity check")
                }
            } else {
                log.warn("message not integrity protected")
            }

            //close streams
            clearDataInputStream?.close()
        }
    }
}
