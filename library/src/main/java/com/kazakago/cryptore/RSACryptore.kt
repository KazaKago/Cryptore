package com.kazakago.cryptore

import android.annotation.TargetApi
import android.content.Context
import android.os.Build
import android.security.KeyPairGeneratorSpec
import java.io.IOException
import java.math.BigInteger
import java.security.*
import java.security.cert.CertificateException
import java.util.*
import javax.crypto.Cipher
import javax.crypto.NoSuchPaddingException
import javax.security.auth.x500.X500Principal

/**
 * RSA Cryptore.
 *
 * Created by tamura_k on 2016/04/22.
 */
@TargetApi(Build.VERSION_CODES.JELLY_BEAN_MR2)
class RSACryptore(
        alias: String,
        blockMode: BlockMode,
        encryptionPadding: EncryptionPadding,
        private val context: Context) : BaseCryptore(
        alias = alias,
        blockMode = blockMode,
        encryptionPadding = encryptionPadding) {

    @Throws(KeyStoreException::class, CertificateException::class, NoSuchAlgorithmException::class, IOException::class, NoSuchProviderException::class, InvalidAlgorithmParameterException::class)
    override fun createKeyStore(): KeyStore {
        return KeyStore.getInstance("AndroidKeyStore")
    }

    @Throws(NoSuchPaddingException::class, NoSuchAlgorithmException::class)
    override fun createCipher(blockMode: BlockMode, encryptionPadding: EncryptionPadding): Cipher {
        return Cipher.getInstance(CipherAlgorithm.RSA.rawValue + "/" + blockMode.rawValue + "/" + encryptionPadding.rawValue)
    }

    @Throws(UnrecoverableKeyException::class, NoSuchAlgorithmException::class, KeyStoreException::class, InvalidKeyException::class, IOException::class)
    override fun getEncryptKey(keyStore: KeyStore, alias: String): Key {
        return keyStore.getCertificate(alias).publicKey
    }

    @Throws(UnrecoverableKeyException::class, NoSuchAlgorithmException::class, KeyStoreException::class, InvalidAlgorithmParameterException::class, InvalidKeyException::class, IOException::class)
    override fun getDecryptKey(keyStore: KeyStore, alias: String): Key {
        return keyStore.getKey(alias, null) as PrivateKey
    }

    @Throws(NoSuchProviderException::class, NoSuchAlgorithmException::class, InvalidAlgorithmParameterException::class)
    override fun createNewKey(alias: String, blockMode: BlockMode, encryptionPadding: EncryptionPadding) {
        val start = Calendar.getInstance()
        val end = Calendar.getInstance()
        end.add(Calendar.YEAR, 100)
        val generator = KeyPairGenerator.getInstance(CipherAlgorithm.RSA.rawValue, "AndroidKeyStore")
        generator.initialize(KeyPairGeneratorSpec.Builder(context)
                .setAlias(alias)
                .setSubject(X500Principal("CN=Cryptore"))
                .setSerialNumber(BigInteger.ONE)
                .setStartDate(start.time)
                .setEndDate(end.time)
                .build())
        generator.generateKeyPair()
    }

}
