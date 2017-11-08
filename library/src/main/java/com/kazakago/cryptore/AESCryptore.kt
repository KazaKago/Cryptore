package com.kazakago.cryptore

import android.annotation.TargetApi
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.IOException
import java.security.*
import java.security.cert.CertificateException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.NoSuchPaddingException
import javax.crypto.SecretKey

/**
 * AES Cryptore.
 *
 * Created by KazaKago on 2016/04/22.
 */
@TargetApi(Build.VERSION_CODES.M)
class AESCryptore(
        alias: String,
        blockMode: BlockMode,
        encryptionPadding: EncryptionPadding) : BaseCryptore(
        alias = alias,
        blockMode = blockMode,
        encryptionPadding = encryptionPadding,
        context = null) {

    @Throws(KeyStoreException::class, CertificateException::class, NoSuchAlgorithmException::class, IOException::class, NoSuchProviderException::class, InvalidAlgorithmParameterException::class)
    override fun createKeyStore(): KeyStore {
        return KeyStore.getInstance("AndroidKeyStore")
    }

    @Throws(NoSuchPaddingException::class, NoSuchAlgorithmException::class)
    override fun createCipher(blockMode: BlockMode, encryptionPadding: EncryptionPadding): Cipher {
        return Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/" + blockMode.rawValue + "/" + encryptionPadding.rawValue)
    }

    @Throws(UnrecoverableKeyException::class, NoSuchAlgorithmException::class, KeyStoreException::class, InvalidKeyException::class, IOException::class)
    override fun getEncryptKey(keyStore: KeyStore, alias: String): Key {
        return keyStore.getKey(alias, null) as SecretKey
    }

    @Throws(UnrecoverableKeyException::class, NoSuchAlgorithmException::class, KeyStoreException::class, InvalidAlgorithmParameterException::class, InvalidKeyException::class, IOException::class)
    override fun getDecryptKey(keyStore: KeyStore, alias: String): Key {
        return keyStore.getKey(alias, null) as SecretKey
    }

    @Throws(NoSuchProviderException::class, NoSuchAlgorithmException::class, InvalidAlgorithmParameterException::class)
    override fun createNewKey(alias: String, blockMode: BlockMode, encryptionPadding: EncryptionPadding) {
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(blockMode.rawValue)
                .setEncryptionPaddings(encryptionPadding.rawValue)
                .build())
        generator.generateKey()
    }

}
