package com.kazakago.cryptore

import android.content.Context
import java.io.IOException
import java.security.*
import java.security.cert.CertificateException
import javax.crypto.Cipher
import javax.crypto.NoSuchPaddingException
import javax.crypto.spec.IvParameterSpec

/**
 * Base Cryptore class.
 *
 * Created by KazaKago on 2017/01/20.
 */
abstract class BaseCryptore(
        private val alias: String,
        private val blockMode: BlockMode,
        private val encryptionPadding: EncryptionPadding,
        val context: Context?) : Cryptore {

    private val cipher: Cipher
    private val keyStore: KeyStore

    init {
        cipher = this.createCipher(blockMode = blockMode, encryptionPadding = encryptionPadding)
        keyStore = this.createKeyStore()
        keyStore.load(null)
        createKeystoreAliasIfNeeded()
    }

    private fun createKeystoreAliasIfNeeded() {
        if (!keyStore.containsAlias(alias)) this.createNewKey(alias = alias, blockMode = blockMode, encryptionPadding = encryptionPadding)
    }

    @Throws(UnrecoverableKeyException::class, NoSuchAlgorithmException::class, KeyStoreException::class, InvalidKeyException::class, IOException::class)
    override fun encrypt(plainByte: ByteArray): EncryptResult {
        createKeystoreAliasIfNeeded()
        val encryptKey = getEncryptKey(keyStore = keyStore, alias = alias)
        cipher.init(Cipher.ENCRYPT_MODE, encryptKey)
        return EncryptResult(cipher.doFinal(plainByte), cipher.iv)
    }

    @Throws(UnrecoverableKeyException::class, NoSuchAlgorithmException::class, KeyStoreException::class, InvalidAlgorithmParameterException::class, InvalidKeyException::class, IOException::class)
    override fun decrypt(encryptedByte: ByteArray, cipherIV: ByteArray?): DecryptResult {
        createKeystoreAliasIfNeeded()
        val decryptKey = getDecryptKey(keyStore = keyStore, alias = alias)
        cipherIV?.let {
            cipher.init(Cipher.DECRYPT_MODE, decryptKey, IvParameterSpec(cipherIV))
        } ?: run {
            cipher.init(Cipher.DECRYPT_MODE, decryptKey)
        }
        return DecryptResult(cipher.doFinal(encryptedByte), cipher.iv)
    }

    @Throws(KeyStoreException::class)
    override fun reset(): Boolean {
        val hasAlias = keyStore.containsAlias(alias)
        if (hasAlias) {
            keyStore.deleteEntry(alias)
        }
        return hasAlias
    }

    /**
     * Initialize KeyStore.
     */
    @Throws(KeyStoreException::class, CertificateException::class, NoSuchAlgorithmException::class, IOException::class, NoSuchProviderException::class, InvalidAlgorithmParameterException::class)
    protected abstract fun createKeyStore(): KeyStore

    /**
     * Initialize Cipher.
     */
    @Throws(NoSuchPaddingException::class, NoSuchAlgorithmException::class)
    protected abstract fun createCipher(blockMode: BlockMode, encryptionPadding: EncryptionPadding): Cipher

    /**
     * Get Encryption Key.
     */
    @Throws(UnrecoverableKeyException::class, NoSuchAlgorithmException::class, KeyStoreException::class, InvalidKeyException::class, IOException::class)
    protected abstract fun getEncryptKey(keyStore: KeyStore, alias: String): Key

    /**
     * Get Decryption Key.
     */
    @Throws(UnrecoverableKeyException::class, NoSuchAlgorithmException::class, KeyStoreException::class, InvalidAlgorithmParameterException::class, InvalidKeyException::class, IOException::class)
    protected abstract fun getDecryptKey(keyStore: KeyStore, alias: String): Key

    /**
     * Create new key pair.
     * Create RSA/AES key pair for encryption/decryption using RSA/AES OAEP.
     */
    @Throws(NoSuchAlgorithmException::class, InvalidAlgorithmParameterException::class, NoSuchProviderException::class, KeyStoreException::class)
    protected abstract fun createNewKey(alias: String, blockMode: BlockMode, encryptionPadding: EncryptionPadding)

}
