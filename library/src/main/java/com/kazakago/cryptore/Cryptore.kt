package com.kazakago.cryptore

import android.content.Context
import android.os.Build

import java.io.IOException
import java.security.*
import java.security.cert.CertificateException
import javax.crypto.Cipher

import javax.crypto.NoSuchPaddingException

/**
 * Cryptore Interface.
 *
 * Created by tamura_k on 2016/05/09.
 */
interface Cryptore {

    /**
     * Encrypt byte.
     *
     * @param plainByte byte to be encrypted
     * *
     * @return cipher byte
     */
    @Throws(KeyStoreException::class, NoSuchPaddingException::class, NoSuchAlgorithmException::class, InvalidKeyException::class, IOException::class, NoSuchProviderException::class, InvalidAlgorithmParameterException::class, UnrecoverableEntryException::class)
    fun encrypt(plainByte: ByteArray): EncryptResult

    /**
     * Decrypt byte
     *
     * @param encryptedByte cipher byte
     * @param cipherIV cipher IV
     * *
     * @return plain byte
     */
    @Throws(UnrecoverableKeyException::class, NoSuchAlgorithmException::class, KeyStoreException::class, InvalidAlgorithmParameterException::class, InvalidKeyException::class, IOException::class)
    fun decrypt(encryptedByte: ByteArray, cipherIV: ByteArray? = null): DecryptResult

    class Builder(var alias: String,
                  var type: CipherAlgorithm = Cryptore.Builder.CIPHER_ALGORITHM_DEFAULT) {

        companion object {
            private val CIPHER_ALGORITHM_DEFAULT = CipherAlgorithm.RSA
            private val BLOCK_MODE_DEFAULT__AES = BlockMode.CBC
            private val ENCRYPTION_PADDING_DEFAULT__AES = EncryptionPadding.PKCS7
            private val BLOCK_MODE_DEFAULT__RSA = BlockMode.ECB
            private val ENCRYPTION_PADDING_DEFAULT__RSA = EncryptionPadding.RSA_PKCS1
        }

        var context: Context? = null
        var blockMode: BlockMode
        var encryptionPadding: EncryptionPadding

        init {
            when (type) {
                CipherAlgorithm.RSA -> {
                    blockMode = BLOCK_MODE_DEFAULT__RSA
                    encryptionPadding = ENCRYPTION_PADDING_DEFAULT__RSA
                }
                CipherAlgorithm.AES -> {
                    blockMode = BLOCK_MODE_DEFAULT__AES
                    encryptionPadding = ENCRYPTION_PADDING_DEFAULT__AES
                }
            }
        }

        @Throws(CertificateException::class, NoSuchAlgorithmException::class, KeyStoreException::class, NoSuchProviderException::class, InvalidAlgorithmParameterException::class, IOException::class, NoSuchPaddingException::class)
        fun build(): Cryptore {
            when (type) {
                CipherAlgorithm.AES -> {
                    if (Build.VERSION_CODES.M <= Build.VERSION.SDK_INT) {
                        return AESCryptore(alias = alias, blockMode = blockMode, encryptionPadding = encryptionPadding)
                    } else {
                        throw NoSuchAlgorithmException("AES is support only above API Lv23.")
                    }
                }
                CipherAlgorithm.RSA -> {
                    if (Build.VERSION_CODES.M <= Build.VERSION.SDK_INT) {
                        return RSACryptoreM(alias = alias, blockMode = blockMode, encryptionPadding = encryptionPadding)
                    } else if (Build.VERSION_CODES.JELLY_BEAN_MR2 <= Build.VERSION.SDK_INT) {
                        context?.let {
                            return RSACryptore(alias = alias, blockMode = blockMode, encryptionPadding = encryptionPadding, context = it)
                        } ?: run {
                            throw NullPointerException("Need \"Context\" for RSA on below API Lv22")
                        }
                    } else {
                        throw NoSuchAlgorithmException("RSA is support only above API Lv18.")
                    }
                }
                else -> throw IllegalArgumentException("Unsupported Algorithm.")
            }
        }

    }

}
