package com.ignis.ciphermanager;

import android.content.Context;
import android.os.Build;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;

import javax.crypto.NoSuchPaddingException;

/**
 * CipherManager Interface.
 * <p/>
 * Created by tamura_k on 2016/05/09.
 */
public interface CipherManager {

    /**
     * Initialize KeyStore.
     */
    void initKeyStore() throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, NoSuchProviderException, InvalidAlgorithmParameterException;

    /**
     * Initialize Cipher.
     */
    void initCipher() throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException;

    /**
     * Encrypt string text.
     *
     * @param plainText string to be encrypted
     * @return base64 encoded cipher text
     */
    String encryptString(String plainText) throws KeyStoreException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IOException, NoSuchProviderException, InvalidAlgorithmParameterException, UnrecoverableEntryException;

    /**
     * Decrypt base64 encoded cipher text.
     *
     * @param encryptedText base64 encoded cipher text
     * @return plain text string
     */
    String decryptString(String encryptedText) throws KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, UnrecoverableEntryException, NoSuchPaddingException, InvalidKeyException, IOException, InvalidAlgorithmParameterException;

    /**
     * Create new key pair.
     * <p/>
     * Create RSA/AES key pair for encryption/decryption using RSA/AES OAEP.
     * See KeyGenParameterSpec document.
     */
    void createNewKey() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchProviderException, KeyStoreException;

    /**
     * Get EncryptCipher IV.
     *
     * @return
     */
    byte[] getCipherIV();

    /**
     * Set EncryptCipher IV.
     *
     * @param iv
     */
    void setCipherIV(byte[] iv);

    class Builder {

        private static final String BLOCK_MODE_DEFAULT__AES = CipherProperties.BLOCK_MODE_CBC;
        private static final String ENCRYPTION_PADDING_DEFAULT__AES = CipherProperties.ENCRYPTION_PADDING_PKCS7;
        private static final String BLOCK_MODE_DEFAULT__RSA = CipherProperties.BLOCK_MODE_ECB;
        private static final String ENCRYPTION_PADDING_DEFAULT__RSA = CipherProperties.ENCRYPTION_PADDING_RSA_PKCS1;

        protected CipherAlgorithm type;
        protected String blockMode;
        protected String encryptionPadding;
        protected String alias;
        protected Context context;

        public Builder type(CipherAlgorithm type) {
            this.type = type;
            return this;
        }

        public Builder blockMode(String blockMode) {
            this.blockMode = blockMode;
            return this;
        }

        public Builder encryptionPadding(String encryptionPadding) {
            this.encryptionPadding = encryptionPadding;
            return this;
        }

        public Builder alias(String alias) {
            this.alias = alias;
            return this;
        }

        public Builder context(Context context) {
            this.context = context;
            return this;
        }

        public CipherManager build() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException, InvalidAlgorithmParameterException, IOException, NoSuchPaddingException {
            if (alias == null || alias.length() == 0) {
                throw new NullPointerException("Need \"alias\".");
            }
            if (type == null) {
                throw new NullPointerException("Need \"type\".");
            } else if (type == CipherAlgorithm.AES) {
                if (blockMode == null) {
                    blockMode = BLOCK_MODE_DEFAULT__AES;
                }
                if (encryptionPadding == null) {
                    encryptionPadding = ENCRYPTION_PADDING_DEFAULT__AES;
                }
                if (Build.VERSION_CODES.M <= Build.VERSION.SDK_INT) {
                    return new AESCipherManager(this);
                } else {
                    throw new NoSuchAlgorithmException("AES is support only above API Lv23.");
                }
            } else if (type == CipherAlgorithm.RSA) {
                if (blockMode == null) {
                    blockMode = BLOCK_MODE_DEFAULT__RSA;
                }
                if (encryptionPadding == null) {
                    encryptionPadding = ENCRYPTION_PADDING_DEFAULT__RSA;
                }
                if (Build.VERSION_CODES.M <= Build.VERSION.SDK_INT) {
                    return new RSACipherManagerM(this);
                } else if (Build.VERSION_CODES.JELLY_BEAN_MR2 <= Build.VERSION.SDK_INT) {
                    if (context == null) {
                        throw new NullPointerException("Need \"Context\" for RSA on below API Lv22");
                    } else {
                        return new RSACipherManager(this);
                    }
                } else {
                    throw new NoSuchAlgorithmException("RSA is support only above API Lv18.");
                }
            } else {
                throw new IllegalArgumentException("Unsupported Algorithm.");
            }
        }

    }

}
