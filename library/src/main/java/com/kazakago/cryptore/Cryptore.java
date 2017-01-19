package com.kazakago.cryptore;

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
 * Cryptore Interface.
 * <p/>
 * Created by tamura_k on 2016/05/09.
 */
public interface Cryptore {

    /**
     * Initialize KeyStore.
     */
    void initKeyStore() throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, NoSuchProviderException, InvalidAlgorithmParameterException;

    /**
     * Initialize Cipher.
     */
    void initCipher() throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException;

    /**
     * Encrypt byte.
     *
     * @param plainByte byte to be encrypted
     * @return cipher byte
     */
    byte[] encrypt(byte[] plainByte) throws KeyStoreException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IOException, NoSuchProviderException, InvalidAlgorithmParameterException, UnrecoverableEntryException;

    /**
     * Decrypt byte.
     *
     * @param encryptedByte cipher byte
     * @return plain byte
     */
    byte[] decrypt(byte[] encryptedByte) throws KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, UnrecoverableEntryException, NoSuchPaddingException, InvalidKeyException, IOException, InvalidAlgorithmParameterException;

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

        private static final CipherAlgorithm CIPHER_ALGORITHM_DEFAULT = CipherAlgorithm.RSA;
        private static final String BLOCK_MODE_DEFAULT__AES = CipherProperties.BLOCK_MODE_CBC;
        private static final String ENCRYPTION_PADDING_DEFAULT__AES = CipherProperties.ENCRYPTION_PADDING_PKCS7;
        private static final String BLOCK_MODE_DEFAULT__RSA = CipherProperties.BLOCK_MODE_ECB;
        private static final String ENCRYPTION_PADDING_DEFAULT__RSA = CipherProperties.ENCRYPTION_PADDING_RSA_PKCS1;

        protected String alias;
        protected CipherAlgorithm type;
        protected Context context;
        protected String blockMode;
        protected String encryptionPadding;

        public Builder(String alias) {
            this(alias, CIPHER_ALGORITHM_DEFAULT);
        }

        public Builder(String alias, CipherAlgorithm type) {
            this.alias = alias;
            this.type = type;
            switch (type) {
                case RSA:
                    blockMode = BLOCK_MODE_DEFAULT__RSA;
                    encryptionPadding = ENCRYPTION_PADDING_DEFAULT__RSA;
                    break;
                case AES:
                    blockMode = BLOCK_MODE_DEFAULT__AES;
                    encryptionPadding = ENCRYPTION_PADDING_DEFAULT__AES;
                    break;
                default:
                    throw new IllegalArgumentException("Unsupported Algorithm.");
            }
        }

        public Builder alias(String alias) {
            this.alias = alias;
            return this;
        }

        public Builder type(CipherAlgorithm type) {
            this.type = type;
            return this;
        }

        public Builder context(Context context) {
            this.context = context;
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

        public Cryptore build() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException, InvalidAlgorithmParameterException, IOException, NoSuchPaddingException {
            switch (type) {
                case AES:
                    if (Build.VERSION_CODES.M <= Build.VERSION.SDK_INT) {
                        return new AESCryptore(this);
                    } else {
                        throw new NoSuchAlgorithmException("AES is support only above API Lv23.");
                    }
                case RSA:
                    if (Build.VERSION_CODES.M <= Build.VERSION.SDK_INT) {
                        return new RSACryptoreM(this);
                    } else if (Build.VERSION_CODES.JELLY_BEAN_MR2 <= Build.VERSION.SDK_INT) {
                        if (context != null) {
                            return new RSACryptore(this);
                        } else {
                            throw new NullPointerException("Need \"Context\" for RSA on below API Lv22");
                        }
                    } else {
                        throw new NoSuchAlgorithmException("RSA is support only above API Lv18.");
                    }
                default:
                    throw new IllegalArgumentException("Unsupported Algorithm.");
            }
        }

    }

}
