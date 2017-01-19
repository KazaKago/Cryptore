package com.kazakago.cryptore;

import android.annotation.TargetApi;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

/**
 * AES Cryptore.
 * <p/>
 * Created by tamura_k on 2016/04/22.
 */
@TargetApi(Build.VERSION_CODES.M)
public class AESCryptore implements Cryptore {

    private Cipher cipher;
    private byte[] cipherIV;
    protected String blockMode;
    protected String encryptionPadding;
    private String alias;
    private KeyStore keyStore;

    @TargetApi(Build.VERSION_CODES.M)
    public AESCryptore(Builder builder) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException, InvalidAlgorithmParameterException, IOException, NoSuchPaddingException {
        this.alias = builder.alias;
        this.blockMode = builder.blockMode;
        this.encryptionPadding = builder.encryptionPadding;
        initKeyStore();
        initCipher();
    }

    @Override
    public void initKeyStore() throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, NoSuchProviderException, InvalidAlgorithmParameterException {
        this.keyStore = KeyStore.getInstance("AndroidKeyStore");
        this.keyStore.load(null);
        if (!keyStore.containsAlias(alias)) createNewKey();
    }

    @Override
    public void initCipher() throws NoSuchPaddingException, NoSuchAlgorithmException {
        cipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/" + blockMode + "/" + encryptionPadding);
    }

    @Override
    public byte[] encrypt(byte[] plainByte) throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, InvalidKeyException, IOException {
        SecretKey secretKey = (SecretKey) keyStore.getKey(alias, null);

        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        cipherIV = cipher.getIV();

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, cipher);
        cipherOutputStream.write(plainByte);
        cipherOutputStream.close();

        return outputStream.toByteArray();
    }

    @Override
    public byte[] decrypt(byte[] encryptedByte) throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, InvalidAlgorithmParameterException, InvalidKeyException, IOException {
        SecretKey secretKey = (SecretKey) keyStore.getKey(alias, null);

        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(cipherIV));
        cipherIV = cipher.getIV();

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        CipherInputStream cipherInputStream = new CipherInputStream(new ByteArrayInputStream(encryptedByte), cipher);
        int b;
        while ((b = cipherInputStream.read()) != -1) {
            outputStream.write(b);
        }
        outputStream.close();

        return outputStream.toByteArray();
    }

    @Override
    public void createNewKey() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyGenerator generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        generator.init(new KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(blockMode)
                .setEncryptionPaddings(encryptionPadding)
                .build());
        generator.generateKey();
    }

    @Override
    public byte[] getCipherIV() {
        return cipherIV;
    }

    @Override
    public void setCipherIV(byte[] cipherIV) {
        this.cipherIV = cipherIV;
    }

}
