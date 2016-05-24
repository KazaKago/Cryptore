package com.ignis.ciphermanager;

import android.annotation.TargetApi;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;

/**
 * RSA CipherManager for above Android M.
 * <p/>
 * Created by tamura_k on 2016/04/22.
 */
@TargetApi(Build.VERSION_CODES.M)
public class CipherRSAManagerM implements CipherManager {

    private Cipher cipher;
    private byte[] cipherIV;
    protected String blockMode;
    protected String encryptionPadding;
    private String alias;
    private KeyStore keyStore;

    @TargetApi(Build.VERSION_CODES.M)
    public CipherRSAManagerM(Builder builder) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, NoSuchProviderException, InvalidAlgorithmParameterException, NoSuchPaddingException {
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
    public void initCipher() throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException {
        cipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_RSA + "/" + blockMode + "/" + encryptionPadding);
    }

    @Override
    public String encryptString(String plainText) throws KeyStoreException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IOException, NoSuchProviderException, InvalidAlgorithmParameterException {
        PublicKey publicKey = keyStore.getCertificate(alias).getPublicKey();

        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        cipherIV = cipher.getIV();

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, cipher);
        cipherOutputStream.write(plainText.getBytes("UTF-8"));
        cipherOutputStream.close();

        byte[] bytes = outputStream.toByteArray();
        return Base64.encodeToString(bytes, Base64.DEFAULT);
    }

    @Override
    public String decryptString(String encryptedText) throws KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, UnrecoverableKeyException, NoSuchPaddingException, InvalidKeyException, IOException, InvalidAlgorithmParameterException {
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, null);

        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        cipherIV = cipher.getIV();

        CipherInputStream cipherInputStream = new CipherInputStream(new ByteArrayInputStream(Base64.decode(encryptedText, Base64.DEFAULT)), cipher);

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        int b;
        while ((b = cipherInputStream.read()) != -1) {
            outputStream.write(b);
        }
        outputStream.close();
        return outputStream.toString("UTF-8");
    }

    @Override
    public void createNewKey() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchProviderException, KeyStoreException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");
        generator.initialize(new KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(blockMode)
                .setEncryptionPaddings(encryptionPadding)
                .build());
        generator.generateKeyPair();
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
