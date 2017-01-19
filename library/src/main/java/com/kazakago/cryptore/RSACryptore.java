package com.kazakago.cryptore;

import android.annotation.TargetApi;
import android.content.Context;
import android.os.Build;
import android.security.KeyPairGeneratorSpec;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
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
import java.util.Calendar;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.security.auth.x500.X500Principal;

/**
 * RSA Cryptore.
 * <p/>
 * Created by tamura_k on 2016/04/22.
 */
@TargetApi(Build.VERSION_CODES.JELLY_BEAN_MR2)
public class RSACryptore implements Cryptore {

    private Context context;
    private Cipher cipher;
    private byte[] cipherIV;
    protected String blockMode;
    protected String encryptionPadding;
    private String alias;
    private KeyStore keyStore;

    @TargetApi(Build.VERSION_CODES.JELLY_BEAN_MR2)
    public RSACryptore(Builder builder) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException, InvalidAlgorithmParameterException, IOException, NoSuchPaddingException {
        this.context = builder.context;
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
        cipher = Cipher.getInstance("RSA/" + blockMode + "/" + encryptionPadding);
    }

    @Override
    public byte[] encrypt(byte[] plainByte) throws KeyStoreException, InvalidKeyException, IOException {
        PublicKey publicKey = keyStore.getCertificate(alias).getPublicKey();

        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        cipherIV = cipher.getIV();

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, cipher);
        cipherOutputStream.write(plainByte);
        cipherOutputStream.close();

        return outputStream.toByteArray();
    }

    @Override
    public byte[] decrypt(byte[] encryptedByte) throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, InvalidKeyException, IOException {
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, null);

        cipher.init(Cipher.DECRYPT_MODE, privateKey);
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
        Calendar start = Calendar.getInstance();
        Calendar end = Calendar.getInstance();
        end.add(Calendar.YEAR, 100);
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "AndroidKeyStore");
        generator.initialize(new KeyPairGeneratorSpec.Builder(context)
                .setAlias(alias)
                .setSubject(new X500Principal("CN=CipherManager"))
                .setSerialNumber(BigInteger.ONE)
                .setStartDate(start.getTime())
                .setEndDate(end.getTime())
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
