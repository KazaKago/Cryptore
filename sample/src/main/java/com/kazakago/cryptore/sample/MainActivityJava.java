package com.kazakago.cryptore.sample;

import android.content.SharedPreferences;
import android.os.Bundle;
import android.preference.PreferenceManager;
import android.support.design.widget.TextInputLayout;
import android.support.v7.app.AppCompatActivity;
import android.util.Base64;
import android.view.View;
import android.widget.Button;
import android.widget.Toast;

import com.kazakago.cryptore.CipherAlgorithm;
import com.kazakago.cryptore.Cryptore;
import com.kazakago.cryptore.DecryptResult;
import com.kazakago.cryptore.EncryptResult;
import com.kazakago.cryptore.R;

public class MainActivityJava extends AppCompatActivity {

    private static final String ALIAS_RSA = "CIPHER_RSA";
    private static final String ALIAS_AES = "CIPHER_AES";

    private TextInputLayout originalInput;
    private TextInputLayout encryptedInput;
    private TextInputLayout decryptedInput;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        originalInput = (TextInputLayout) findViewById(R.id.input_original);
        encryptedInput = (TextInputLayout) findViewById(R.id.input_encrypted);
        decryptedInput = (TextInputLayout) findViewById(R.id.input_decrypted);

        Button encryptRSAButton = (Button) findViewById(R.id.button_encrypt_rsa);
        encryptRSAButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String encryptedStr = encryptRSA(originalInput.getEditText().getText().toString());
                encryptedInput.getEditText().setText(encryptedStr);
            }
        });

        Button encryptAESButton = (Button) findViewById(R.id.button_encrypt_aes);
        encryptAESButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String encryptedStr = encryptAES(originalInput.getEditText().getText().toString());
                encryptedInput.getEditText().setText(encryptedStr);
            }
        });

        Button decryptRSAButton = (Button) findViewById(R.id.button_decrypt_rsa);
        decryptRSAButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String decryptedStr = decryptRSA(encryptedInput.getEditText().getText().toString());
                decryptedInput.getEditText().setText(decryptedStr);
            }
        });

        Button decryptAESButton = (Button) findViewById(R.id.button_decrypt_aes);
        decryptAESButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String decryptedStr = decryptAES(encryptedInput.getEditText().getText().toString());
                decryptedInput.getEditText().setText(decryptedStr);
            }
        });
    }

    private Cryptore getCryptoreRSA() throws Exception {
        Cryptore.Builder builder = new Cryptore.Builder(ALIAS_RSA, CipherAlgorithm.RSA);
        builder.setContext(this); //Need Only RSA on below API Lv22.
//        builder.setBlockMode(BlockMode.ECB); //If Needed.
//        builder.setEncryptionPadding(EncryptionPadding.RSA_PKCS1); //If Needed.
        return builder.build();
    }

    private Cryptore getCryptoreAES() throws Exception {
        Cryptore.Builder builder = new Cryptore.Builder(ALIAS_AES, CipherAlgorithm.AES);
//        builder.setBlockMode(BlockMode.CBC); //If Needed.
//        builder.setEncryptionPadding(EncryptionPadding.PKCS7); //If Needed.
        return builder.build();
    }

    private String encryptRSA(String plainStr) {
        try {
            byte[] plainByte = plainStr.getBytes();
            EncryptResult result = getCryptoreRSA().encrypt(plainByte);
            return Base64.encodeToString(result.getBytes(), Base64.DEFAULT);
        } catch (Exception e) {
            e.printStackTrace();
            Toast.makeText(this, e.getLocalizedMessage(), Toast.LENGTH_LONG).show();
        }
        return "";
    }

    private String decryptRSA(String encryptedStr) {
        try {
            byte[] encryptedByte = Base64.decode(encryptedStr, Base64.DEFAULT);
            DecryptResult result = getCryptoreRSA().decrypt(encryptedByte, null);
            return new String(result.getBytes());
        } catch (Exception e) {
            e.printStackTrace();
            Toast.makeText(this, e.getLocalizedMessage(), Toast.LENGTH_LONG).show();
        }
        return "";
    }

    private String encryptAES(String plainStr) {
        try {
            byte[] plainByte = plainStr.getBytes();
            EncryptResult result = getCryptoreAES().encrypt(plainByte);
            saveCipherIV(result.getCipherIV());
            return Base64.encodeToString(result.getBytes(), Base64.DEFAULT);
        } catch (Exception e) {
            e.printStackTrace();
            Toast.makeText(this, e.getLocalizedMessage(), Toast.LENGTH_LONG).show();
        }
        return "";
    }

    private String decryptAES(String encryptedStr) {
        try {
            byte[] encryptedByte = Base64.decode(encryptedStr, Base64.DEFAULT);
            byte[] cipherIV = loadCipherIV();
            DecryptResult result = getCryptoreAES().decrypt(encryptedByte, cipherIV);
            return new String(result.getBytes());
        } catch (Exception e) {
            e.printStackTrace();
            Toast.makeText(this, e.getLocalizedMessage(), Toast.LENGTH_LONG).show();
        }
        return "";
    }

    private void saveCipherIV(byte[] cipherIV) {
        SharedPreferences preferences = PreferenceManager.getDefaultSharedPreferences(this);
        SharedPreferences.Editor editor = preferences.edit();
        editor.putString("cipher_iv", Base64.encodeToString(cipherIV, Base64.DEFAULT));
        editor.apply();
    }

    private byte[] loadCipherIV() {
        SharedPreferences preferences = PreferenceManager.getDefaultSharedPreferences(this);
        String cipherIVStr = preferences.getString("cipher_iv", null);
        return (cipherIVStr != null) ? Base64.decode(cipherIVStr, Base64.DEFAULT) : null;
    }

}
