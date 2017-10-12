package com.kazakago.cryptore.samplejava;

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

public class MainActivity extends AppCompatActivity {

    private enum Alias {
        RSA("CIPHER_RSA"),
        AES("CIPHER_AES");

        String value;

        Alias(String value) {
            this.value = value;
        }
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        final TextInputLayout originalInput = findViewById(R.id.input_original);
        final TextInputLayout encryptedInput = findViewById(R.id.input_encrypted);
        final TextInputLayout decryptedInput = findViewById(R.id.input_decrypted);

        Button encryptRSAButton = findViewById(R.id.button_encrypt_rsa);
        encryptRSAButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String encryptedStr = encryptRSA(originalInput.getEditText().getText().toString());
                encryptedInput.getEditText().setText(encryptedStr);
            }
        });

        Button encryptAESButton = findViewById(R.id.button_encrypt_aes);
        encryptAESButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String encryptedStr = encryptAES(originalInput.getEditText().getText().toString());
                encryptedInput.getEditText().setText(encryptedStr);
            }
        });

        Button decryptRSAButton = findViewById(R.id.button_decrypt_rsa);
        decryptRSAButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String decryptedStr = decryptRSA(encryptedInput.getEditText().getText().toString());
                decryptedInput.getEditText().setText(decryptedStr);
            }
        });

        Button decryptAESButton = findViewById(R.id.button_decrypt_aes);
        decryptAESButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String decryptedStr = decryptAES(encryptedInput.getEditText().getText().toString());
                decryptedInput.getEditText().setText(decryptedStr);
            }
        });
    }

    private Cryptore getCryptoreRSA() throws Exception {
        Cryptore.Builder builder = new Cryptore.Builder(Alias.RSA.value, CipherAlgorithm.RSA);
        builder.setContext(this); //Need Only RSA on below API Lv22.
//        builder.setBlockMode(BlockMode.ECB); //If Needed.
//        builder.setEncryptionPadding(EncryptionPadding.RSA_PKCS1); //If Needed.
        return builder.build();
    }

    private Cryptore getCryptoreAES() throws Exception {
        Cryptore.Builder builder = new Cryptore.Builder(Alias.AES.value, CipherAlgorithm.AES);
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
