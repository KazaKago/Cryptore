package com.ignis.cipherapp;

import android.content.SharedPreferences;
import android.os.Bundle;
import android.preference.PreferenceManager;
import android.support.design.widget.TextInputLayout;
import android.support.v7.app.AppCompatActivity;
import android.util.Base64;
import android.view.View;
import android.widget.Button;
import android.widget.Toast;

import com.ignis.ciphermanager.AESCipherManager;
import com.ignis.ciphermanager.CipherAlgorithm;
import com.ignis.ciphermanager.CipherManager;

public class MainActivity extends AppCompatActivity {

    private static final String ALIAS = "CIPHER";

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

        Button encryptButton = (Button) findViewById(R.id.button_encrypt);
        encryptButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String encryptedStr = encrypt(originalInput.getEditText().getText().toString());
                encryptedInput.getEditText().setText(encryptedStr);
            }
        });

        Button decryptButton = (Button) findViewById(R.id.button_decrypt);
        decryptButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String decryptedStr = decrypt(encryptedInput.getEditText().getText().toString());
                decryptedInput.getEditText().setText(decryptedStr);
            }
        });
    }

    private CipherManager getCipherManager() throws Exception {
        CipherManager.Builder builder = new CipherManager.Builder();
        builder.type(CipherAlgorithm.RSA);
//        builder.blockMode(CipherProperties.BLOCK_MODE_ECB); //If Needed.
//        builder.encryptionPadding(CipherProperties.ENCRYPTION_PADDING_RSA_PKCS1); //If Needed.
        builder.context(this); //Need Only RSA on below API Lv22.
        builder.alias(ALIAS);
        return builder.build();
    }

    private String encrypt(String originalStr) {
        String encryptedStr = null;
        try {
            CipherManager cipherManager = getCipherManager();
            encryptedStr = cipherManager.encryptString(originalStr);
            if (cipherManager instanceof AESCipherManager) saveCipherIV(cipherManager.getCipherIV()); //Need Only AES.
        } catch (Exception e) {
            e.printStackTrace();
            Toast.makeText(MainActivity.this, e.getLocalizedMessage(), Toast.LENGTH_LONG).show();
        }
        return encryptedStr;
    }

    private String decrypt(String encryptedStr) {
        String decryptedStr = null;
        try {
            CipherManager cipherManager = getCipherManager();
            if (cipherManager instanceof AESCipherManager) cipherManager.setCipherIV(restoreCipherIV()); //Need Only AES.
            decryptedStr = cipherManager.decryptString(encryptedStr);
        } catch (Exception e) {
            e.printStackTrace();
            Toast.makeText(MainActivity.this, e.getLocalizedMessage(), Toast.LENGTH_LONG).show();
        }
        return decryptedStr;
    }

    private void saveCipherIV(byte[] cipherIV) {
        SharedPreferences preferences = PreferenceManager.getDefaultSharedPreferences(this);
        SharedPreferences.Editor editor = preferences.edit();
        editor.putString("cipher_iv", Base64.encodeToString(cipherIV, Base64.DEFAULT));
        editor.apply();
    }

    private byte[] restoreCipherIV() {
        SharedPreferences preferences = PreferenceManager.getDefaultSharedPreferences(this);
        String cipherIVStr = preferences.getString("cipher_iv", null);
        return (cipherIVStr != null) ? Base64.decode(cipherIVStr, Base64.DEFAULT) : null;
    }

}
