package com.kazakago.cryptore.samplekotlin

import android.os.Bundle
import android.preference.PreferenceManager
import android.support.design.widget.TextInputLayout
import android.support.v7.app.AppCompatActivity
import android.util.Base64
import android.widget.Button
import android.widget.Toast
import com.kazakago.cryptore.CipherAlgorithm
import com.kazakago.cryptore.Cryptore

class MainActivity : AppCompatActivity() {

    companion object {
        private val ALIAS_RSA = "CIPHER_RSA"
        private val ALIAS_AES = "CIPHER_AES"
    }

    private val originalInput by lazy { findViewById(R.id.input_original) as TextInputLayout }
    private val encryptedInput by lazy { findViewById(R.id.input_encrypted) as TextInputLayout }
    private val decryptedInput by lazy { findViewById(R.id.input_decrypted) as TextInputLayout }
    private val cryptoreRSA: Cryptore by lazy {
        val builder = Cryptore.Builder(alias = ALIAS_RSA, type = CipherAlgorithm.RSA)
        builder.context = this //Need Only RSA on below API Lv22.
//        builder.blockMode = BlockMode.ECB //If Needed.
//        builder.encryptionPadding = EncryptionPadding.RSA_PKCS1 //If Needed.
        builder.build()
    }
    private val cryptoreAES: Cryptore by lazy {
        val builder = Cryptore.Builder(alias = ALIAS_AES, type = CipherAlgorithm.AES)
//        builder.blockMode = BlockMode.CBC //If Needed.
//        builder.encryptionPadding = EncryptionPadding.PKCS7 //If Needed.
        builder.build()
    }
    private var cipherIV: ByteArray?
        get() {
            val preferences = PreferenceManager.getDefaultSharedPreferences(this)
            preferences.getString("cipher_iv", null)?.let {
                return Base64.decode(it, Base64.DEFAULT)
            }
            return null
        }
        set(value) {
            val preferences = PreferenceManager.getDefaultSharedPreferences(this)
            val editor = preferences.edit()
            editor.putString("cipher_iv", Base64.encodeToString(value, Base64.DEFAULT))
            editor.apply()
        }


    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val encryptRSAButton = findViewById(R.id.button_encrypt_rsa) as Button
        encryptRSAButton.setOnClickListener {
            val encryptedStr = encryptRSA(plainStr = originalInput.editText?.text.toString())
            encryptedInput.editText?.setText(encryptedStr)
        }

        val encryptAESButton = findViewById(R.id.button_encrypt_aes) as Button
        encryptAESButton.setOnClickListener {
            val encryptedStr = encryptAES(plainStr = originalInput.editText?.text.toString())
            encryptedInput.editText?.setText(encryptedStr)
        }

        val decryptRSAButton = findViewById(R.id.button_decrypt_rsa) as Button
        decryptRSAButton.setOnClickListener {
            val decryptedStr = decryptRSA(encryptedStr = encryptedInput.editText?.text.toString())
            decryptedInput.editText?.setText(decryptedStr)
        }

        val decryptAESButton = findViewById(R.id.button_decrypt_aes) as Button
        decryptAESButton.setOnClickListener {
            val decryptedStr = decryptAES(encryptedStr = encryptedInput.editText?.text.toString())
            decryptedInput.editText?.setText(decryptedStr)
        }
    }

    private fun encryptRSA(plainStr: String): String {
        try {
            val plainByte = plainStr.toByteArray()
            val result = cryptoreRSA.encrypt(plainByte = plainByte)
            return Base64.encodeToString(result.bytes, Base64.DEFAULT)
        } catch (e: Exception) {
            e.printStackTrace()
            Toast.makeText(this, e.localizedMessage, Toast.LENGTH_LONG).show()
        }
        return ""
    }

    private fun decryptRSA(encryptedStr: String): String {
        try {
            val encryptedByte = Base64.decode(encryptedStr, Base64.DEFAULT)
            val result = cryptoreRSA.decrypt(encryptedByte = encryptedByte)
            return String(result.bytes!!)
        } catch (e: Exception) {
            e.printStackTrace()
            Toast.makeText(this, e.localizedMessage, Toast.LENGTH_LONG).show()
        }
        return ""
    }

    private fun encryptAES(plainStr: String): String {
        try {
            val plainByte = plainStr.toByteArray()
            val result = cryptoreAES.encrypt(plainByte = plainByte)
            cipherIV = result.cipherIV
            return Base64.encodeToString(result.bytes, Base64.DEFAULT)
        } catch (e: Exception) {
            e.printStackTrace()
            Toast.makeText(this, e.localizedMessage, Toast.LENGTH_LONG).show()
        }
        return ""
    }

    private fun decryptAES(encryptedStr: String): String {
        try {
            val encryptedByte = Base64.decode(encryptedStr, Base64.DEFAULT)
            val result = cryptoreAES.decrypt(encryptedByte = encryptedByte, cipherIV = cipherIV)
            return String(result.bytes!!)
        } catch (e: Exception) {
            e.printStackTrace()
            Toast.makeText(this, e.localizedMessage, Toast.LENGTH_LONG).show()
        }
        return ""
    }

}
