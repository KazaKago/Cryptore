package com.kazakago.cryptore.samplekotlin

import android.os.Bundle
import android.preference.PreferenceManager
import android.util.Base64
import android.widget.Button
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.textfield.TextInputLayout
import com.kazakago.cryptore.CipherAlgorithm
import com.kazakago.cryptore.Cryptore

class MainActivity : AppCompatActivity() {

    private enum class Alias(val value: String) {
        RSA("CIPHER_RSA"),
        AES("CIPHER_AES")
    }

    private val cryptoreRSA: Cryptore by lazy {
        val builder = Cryptore.Builder(alias = Alias.RSA.value, type = CipherAlgorithm.RSA)
        builder.context = this //Need Only RSA on below API Lv22.
//        builder.blockMode = BlockMode.ECB //If Needed.
//        builder.encryptionPadding = EncryptionPadding.RSA_PKCS1 //If Needed.
        builder.build()
    }
    private val cryptoreAES: Cryptore by lazy {
        val builder = Cryptore.Builder(alias = Alias.AES.value, type = CipherAlgorithm.AES)
//        builder.blockMode = BlockMode.CBC //If Needed.
//        builder.encryptionPadding = EncryptionPadding.PKCS7 //If Needed.
        builder.build()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val originalInput = findViewById<TextInputLayout>(R.id.input_original)
        val encryptedInput = findViewById<TextInputLayout>(R.id.input_encrypted)
        val decryptedInput = findViewById<TextInputLayout>(R.id.input_decrypted)

        val encryptRSAButton = findViewById<Button>(R.id.button_encrypt_rsa)
        encryptRSAButton.setOnClickListener {
            val encryptedStr = encryptRSA(plainStr = originalInput.editText?.text.toString())
            encryptedInput.editText?.setText(encryptedStr)
        }

        val encryptAESButton = findViewById<Button>(R.id.button_encrypt_aes)
        encryptAESButton.setOnClickListener {
            val encryptedStr = encryptAES(plainStr = originalInput.editText?.text.toString())
            encryptedInput.editText?.setText(encryptedStr)
        }

        val decryptRSAButton = findViewById<Button>(R.id.button_decrypt_rsa)
        decryptRSAButton.setOnClickListener {
            val decryptedStr = decryptRSA(encryptedStr = encryptedInput.editText?.text.toString())
            decryptedInput.editText?.setText(decryptedStr)
        }

        val decryptAESButton = findViewById<Button>(R.id.button_decrypt_aes)
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
            Toast.makeText(this, e.toString(), Toast.LENGTH_LONG).show()
        }
        return ""
    }

    private fun decryptRSA(encryptedStr: String): String {
        try {
            val encryptedByte = Base64.decode(encryptedStr, Base64.DEFAULT)
            val result = cryptoreRSA.decrypt(encryptedByte = encryptedByte)
            return String(result.bytes)
        } catch (e: Exception) {
            e.printStackTrace()
            Toast.makeText(this, e.toString(), Toast.LENGTH_LONG).show()
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
            Toast.makeText(this, e.toString(), Toast.LENGTH_LONG).show()
        }
        return ""
    }

    private fun decryptAES(encryptedStr: String): String {
        try {
            val encryptedByte = Base64.decode(encryptedStr, Base64.DEFAULT)
            val result = cryptoreAES.decrypt(encryptedByte = encryptedByte, cipherIV = cipherIV)
            return String(result.bytes)
        } catch (e: Exception) {
            e.printStackTrace()
            Toast.makeText(this, e.toString(), Toast.LENGTH_LONG).show()
        }
        return ""
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

}
