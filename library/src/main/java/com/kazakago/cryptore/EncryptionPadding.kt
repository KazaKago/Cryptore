package com.kazakago.cryptore

/**
 * Encryption Padding, copied from Android Framework API Level 23.
 *
 * Created by tamura_k on 2016/05/25.
 */
enum class EncryptionPadding(val rawValue: String) {

    /**
     * No encryption padding.
     */
    NONE("NoPadding"),
    /**
     * PKCS#7 encryption padding scheme.
     */
    PKCS7("PKCS7Padding"),
    /**
     * RSA PKCS#1 v1.5 padding scheme for encryption.
     */
    RSA_PKCS1("PKCS1Padding"),
    /**
     * RSA Optimal Asymmetric Encryption Padding (OAEP) scheme.
     */
    RSA_OAEP("OAEPPadding"),

}
