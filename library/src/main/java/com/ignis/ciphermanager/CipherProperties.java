package com.ignis.ciphermanager;

/**
 * Cipher Property, copied from Android Framework API Level 23.
 * <p/>
 * Created by tamura_k on 2016/05/25.
 */
public class CipherProperties {

    /**
     * Electronic Codebook (ECB) block mode.
     */
    public static final String BLOCK_MODE_ECB = "ECB";
    /**
     * Cipher Block Chaining (CBC) block mode.
     */
    public static final String BLOCK_MODE_CBC = "CBC";
    /**
     * Counter (CTR) block mode.
     */
    public static final String BLOCK_MODE_CTR = "CTR";
    /**
     * Galois/Counter Mode (GCM) block mode.
     */
    public static final String BLOCK_MODE_GCM = "GCM";

    /**
     * No encryption padding.
     */
    public static final String ENCRYPTION_PADDING_NONE = "NoPadding";
    /**
     * PKCS#7 encryption padding scheme.
     */
    public static final String ENCRYPTION_PADDING_PKCS7 = "PKCS7Padding";
    /**
     * RSA PKCS#1 v1.5 padding scheme for encryption.
     */
    public static final String ENCRYPTION_PADDING_RSA_PKCS1 = "PKCS1Padding";
    /**
     * RSA Optimal Asymmetric Encryption Padding (OAEP) scheme.
     */
    public static final String ENCRYPTION_PADDING_RSA_OAEP = "OAEPPadding";

}
