package com.kazakago.cryptore

/**
 * Block Mode, copied from Android Framework API Level 23.
 *
 * Created by tamura_k on 2016/05/25.
 */
enum class BlockMode(val rawValue: String) {

    /**
     * Electronic Codebook (ECB) block mode.
     */
    ECB("ECB"),
    /**
     * Cipher Block Chaining (CBC) block mode.
     */
    CBC("CBC"),
    /**
     * Counter (CTR) block mode.
     */
    CTR("CTR"),
    /**
     * Galois/Counter Mode (GCM) block mode.
     */
    GCM("GCM"),

}
