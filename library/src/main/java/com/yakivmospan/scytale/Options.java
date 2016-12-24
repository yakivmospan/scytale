package com.yakivmospan.scytale;

public final class Options {

    public static final String ALGORITHM_AES = "AES";
    public static final String ALGORITHM_RSA = "RSA";
    public static final String ALGORITHM_SHA256_WITH_RSA_ENCRYPTION = "SHA256WithRSAEncryption";
    public static final String BLOCK_MODE_ECB = "ECB";
    public static final String BLOCK_MODE_CBC = "CBC";
    public static final String PADDING_PKCS_1 = "PKCS1Padding";
    public static final String PADDING_PKCS_7 = "PKCS7Padding";

    public static final String RSA_ECB_PKCS1PADDING = "RSA/ECB/PKCS1Padding";
    public static final String AES_CBC_PKCS7PADDING = "AES/CBC/PKCS7Padding";

    public static final int RSA_ECB_PKCS1PADDING_ENCRYPTION_BLOCK_SIZE_FOR_JELLY_BEAN = 245;
    public static final int RSA_ECB_PKCS1PADDING_DECRYPTION_BLOCK_SIZE_FOR_JELLY_BEAN = 256;

    public static final int RSA_ECB_PKCS1PADDING_1024_ENCRYPTION_BLOCK_SIZE = 117;
    public static final int RSA_ECB_PKCS1PADDING_1024_DECRYPTION_BLOCK_SIZE = 128;

    /**
     * For default created asymmetric keys
     */
    public static String TRANSFORMATION_ASYMMETRIC = RSA_ECB_PKCS1PADDING;

    /**
     * For default created symmetric keys
     */
    public static String TRANSFORMATION_SYMMETRIC = AES_CBC_PKCS7PADDING;

    /**
     * For default created asymmetric keys
     */
    public static int ENCRYPTION_BLOCK_SIZE;

    /**
     * For default created asymmetric keys
     */
    public static int DECRYPTION_BLOCK_SIZE;

    private Options() {
    }

    static {
        if (Utils.isJellyBean()) {
            ENCRYPTION_BLOCK_SIZE = RSA_ECB_PKCS1PADDING_ENCRYPTION_BLOCK_SIZE_FOR_JELLY_BEAN;
            DECRYPTION_BLOCK_SIZE = RSA_ECB_PKCS1PADDING_DECRYPTION_BLOCK_SIZE_FOR_JELLY_BEAN;
        } else {
            ENCRYPTION_BLOCK_SIZE = RSA_ECB_PKCS1PADDING_1024_ENCRYPTION_BLOCK_SIZE;
            DECRYPTION_BLOCK_SIZE = RSA_ECB_PKCS1PADDING_1024_DECRYPTION_BLOCK_SIZE;
        }
    }
}
