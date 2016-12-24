package com.yakivmospan.scytale;

import android.security.KeyPairGeneratorSpec;

import java.math.BigInteger;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

public final class KeyProps {
    String mAlias;
    char[] mPassword;
    String mKeyType;
    int mKeySize;

    String mBlockModes;
    String mEncryptionPaddings;

    String mSignatureAlgorithm;
    BigInteger mSerialNumber;
    X500Principal mSubject;
    Date mStartDate;
    Date mEndDate;

    public static final class Builder {
        private KeyProps mProps = new KeyProps();

        /**
         * Required for Symmetric and Asymmetric key
         */
        public Builder setAlias(String alias) {
            mProps.mAlias = alias;
            return this;
        }

        /**
         * Required for Symmetric and Asymmetric key
         */
        public Builder setKeyType(String keyType) {
            mProps.mKeyType = keyType;
            return this;
        }

        /**
         * Required for Symmetric using API < 23 and Asymmetric key using API < 18.
         *
         * @param password used for additional key secure in Default KeyStore.
         */
        public Builder setPassword(char[] password) {
            mProps.mPassword = password;
            return this;
        }

        /**
         * Required for Symmetric using API < 23 and Asymmetric key using API < 18. Is ignored in 18 API for Asymmetric
         * keys as there is no possibility to specify it for {@link KeyPairGeneratorSpec}
         */
        public Builder setKeySize(int keySize) {
            mProps.mKeySize = keySize;
            return this;
        }

        /**
         * Required for Asymmetric key.
         */
        public Builder setSerialNumber(BigInteger serialNumber) {
            mProps.mSerialNumber = serialNumber;
            return this;
        }

        /**
         * Required for Asymmetric key.
         * <p/>
         * Example: final X500Principal subject = new X500Principal("CN=" + alias + " CA Certificate");
         */
        public Builder setSubject(X500Principal subject) {
            mProps.mSubject = subject;
            return this;
        }

        /**
         * Required for Asymmetric key.
         */
        public Builder setStartDate(Date startDate) {
            mProps.mStartDate = startDate;
            return this;
        }

        /**
         * Required for Asymmetric key.
         */
        public Builder setEndDate(Date endDate) {
            mProps.mEndDate = endDate;
            return this;
        }

        /**
         * Required for Symmetric and Asymmetric keys using API >= 23.
         */
        public Builder setBlockModes(String blockModes) {
            mProps.mBlockModes = blockModes;
            return this;
        }

        /**
         * Required for Symmetric and Asymmetric keys using API >= 23.
         */
        public Builder setEncryptionPaddings(String encryptionPaddings) {
            mProps.mEncryptionPaddings = encryptionPaddings;
            return this;
        }

        /**
         * Required for Asymmetric key using API < 18.
         */
        public Builder setSignatureAlgorithm(String signatureAlgorithm) {
            mProps.mSignatureAlgorithm = signatureAlgorithm;
            return this;
        }

        public KeyProps build() {
            return mProps;
        }
    }
}
