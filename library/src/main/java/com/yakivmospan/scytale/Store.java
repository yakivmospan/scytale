package com.yakivmospan.scytale;

import android.annotation.TargetApi;
import android.content.Context;
import android.os.Build;
import android.security.KeyPairGeneratorSpec;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.annotation.NonNull;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Calendar;
import java.util.Date;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.security.auth.x500.X500Principal;

import static java.security.KeyStore.getDefaultType;
import static java.security.KeyStore.getInstance;

/**
 * API to create, save and get keys
 */
public class Store extends ErrorHandler {

    private static final String PROVIDER_BC = "BC";
    private static final String PROVIDER_ANDROID_KEY_STORE = "AndroidKeyStore";
    private static final String DEFAULT_KEYSTORE_NAME = "keystore";
    private static final char[] DEFAULT_KEYSTORE_PASSWORD = BuildConfig.APPLICATION_ID.toCharArray();

    private String mKeystoreName = DEFAULT_KEYSTORE_NAME;
    private char[] mKeystorePassword = DEFAULT_KEYSTORE_PASSWORD;
    private final File mKeystoreFile;

    private final Context mContext;

    /**
     * Creates a store with default name and password. Name is "keystore" and password is application id
     *
     * @param context used to get local files dir of application
     */
    public Store(@NonNull Context context) {
        mContext = context;
        mKeystoreFile = new File(mContext.getFilesDir(), mKeystoreName);
    }

    /**
     * Creates a store with provided name and password.
     *
     * @param context used to get local files dir of application
     */
    public Store(@NonNull Context context, @NonNull String name, char[] password) {
        mContext = context;
        mKeystoreName = name;
        mKeystorePassword = password;
        mKeystoreFile = new File(mContext.getFilesDir(), mKeystoreName);
    }

    /**
     * Create and saves RSA 1024 Private key with given alias and password. Use generateAsymmetricKey(@NonNull
     * KeyProps keyProps) to customize key properties
     * <p/>
     * Saves key to KeyStore. Uses keystore with default type located in application cache on device if API < 18.
     * Uses AndroidKeyStore if API is >= 18.
     *
     * @return KeyPair or null if any error occurs
     */
    public KeyPair generateAsymmetricKey(@NonNull String alias, char[] password) {
        final Calendar start = Calendar.getInstance();
        final Calendar end = Calendar.getInstance();
        end.add(Calendar.YEAR, 20);

        KeyProps keyProps = new KeyProps.Builder()
                .setAlias(alias)
                .setPassword(password)
                .setKeySize(1024)
                .setKeyType(Options.ALGORITHM_RSA)
                .setSerialNumber(BigInteger.ONE)
                .setSubject(new X500Principal("CN=" + alias + " CA Certificate"))
                .setStartDate(start.getTime())
                .setEndDate(end.getTime())
                .setBlockModes(Options.BLOCK_MODE_ECB)
                .setEncryptionPaddings(Options.PADDING_PKCS_1)
                .setSignatureAlgorithm(Options.ALGORITHM_SHA256_WITH_RSA_ENCRYPTION)
                .build();

        return generateAsymmetricKey(keyProps);
    }

    /**
     * Create and saves Private key specified in KeyProps with self signed x509 Certificate.
     * <p/>
     * Saves key to KeyStore. Uses keystore with default type located in application cache on device if API < 18.
     * Uses AndroidKeyStore if API is >= 18.
     *
     * @return KeyPair or null if any error occurs
     */
    public KeyPair generateAsymmetricKey(@NonNull KeyProps keyProps) {
        KeyPair result = null;
        if (Utils.lowerThenJellyBean()) {
            result = generateDefaultAsymmetricKey(keyProps);
        } else if (Utils.lowerThenMarshmallow()) {
            result = generateAndroidJellyAsymmetricKey(keyProps);
        } else {
            result = generateAndroidMAsymmetricKey(keyProps);
        }
        return result;
    }

    /**
     * Create and saves 256 AES SecretKey key using provided alias and password.
     * <p/>
     * Saves key to KeyStore. Uses keystore with default type located in application cache on device if API < 23.
     * Uses AndroidKeyStore if API is >= 23.
     *
     * @return KeyPair or null if any error occurs
     */
    public SecretKey generateSymmetricKey(@NonNull String alias, char[] password) {
        KeyProps keyProps = new KeyProps.Builder()
                .setAlias(alias)
                .setPassword(password)
                .setKeySize(256)
                .setKeyType(Options.ALGORITHM_AES)
                .setBlockModes(Options.BLOCK_MODE_CBC)
                .setEncryptionPaddings(Options.PADDING_PKCS_7)
                .build();
        return generateSymmetricKey(keyProps);
    }

    /**
     * Create and saves SecretKey key specified in KeyProps.
     * <p/>
     * Saves key to KeyStore. Uses keystore with default type located in application cache on device if API < 23.
     * Uses AndroidKeyStore if API is >= 23.
     *
     * @return KeyPair or null if any error occurs
     */
    public SecretKey generateSymmetricKey(@NonNull KeyProps keyProps) {
        SecretKey result = null;
        if (Utils.lowerThenMarshmallow()) {
            result = generateDefaultSymmetricKey(keyProps);
        } else {
            result = generateAndroidSymmetricKey(keyProps);
        }
        return result;
    }

    /**
     * @return KeyPair or null if any error occurs
     */
    public KeyPair getAsymmetricKey(@NonNull String alias, char[] password) {
        KeyPair result = null;
        if (Utils.lowerThenJellyBean()) {
            result = getAsymmetricKeyFromDefaultKeyStore(alias, password);
        } else {
            result = getAsymmetricKeyFromAndroidKeyStore(alias);
        }
        return result;
    }

    /**
     * @return SecretKey or null if any error occurs
     */
    public SecretKey getSymmetricKey(@NonNull String alias, char[] password) {
        SecretKey result = null;
        if (Utils.lowerThenMarshmallow()) {
            result = getSymmetricKeyFromDefaultKeyStore(alias, password);
        } else {
            result = getSymmetricKeyFromAndroidtKeyStore(alias);
        }
        return result;
    }

    /**
     * @return true if key with given alias is in keystore
     */
    public boolean hasKey(@NonNull String alias) {
        boolean result = false;
        try {
            KeyStore keyStore;
            if (Utils.lowerThenJellyBean()) {
                keyStore = createDefaultKeyStore();
                result = isKeyEntry(alias, keyStore);
            } else if (Utils.lowerThenMarshmallow()) {
                keyStore = createAndroidKeystore();
                result = isKeyEntry(alias, keyStore);
                if (!result) {
                    // SecretKey's are stored in default keystore up to 23 API
                    keyStore = createDefaultKeyStore();
                    result = isKeyEntry(alias, keyStore);
                }
            } else {
                keyStore = createAndroidKeystore();
                result = isKeyEntry(alias, keyStore);
            }

        } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException e) {
            onException(e);
        }

        return result;
    }

    /**
     * Deletes key with given alias
     */
    public void deleteKey(@NonNull String alias) {
        try {
            KeyStore keyStore;
            if (Utils.lowerThenJellyBean()) {
                keyStore = createDefaultKeyStore();
                deleteEntryFromDefaultKeystore(alias, keyStore);
            } else if (Utils.lowerThenMarshmallow()) {
                keyStore = createAndroidKeystore();
                if (isKeyEntry(alias, keyStore)) {
                    deleteEntryFromAndroidKeystore(alias, keyStore);
                } else {
                    keyStore = createDefaultKeyStore();
                    if (isKeyEntry(alias, keyStore)) {
                        deleteEntryFromDefaultKeystore(alias, keyStore);
                    }
                }
            } else {
                keyStore = createAndroidKeystore();
                deleteEntryFromAndroidKeystore(alias, keyStore);
            }
        } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException e) {
            onException(e);
        }
    }

    private boolean isKeyEntry(@NonNull String alias, KeyStore keyStore) throws KeyStoreException {
        return keyStore != null && keyStore.isKeyEntry(alias);
    }

    private void deleteEntryFromDefaultKeystore(@NonNull String alias, KeyStore keyStore)
            throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        if (keyStore != null) {
            keyStore.deleteEntry(alias);
            keyStore.store(new FileOutputStream(mKeystoreFile), mKeystorePassword);
        }
    }

    private void deleteEntryFromAndroidKeystore(@NonNull String alias, KeyStore keyStore) throws KeyStoreException {
        if (keyStore != null) {
            keyStore.deleteEntry(alias);
        }
    }

    private KeyPair generateDefaultAsymmetricKey(KeyProps keyProps) {
        try {
            KeyPair keyPair = createAsymmetricKey(keyProps);
            PrivateKey key = keyPair.getPrivate();
            X509Certificate certificate = keyToCertificateReflection(keyPair, keyProps);
            KeyStore keyStore = createDefaultKeyStore();

            keyStore.setKeyEntry(keyProps.mAlias, key, keyProps.mPassword, new Certificate[]{certificate});
            keyStore.store(new FileOutputStream(mKeystoreFile), mKeystorePassword);
            return keyPair;
        } catch (NoSuchAlgorithmException | CertificateException | KeyStoreException | IOException | UnsupportedOperationException e) {
            onException(e);
        } catch (NoSuchMethodException e) {
            onException(e);
        } catch (InvocationTargetException e) {
            onException(e);
        } catch (InstantiationException e) {
            onException(e);
        } catch (IllegalAccessException e) {
            onException(e);
        }
        return null;
    }

    @TargetApi(Build.VERSION_CODES.JELLY_BEAN_MR2)
    private KeyPair generateAndroidJellyAsymmetricKey(KeyProps keyProps) {
        try {
            KeyPairGeneratorSpec keySpec = keyPropsToKeyPairGeneratorSpec(keyProps);
            return generateAndroidAsymmetricKey(keyProps, keySpec);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            onException(e);
        }
        return null;
    }

    @TargetApi(Build.VERSION_CODES.M)
    private KeyPair generateAndroidMAsymmetricKey(KeyProps keyProps) {
        try {
            KeyGenParameterSpec keySpec = keyPropsToKeyGenParameterASpec(keyProps);
            return generateAndroidAsymmetricKey(keyProps, keySpec);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            onException(e);
        }
        return null;
    }

    private KeyPair generateAndroidAsymmetricKey(KeyProps keyProps, AlgorithmParameterSpec keySpec)
            throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        String provider = PROVIDER_ANDROID_KEY_STORE;
        KeyPairGenerator generator = KeyPairGenerator.getInstance(keyProps.mKeyType, provider);
        generator.initialize(keySpec);
        return generator.generateKeyPair();
    }

    private KeyPair createAsymmetricKey(KeyProps keyProps) throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(keyProps.mKeyType);
        generator.initialize(keyProps.mKeySize);
        return generator.generateKeyPair();
    }

    private SecretKey generateDefaultSymmetricKey(KeyProps keyProps) {
        try {
            SecretKey key = createSymmetricKey(keyProps);
            KeyStore.SecretKeyEntry keyEntry = new KeyStore.SecretKeyEntry(key);
            KeyStore keyStore = createDefaultKeyStore();

            keyStore.setEntry(keyProps.mAlias, keyEntry, new KeyStore.PasswordProtection(keyProps.mPassword));
            keyStore.store(new FileOutputStream(mKeystoreFile), mKeystorePassword);
            return key;
        } catch (NoSuchAlgorithmException | CertificateException | KeyStoreException | IOException e) {
            onException(e);
        }
        return null;
    }

    @TargetApi(Build.VERSION_CODES.M)
    private SecretKey generateAndroidSymmetricKey(KeyProps keyProps) {
        try {
            String provider = PROVIDER_ANDROID_KEY_STORE;
            KeyGenerator keyGenerator = KeyGenerator.getInstance(keyProps.mKeyType, provider);
            KeyGenParameterSpec keySpec = keyPropsToKeyGenParameterSSpec(keyProps);
            keyGenerator.init(keySpec);
            return keyGenerator.generateKey();
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            onException(e);
        }
        return null;
    }

    /**
     * Generating X509Certificate using private com.android.org.bouncycastle.x509.X509V3CertificateGenerator class.
     * If it is not found, tries to use Google did copied http://www.bouncycastle.org/ but made it private. To not
     * include additional library Im using reflection here. Tested on API level 16, 17
     */
    private X509Certificate keyToCertificateReflection(KeyPair keyPair, KeyProps keyProps)
            throws UnsupportedOperationException, IllegalAccessException, InstantiationException,
            NoSuchMethodException,
            InvocationTargetException {

        Class generatorClass = null;
        try {
            generatorClass = Class.forName("com.android.org.bouncycastle.x509.X509V3CertificateGenerator");
        } catch (ClassNotFoundException e) {
            // if there is no android default implementation of X509V3CertificateGenerator try to find it from library
            try {
                generatorClass = Class.forName("org.bouncycastle.x509.X509V3CertificateGenerator");
            } catch (ClassNotFoundException e1) {
                throw new UnsupportedOperationException(
                        "You need to include  http://www.bouncycastle.org/ library to generate KeyPair on "
                                + Utils.VERSION
                                + " API version. You can do this via gradle using command 'compile 'org.bouncycastle:bcprov-jdk15on:1.54'");
            }
        }
        return keyToCertificateReflection(generatorClass, keyPair, keyProps);
    }

    /**
     * Generating X509Certificate using private com.android.org.bouncycastle.x509.X509V3CertificateGenerator class.
     * Google did copied http://www.bouncycastle.org/ but made it private. To not include additional library Im
     * using reflection here. Tested on API level 16, 17
     */
    private X509Certificate keyToCertificateReflection(Class generatorClass, KeyPair keyPair, KeyProps keyProps)
            throws IllegalAccessException, InstantiationException, NoSuchMethodException,
            InvocationTargetException {
        Object generator = generatorClass.newInstance();

        Method method = generator.getClass().getMethod("setPublicKey", PublicKey.class);
        method.invoke(generator, keyPair.getPublic());

        method = generator.getClass().getMethod("setSerialNumber", BigInteger.class);
        method.invoke(generator, keyProps.mSerialNumber);

        method = generator.getClass().getMethod("setSubjectDN", X500Principal.class);
        method.invoke(generator, keyProps.mSubject);

        method = generator.getClass().getMethod("setIssuerDN", X500Principal.class);
        method.invoke(generator, keyProps.mSubject);

        method = generator.getClass().getMethod("setNotBefore", Date.class);
        method.invoke(generator, keyProps.mStartDate);

        method = generator.getClass().getMethod("setNotAfter", Date.class);
        method.invoke(generator, keyProps.mEndDate);

        method = generator.getClass().getMethod("setSignatureAlgorithm", String.class);
        method.invoke(generator, keyProps.mSignatureAlgorithm);

        method = generator.getClass().getMethod("generate", PrivateKey.class, String.class);
        return (X509Certificate) method.invoke(generator, keyPair.getPrivate(), PROVIDER_BC);
    }

    @TargetApi(Build.VERSION_CODES.KITKAT)
    private KeyPairGeneratorSpec keyPropsToKeyPairGeneratorSpec(KeyProps keyProps) throws NoSuchAlgorithmException {
        KeyPairGeneratorSpec.Builder builder = new KeyPairGeneratorSpec.Builder(mContext)
                .setAlias(keyProps.mAlias)
                .setSerialNumber(keyProps.mSerialNumber)
                .setSubject(keyProps.mSubject)
                .setStartDate(keyProps.mStartDate)
                .setEndDate(keyProps.mEndDate);

        if (Utils.biggerThenJellyBean()) {
            builder.setKeySize(keyProps.mKeySize);
        }

        return builder.build();
    }

    @TargetApi(Build.VERSION_CODES.M)
    private KeyGenParameterSpec keyPropsToKeyGenParameterASpec(KeyProps keyProps) throws NoSuchAlgorithmException {
        int purposes = KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT;
        return new KeyGenParameterSpec.Builder(keyProps.mAlias, purposes)
                .setKeySize(keyProps.mKeySize)
                .setCertificateSerialNumber(keyProps.mSerialNumber)
                .setCertificateSubject(keyProps.mSubject)
                .setCertificateNotBefore(keyProps.mStartDate)
                .setCertificateNotAfter(keyProps.mEndDate)
                .setBlockModes(keyProps.mBlockModes)
                .setEncryptionPaddings(keyProps.mEncryptionPaddings)
                .build();
    }

    @TargetApi(Build.VERSION_CODES.M)
    private KeyGenParameterSpec keyPropsToKeyGenParameterSSpec(KeyProps keyProps) throws NoSuchAlgorithmException {
        int purposes = KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT;
        return new KeyGenParameterSpec.Builder(keyProps.mAlias, purposes)
                .setKeySize(keyProps.mKeySize)
                .setBlockModes(keyProps.mBlockModes)
                .setEncryptionPaddings(keyProps.mEncryptionPaddings)
                .build();
    }

    private SecretKey createSymmetricKey(KeyProps keyProps) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(keyProps.mKeyType);
        keyGenerator.init(keyProps.mKeySize);
        SecretKey key = keyGenerator.generateKey();
        return key;
    }

    private KeyPair getAsymmetricKeyFromDefaultKeyStore(@NonNull String alias, char[] password) {
        KeyPair result = null;
        try {
            // get asymmetric key
            KeyStore keyStore = createDefaultKeyStore();
            KeyStore.PasswordProtection protection = new KeyStore.PasswordProtection(password);
            KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias, protection);
            if (entry != null) {
                result = new KeyPair(entry.getCertificate().getPublicKey(), entry.getPrivateKey());
            }
        } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException | UnrecoverableEntryException e) {
            onException(e);
        }
        return result;
    }

    private KeyPair getAsymmetricKeyFromAndroidKeyStore(@NonNull String alias) {
        KeyPair result = null;
        try {
            KeyStore keyStore = createAndroidKeystore();
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, null);
            if (privateKey != null) {
                PublicKey publicKey = keyStore.getCertificate(alias).getPublicKey();
                result = new KeyPair(publicKey, privateKey);
            }
        } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException | UnrecoverableEntryException e) {
            onException(e);
        }
        return result;
    }

    private SecretKey getSymmetricKeyFromDefaultKeyStore(@NonNull String alias, char[] password) {
        SecretKey result = null;
        try {
            KeyStore keyStore = createDefaultKeyStore();
            result = (SecretKey) keyStore.getKey(alias, password);
        } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException | UnrecoverableEntryException e) {
            onException(e);
        }
        return result;
    }

    private SecretKey getSymmetricKeyFromAndroidtKeyStore(@NonNull String alias) {
        SecretKey result = null;
        try {
            KeyStore keyStore = createAndroidKeystore();
            result = (SecretKey) keyStore.getKey(alias, null);
        } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException | UnrecoverableEntryException e) {
            onException(e);
        }
        return result;
    }

    /**
     * Cache for default keystore
     */
    private KeyStore mDefaultKeyStore;

    private KeyStore createDefaultKeyStore()
            throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        if (mDefaultKeyStore == null) {
            String defaultType = getDefaultType();
            mDefaultKeyStore = getInstance(defaultType);
            if (!mKeystoreFile.exists()) {
                mDefaultKeyStore.load(null);
            } else {
                mDefaultKeyStore.load(new FileInputStream(mKeystoreFile), mKeystorePassword);
            }
        }
        return mDefaultKeyStore;
    }

    /**
     * Cache for android keystore
     */
    private KeyStore mAndroidKeyStore;

    private KeyStore createAndroidKeystore()
            throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        if (mAndroidKeyStore == null) {
            mAndroidKeyStore = KeyStore.getInstance(PROVIDER_ANDROID_KEY_STORE);
        }
        mAndroidKeyStore.load(null);
        return mAndroidKeyStore;
    }
}
