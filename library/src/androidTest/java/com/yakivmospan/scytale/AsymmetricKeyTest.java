package com.yakivmospan.scytale;

import org.hamcrest.Matchers;
import org.junit.Test;
import org.junit.runner.RunWith;

import android.os.Build;
import android.support.test.runner.AndroidJUnit4;

import java.math.BigInteger;
import java.security.KeyPair;
import java.util.Calendar;

import javax.security.auth.x500.X500Principal;

import static com.yakivmospan.scytale.Options.DECRYPTION_BLOCK_SIZE;
import static com.yakivmospan.scytale.Options.ENCRYPTION_BLOCK_SIZE;
import static com.yakivmospan.scytale.Options.TRANSFORMATION_ASYMMETRIC;
import static com.yakivmospan.scytale.Options.TRANSFORMATION_SYMMETRIC;
import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.core.IsNot.not;
import static org.junit.Assert.assertThat;

@RunWith(AndroidJUnit4.class)
public class AsymmetricKeyTest extends BaseContextTest implements KeyTest {

    @Test
    @Override
    public void generateDefaultKeyIsNotNull() {
        Store store = new Store(context, STORE_NAME, STORE_PASSWORD);
        KeyPair keyPair = store.generateAsymmetricKey(KEY_ALIAS_ASYMMETRIC, KEY_PASSWORD);
        assertThat(keyPair, is(notNullValue()));
        store.deleteKey(KEY_ALIAS_ASYMMETRIC);
    }

    @Test
    @Override
    public void generateKeyIsNotNull() {
        Store store = new Store(context, STORE_NAME, STORE_PASSWORD);

        final Calendar start = Calendar.getInstance();
        final Calendar end = Calendar.getInstance();
        end.add(Calendar.YEAR, 1);

        KeyPair keyPair = store.generateAsymmetricKey(new KeyProps.Builder()
                .setAlias(KEY_ALIAS_ASYMMETRIC)
                .setPassword(KEY_PASSWORD)
                .setKeySize(KEY_SIZE)
                .setKeyType("RSA")
                .setSerialNumber(BigInteger.ONE)
                .setSubject(new X500Principal("CN=" + KEY_ALIAS_ASYMMETRIC + " CA Certificate"))
                .setStartDate(start.getTime())
                .setEndDate(start.getTime())
                .setBlockModes("ECB")
                .setEncryptionPaddings("PKCS1Padding")
                .setSignatureAlgorithm("SHA256WithRSAEncryption")
                .build());

        assertThat(keyPair, is(notNullValue()));
        store.deleteKey(KEY_ALIAS_ASYMMETRIC);
    }

    @Test
    @Override
    public void generateKeyHasWrongType() {
        Store store = new Store(context, STORE_NAME, STORE_PASSWORD);

        final Calendar start = Calendar.getInstance();
        final Calendar end = Calendar.getInstance();
        end.add(Calendar.YEAR, 1);

        KeyPair keyPair = store.generateAsymmetricKey(new KeyProps.Builder()
                .setAlias(KEY_ALIAS_ASYMMETRIC)
                .setPassword(KEY_PASSWORD)
                .setKeySize(KEY_SIZE)
                .setKeyType("no-such-key-type")
                .setSerialNumber(BigInteger.ONE)
                .setSubject(new X500Principal("CN=" + KEY_ALIAS_ASYMMETRIC + " CA Certificate"))
                .setStartDate(start.getTime())
                .setEndDate(start.getTime())
                .setBlockModes("ECB")
                .setEncryptionPaddings("PKCS1Padding")
                .setSignatureAlgorithm("SHA256WithRSAEncryption")
                .build());

        assertThat(keyPair, is(nullValue()));
    }

    @Test
    @Override
    public void generateKeyHasNoBlockModes() {
        Store store = new Store(context, STORE_NAME, STORE_PASSWORD);

        final Calendar start = Calendar.getInstance();
        final Calendar end = Calendar.getInstance();
        end.add(Calendar.YEAR, 1);

        KeyPair keyPair = store.generateAsymmetricKey(new KeyProps.Builder()
                .setAlias(KEY_ALIAS_ASYMMETRIC)
                .setPassword(KEY_PASSWORD)
                .setKeySize(KEY_SIZE)
                .setKeyType("RSA")
                .setSerialNumber(BigInteger.ONE)
                .setSubject(new X500Principal("CN=" + KEY_ALIAS_ASYMMETRIC + " CA Certificate"))
                .setStartDate(start.getTime())
                .setEndDate(start.getTime())
                .setBlockModes("no-such-block-modes")
                .setEncryptionPaddings("PKCS1Padding")
                .setSignatureAlgorithm("SHA256WithRSAEncryption")
                .build());

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            assertThat(keyPair, is(notNullValue()));
            store.deleteKey(KEY_ALIAS_ASYMMETRIC);
        } else {
            assertThat(keyPair, is(nullValue()));
        }
    }

    @Test
    @Override
    public void generateKeyHasNoEncryptionPaddings() {
        Store store = new Store(context, STORE_NAME, STORE_PASSWORD);

        final Calendar start = Calendar.getInstance();
        final Calendar end = Calendar.getInstance();
        end.add(Calendar.YEAR, 1);

        KeyPair keyPair = store.generateAsymmetricKey(new KeyProps.Builder()
                .setAlias(KEY_ALIAS_ASYMMETRIC)
                .setPassword(KEY_PASSWORD)
                .setKeySize(KEY_SIZE)
                .setKeyType("RSA")
                .setSerialNumber(BigInteger.ONE)
                .setSubject(new X500Principal("CN=" + KEY_ALIAS_ASYMMETRIC + " CA Certificate"))
                .setStartDate(start.getTime())
                .setEndDate(start.getTime())
                .setBlockModes("ECB")
                .setEncryptionPaddings("no-such-encryption-paddings")
                .setSignatureAlgorithm("SHA256WithRSAEncryption")
                .build());

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            assertThat(keyPair, is(notNullValue()));
            store.deleteKey(KEY_ALIAS_ASYMMETRIC);
        } else {
            assertThat(keyPair, is(nullValue()));
        }
    }

    @Test
    @Override
    public void getKeyIsNotNull() {
        Store store = new Store(context, STORE_NAME, STORE_PASSWORD);
        store.generateAsymmetricKey(KEY_ALIAS_ASYMMETRIC, KEY_PASSWORD);
        KeyPair keyPair = store.getAsymmetricKey(KEY_ALIAS_ASYMMETRIC, KEY_PASSWORD);
        assertThat(keyPair, is(notNullValue()));

        store = new Store(context, STORE_NAME, STORE_PASSWORD);
        keyPair = store.getAsymmetricKey(KEY_ALIAS_ASYMMETRIC, KEY_PASSWORD);
        assertThat(keyPair, is(notNullValue()));

        store.deleteKey(KEY_ALIAS_ASYMMETRIC);
    }

    @Test
    @Override
    public void getKeyIsNull() {
        Store store = new Store(context, STORE_NAME, STORE_PASSWORD);
        KeyPair keyPair = store.getAsymmetricKey(KEY_ALIAS_ASYMMETRIC, KEY_PASSWORD);
        assertThat(keyPair, is(nullValue()));
    }

    @Test
    @Override
    public void hasKeyIsTrue() {
        Store store = new Store(context, STORE_NAME, STORE_PASSWORD);
        store.generateAsymmetricKey(KEY_ALIAS_ASYMMETRIC, KEY_PASSWORD);
        assertThat(store.hasKey(KEY_ALIAS_ASYMMETRIC), is(true));
        store.deleteKey(KEY_ALIAS_ASYMMETRIC);
    }

    @Test
    @Override
    public void hasKeyIsFalse() {
        Store store = new Store(context, STORE_NAME, STORE_PASSWORD);
        assertThat(store.hasKey(KEY_ALIAS_ASYMMETRIC), is(false));
    }

    @Test
    @Override
    public void deleteKeyIsWorking() {
        Store store = new Store(context, STORE_NAME, STORE_PASSWORD);
        store.generateAsymmetricKey(KEY_ALIAS_ASYMMETRIC, KEY_PASSWORD);
        store.deleteKey(KEY_ALIAS_ASYMMETRIC);
        assertThat(store.hasKey(KEY_ALIAS_ASYMMETRIC), is(false));

        // make sure that new instance of store also doesn't contains the key
        store = new Store(context, STORE_NAME, STORE_PASSWORD);
        assertThat(store.hasKey(KEY_ALIAS_ASYMMETRIC), is(false));
    }

    @Test
    @Override
    public void encryptSmallDataIsValid() {
        Store store = new Store(context, STORE_NAME, STORE_PASSWORD);
        KeyPair keyPair = store.generateAsymmetricKey(KEY_ALIAS_ASYMMETRIC, KEY_PASSWORD);
        Crypto crypto = new Crypto(TRANSFORMATION_ASYMMETRIC);
        String encrypt = crypto.encrypt(SMALL_DATA, keyPair);
        String decrypt = crypto.decrypt(encrypt, keyPair);
        assertThat(SMALL_DATA, is(decrypt));
        store.deleteKey(KEY_ALIAS_ASYMMETRIC);
    }

    @Test
    @Override
    public void encryptLargeDataIsValid() {
        Store store = new Store(context, STORE_NAME, STORE_PASSWORD);
        KeyPair keyPair = store.generateAsymmetricKey(KEY_ALIAS_ASYMMETRIC, KEY_PASSWORD);
        Crypto crypto = new Crypto(TRANSFORMATION_ASYMMETRIC, ENCRYPTION_BLOCK_SIZE, DECRYPTION_BLOCK_SIZE);
        String encrypt = crypto.encrypt(LARGE_DATA, keyPair);
        String decrypt = crypto.decrypt(encrypt, keyPair);
        assertThat(LARGE_DATA, is(decrypt));
        store.deleteKey(KEY_ALIAS_ASYMMETRIC);
    }

    @Test
    public void encryptLargeDataWith512KeySizeIsValid() {
        encryptLargeDataIsValid(512);
    }

    @Test
    public void encryptLargeDataWith1024KeySizeIsValid() {
        encryptLargeDataIsValid(1024);
    }

    @Test
    public void encryptLargeDataWith2048KeySizeIsValid() {
        encryptLargeDataIsValid(2048);
    }

    @Test
    public void encryptLargeDataWith3072KeySizeIsValid() {
        encryptLargeDataIsValid(3072);
    }

    @Test
    public void encryptLargeDataWith4096KeySizeIsValid() {
        encryptLargeDataIsValid(4096);
    }

    @Test
    @Override
    public void encryptDataIsNotValid() {
        // different keys encryption
        Store store = new Store(context, STORE_NAME, STORE_PASSWORD);
        KeyPair keyPair = store.generateAsymmetricKey(KEY_ALIAS_ASYMMETRIC, KEY_PASSWORD);
        KeyPair keyPair2 = store.generateAsymmetricKey("key-pair-2", KEY_PASSWORD);
        Crypto crypto = new Crypto(TRANSFORMATION_SYMMETRIC);
        String encrypt = crypto.encrypt(SMALL_DATA, keyPair);
        String decrypt = crypto.decrypt(encrypt, keyPair2);
        assertThat(SMALL_DATA, is(not(decrypt)));
        store.deleteKey(KEY_ALIAS_ASYMMETRIC);
        store.deleteKey("key-pair-2");

        // wrong block props for large data

        try {
            keyPair = store.generateAsymmetricKey(KEY_ALIAS_ASYMMETRIC, KEY_PASSWORD);
            crypto = new Crypto(TRANSFORMATION_ASYMMETRIC);
            encrypt = crypto.encrypt(LARGE_DATA, keyPair);
            decrypt = crypto.decrypt(encrypt, keyPair);
        } catch (Exception e) {
            assertThat(Build.VERSION.SDK_INT, is(Matchers.lessThan(Build.VERSION_CODES.JELLY_BEAN_MR2)));
            assertThat(e, is(instanceOf(ArrayIndexOutOfBoundsException.class)));
        }

        assertThat(LARGE_DATA, is(not(decrypt)));
        store.deleteKey(KEY_ALIAS_ASYMMETRIC);
    }

    private void encryptLargeDataIsValid(int keySize) {
        Store store = new Store(context, STORE_NAME, STORE_PASSWORD);

        final Calendar start = Calendar.getInstance();
        final Calendar end = Calendar.getInstance();
        end.add(Calendar.YEAR, 1);

        KeyProps keyProps = new KeyProps.Builder()
                .setAlias(KEY_ALIAS_ASYMMETRIC)
                .setPassword(KEY_PASSWORD)
                .setKeySize(keySize)
                .setKeyType("RSA")
                .setSerialNumber(BigInteger.ONE)
                .setSubject(new X500Principal("CN=" + KEY_ALIAS_ASYMMETRIC + " CA Certificate"))
                .setStartDate(start.getTime())
                .setEndDate(start.getTime())
                .setBlockModes("ECB")
                .setEncryptionPaddings("PKCS1Padding")
                .setSignatureAlgorithm("SHA256WithRSAEncryption")
                .build();

        KeyPair keyPair = store.generateAsymmetricKey(keyProps);

        int encryptionBlock;
        int decryptionBlock;

        if (Build.VERSION.SDK_INT == Build.VERSION_CODES.JELLY_BEAN_MR2) {
            encryptionBlock = Options.RSA_ECB_PKCS1PADDING_ENCRYPTION_BLOCK_SIZE_FOR_JELLY_BEAN;
            decryptionBlock = Options.RSA_ECB_PKCS1PADDING_DECRYPTION_BLOCK_SIZE_FOR_JELLY_BEAN;
        } else {
            encryptionBlock = keySize / 8 - 11;
            decryptionBlock = keySize / 8;
        }

        Crypto crypto = new Crypto(TRANSFORMATION_ASYMMETRIC, encryptionBlock, decryptionBlock);
        String encrypt = crypto.encrypt(LARGE_DATA, keyPair);
        String decrypt = crypto.decrypt(encrypt, keyPair);

        assertThat(LARGE_DATA, is(decrypt));
        store.deleteKey(KEY_ALIAS_ASYMMETRIC);
    }
}