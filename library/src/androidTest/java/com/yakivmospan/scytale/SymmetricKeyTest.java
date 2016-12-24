package com.yakivmospan.scytale;

import org.junit.Test;
import org.junit.runner.RunWith;

import android.os.Build;
import android.support.test.runner.AndroidJUnit4;

import javax.crypto.SecretKey;

import static com.yakivmospan.scytale.Options.TRANSFORMATION_SYMMETRIC;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.core.IsNot.not;
import static org.junit.Assert.assertThat;

@RunWith(AndroidJUnit4.class)
public class SymmetricKeyTest extends BaseContextTest implements KeyTest {

    @Test
    @Override
    public void generateDefaultKeyIsNotNull() {
        Store store = new Store(context, STORE_NAME, STORE_PASSWORD);
        SecretKey secretKey = store.generateSymmetricKey(KEY_ALIAS_SYMMETRIC, KEY_PASSWORD);
        assertThat(secretKey, is(notNullValue()));
        store.deleteKey(KEY_ALIAS_SYMMETRIC);
    }

    @Test
    @Override
    public void generateKeyIsNotNull() {
        Store store = new Store(context, STORE_NAME, STORE_PASSWORD);
        SecretKey secretKey = store.generateSymmetricKey(new KeyProps.Builder()
                .setAlias(KEY_ALIAS_SYMMETRIC)
                .setPassword(KEY_PASSWORD)
                .setKeySize(256)
                .setKeyType("AES")
                .setBlockModes("CBC")
                .setEncryptionPaddings("PKCS7Padding")
                .build());
        assertThat(secretKey, is(notNullValue()));
        store.deleteKey(KEY_ALIAS_SYMMETRIC);
    }

    @Test
    @Override
    public void generateKeyHasWrongType() {
        Store store = new Store(context, STORE_NAME, STORE_PASSWORD);
        SecretKey secretKey = store.generateSymmetricKey(new KeyProps.Builder()
                .setAlias(KEY_ALIAS_SYMMETRIC)
                .setPassword(KEY_PASSWORD)
                .setKeySize(256)
                .setKeyType("no-such-key-type")
                .setBlockModes("CBC")
                .setEncryptionPaddings("PKCS7Padding")
                .build());

        assertThat(secretKey, is(nullValue()));
    }

    @Test
    @Override
    public void generateKeyHasNoBlockModes() {
        Store store = new Store(context, STORE_NAME, STORE_PASSWORD);
        SecretKey secretKey = store.generateSymmetricKey(new KeyProps.Builder()
                .setAlias(KEY_ALIAS_SYMMETRIC)
                .setPassword(KEY_PASSWORD)
                .setKeySize(256)
                .setKeyType("AES")
                .setBlockModes("no-such-block-modes")
                .setEncryptionPaddings("PKCS7Padding")
                .build());

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            assertThat(secretKey, is(notNullValue()));
            store.deleteKey(KEY_ALIAS_SYMMETRIC);
        } else {
            assertThat(secretKey, is(nullValue()));
        }
    }

    @Test
    @Override
    public void generateKeyHasNoEncryptionPaddings() {
        Store store = new Store(context, STORE_NAME, STORE_PASSWORD);
        SecretKey secretKey = store.generateSymmetricKey(new KeyProps.Builder()
                .setAlias(KEY_ALIAS_SYMMETRIC)
                .setPassword(KEY_PASSWORD)
                .setKeySize(256)
                .setKeyType("AES")
                .setBlockModes("CBC")
                .setEncryptionPaddings("no-such-encryption-paddings")
                .build());

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            assertThat(secretKey, is(notNullValue()));
            store.deleteKey(KEY_ALIAS_SYMMETRIC);
        } else {
            assertThat(secretKey, is(nullValue()));
        }
    }

    @Test
    @Override
    public void getKeyIsNotNull() {
        Store store = new Store(context, STORE_NAME, STORE_PASSWORD);
        store.generateSymmetricKey(KEY_ALIAS_SYMMETRIC, KEY_PASSWORD);
        SecretKey symmetricKey = store.getSymmetricKey(KEY_ALIAS_SYMMETRIC, KEY_PASSWORD);
        assertThat(symmetricKey, is(notNullValue()));

        store = new Store(context, STORE_NAME, STORE_PASSWORD);
        symmetricKey = store.getSymmetricKey(KEY_ALIAS_SYMMETRIC, KEY_PASSWORD);
        assertThat(symmetricKey, is(notNullValue()));

        store.deleteKey(KEY_ALIAS_SYMMETRIC);
    }

    @Test
    @Override
    public void getKeyIsNull() {
        Store store = new Store(context, STORE_NAME, STORE_PASSWORD);
        SecretKey symmetricKey = store.getSymmetricKey(KEY_ALIAS_SYMMETRIC, KEY_PASSWORD);
        assertThat(symmetricKey, is(nullValue()));
    }

    @Test
    @Override
    public void hasKeyIsTrue() {
        Store store = new Store(context, STORE_NAME, STORE_PASSWORD);
        store.generateSymmetricKey(KEY_ALIAS_SYMMETRIC, KEY_PASSWORD);
        assertThat(store.hasKey(KEY_ALIAS_SYMMETRIC), is(true));
        store.deleteKey(KEY_ALIAS_SYMMETRIC);
    }

    @Test
    @Override
    public void hasKeyIsFalse() {
        Store store = new Store(context, STORE_NAME, STORE_PASSWORD);
        assertThat(store.hasKey(KEY_ALIAS_SYMMETRIC), is(false));
    }

    @Test
    @Override
    public void deleteKeyIsWorking() {
        Store store = new Store(context, STORE_NAME, STORE_PASSWORD);
        store.generateSymmetricKey(KEY_ALIAS_SYMMETRIC, KEY_PASSWORD);
        store.deleteKey(KEY_ALIAS_SYMMETRIC);
        assertThat(store.hasKey(KEY_ALIAS_SYMMETRIC), is(false));

        // make sure that new instance of store also doesn't contains the key
        store = new Store(context, STORE_NAME, STORE_PASSWORD);
        assertThat(store.hasKey(KEY_ALIAS_SYMMETRIC), is(false));
    }

    @Test
    @Override
    public void encryptSmallDataIsValid() {
        encryptDataIsValid(SMALL_DATA);
    }

    @Test
    @Override
    public void encryptLargeDataIsValid() {
        encryptDataIsValid(LARGE_DATA);
    }

    @Test
    @Override
    public void encryptDataIsNotValid() {
        Store store = new Store(context, STORE_NAME, STORE_PASSWORD);
        SecretKey secretKey = store.generateSymmetricKey(KEY_ALIAS_SYMMETRIC, KEY_PASSWORD);
        SecretKey secretKey2 = store.generateSymmetricKey("secret-key-2", KEY_PASSWORD);
        Crypto crypto = new Crypto(TRANSFORMATION_SYMMETRIC);
        String encrypt = crypto.encrypt(LARGE_DATA, secretKey);
        String decrypt = crypto.decrypt(encrypt, secretKey2);
        assertThat(LARGE_DATA, is(not(decrypt)));
        store.deleteKey(KEY_ALIAS_SYMMETRIC);
        store.deleteKey("secret-key-2");
    }

    private void encryptDataIsValid(String data) {
        Store store = new Store(context, STORE_NAME, STORE_PASSWORD);
        SecretKey secretKey = store.generateSymmetricKey(KEY_ALIAS_SYMMETRIC, KEY_PASSWORD);
        Crypto crypto = new Crypto(TRANSFORMATION_SYMMETRIC);
        String encrypt = crypto.encrypt(data, secretKey);
        String decrypt = crypto.decrypt(encrypt, secretKey);
        assertThat(data, is(decrypt));
        store.deleteKey(KEY_ALIAS_SYMMETRIC);
    }
}