package com.yakivmospan.scytale;

import org.junit.Test;
import org.junit.runner.RunWith;

import android.support.test.runner.AndroidJUnit4;

import javax.crypto.SecretKey;

import static com.yakivmospan.scytale.Constants.KEY_ALIAS_SYMMETRIC;
import static com.yakivmospan.scytale.Constants.KEY_PASSWORD;
import static com.yakivmospan.scytale.Constants.STORE_NAME;
import static com.yakivmospan.scytale.Constants.STORE_PASSWORD;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.junit.Assert.assertThat;

@RunWith(AndroidJUnit4.class)
public class WrappingKeysTest extends BaseContextTest {

    @Test
    public void generateDefaultKeyIsNotNull() {
        Store store = new Store(context, STORE_NAME, STORE_PASSWORD);
        SecretKey secretKey = store.generateSymmetricKey(KEY_ALIAS_SYMMETRIC, KEY_PASSWORD);
        assertThat(secretKey, is(notNullValue()));
        store.deleteKey(KEY_ALIAS_SYMMETRIC);
    }
}