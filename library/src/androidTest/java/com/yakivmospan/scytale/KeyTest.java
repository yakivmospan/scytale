package com.yakivmospan.scytale;

interface KeyTest {

    void generateDefaultKeyIsNotNull();
    void generateKeyIsNotNull();
    void generateKeyHasWrongType();
    void generateKeyHasNoBlockModes();
    void generateKeyHasNoEncryptionPaddings();
    void getKeyIsNotNull();
    void getKeyIsNull();
    void hasKeyIsTrue();
    void hasKeyIsFalse();
    void deleteKeyIsWorking();
    void encryptSmallDataIsValid();
    void encryptLargeDataIsValid();
    void encryptDataIsNotValid();

    String STORE_NAME = "security-store";
    char[] STORE_PASSWORD = "password".toCharArray();

    String KEY_ALIAS_ASYMMETRIC = "asymmetric";
    String KEY_ALIAS_SYMMETRIC = "symmetric";
    char[] KEY_PASSWORD = "password".toCharArray();
    int KEY_SIZE = 1024;

    String SMALL_DATA = "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo";
    String LARGE_DATA = "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeee eeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooodddwwoo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo"
            + "Hhhhhhhhhhhhhheeeeeeeeeeeellllllllooooo";
}
