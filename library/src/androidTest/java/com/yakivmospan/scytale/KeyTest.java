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

}
