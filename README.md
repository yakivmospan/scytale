# Scytale

[![Download](https://api.bintray.com/packages/yakivmospan/maven/scytale/images/download.svg)](https://bintray.com/yakivmospan/maven/scytale/_latestVersion)

One tool to manage key generation, key storing and encryption on different APIs of Android.

![](assets/logo.png)

As you may know android provided API to use `keystore` that is stored in system only from API 18. They introduced [AndroidKeyStore](http://developer.android.com/training/articles/keystore.html) provider that is responsible to manage this.

But as always there are underwater stones. Up to API 23 you are only able to create asymmetric keys using  `AndroidKeyStore` provider. Also [algorithms](http://developer.android.com/training/articles/keystore.html#SupportedAlgorithms) that you can use are limited. And what about devices below API 18 ?

I've create API that wraps default [JCA](http://docs.oracle.com/javase/7/docs/technotes/guides/security/crypto/CryptoSpec.html) api and `AndroidKeyStore` API and makes it easy to create, manage and use your keys on any andorid API.

## Sample

```java
// Create and save key
Store store = new Store(getApplicationContext());
if (!store.hasKey("test")) {
   SecretKey key = store.generateSymmetricKey("test", null);
}
...

// Get key
SecretKey key = store.getSymmetricKey("test", null);

// Encrypt/Dencrypt data
Crypto crypto = new Crypto(Options.TRANSFORMATION_SYMMETRIC);
String text = "Sample text";

String encryptedData = crypto.encrypt(text, key);
Log.i("Scytale", "Encrypted data: " + encryptedData);

String decryptedData = crypto.decrypt(encryptedData, key);
Log.i("Scytale", "Decrypted data: " + decryptedData);
```

## How it works?

Depending on what key you need and what Android you are using, API will create `keystore` file in application inner cache or will use `AndroidKeyStore` to hold keys. Key generation will be also made with different API. The tables below shows what will be used in different cases.

In case you want to generate and save `Asymmetric` key

| API   | Application Keystore | AndroidKeyStore |
|:-----:|:--------------------:|:---------------:|
|`< 18` |  `+`                 |                 |
|`>= 18`|                      |        `+`      |


In case you want to generate and save `Symmetric` key

| API   | Application Keystore | AndroidKeyStore |
|:-----:|:--------------------:|:---------------:|
|`< 18` |  `+`                 |                 |
|`>= 23`|                      |        `+`      |

After calling one of `generateKey` methods, key will be automatically stored in `keystore`.

To store asymmetric `PrivateKey` we need to provide `X509Certificate`. And of course there is no default API to do that.

On `18+` devices its pretty easy, google did it for us.

For  `pre 18`  there is one 3d party library that can create self signed `X509Certificate`. It is called [Bouncy Castle](http://www.bouncycastle.org/) and is available on maven as well. But after some research I found that [Google did copied this library](https://goo.gl/Zcaqpj) to their API but made it private. Why ? Don't ask me..

So I decided to make it like this :

- API will try to get  Google Bouncy Castle using reflection (I've checked it on few APIs and it seems to work well)
- If Google version is missing, API will try to get 3d party Bouncy Castle library.  It will use reflection as well. This gives two advantages:
 - You can add this API for 18+ devices with out any additional libraries
 - You can run this API on pre 18 devices with out any additional libraries as well. And in case if some device will miss google hidden API you will receive an error and then include  Bouncy Castle to project. This is pretty cool if you are getting error on 15 API but your min project API is 16, and there is no errors on it.

In general it creates simple interface to work with `Keystore` using API provided by Java and different versions of Android.

## Extended Usage

Instead of using `generateAsymmetricKey(@NonNull String alias, char[] password)` method you can use ` generateAsymmetricKey(@NonNull KeyProps keyProps)` one, and  define key with specific options.

```java
// Create store with specific name and password
Store store = new Store(context, STORE_NAME, STORE_PASSWORD);

final int alias = "alias";
final int password = "password".toCharArray();
final int keysize = 512;

final Calendar start = Calendar.getInstance();
final Calendar end = Calendar.getInstance();
end.add(Calendar.YEAR, 1);

// Create a key store params, some of them are specific per platform
// Check KeyProps doc for more info
KeyProps keyProps = new KeyProps.Builder()
   .setAlias(alias)
   .setPassword(password)
   .setKeySize(keysize)
   .setKeyType("RSA")
   .setSerialNumber(BigInteger.ONE)
   .setSubject(new X500Principal("CN=" + alias + " CA Certificate"))
   .setStartDate(start.getTime())
   .setEndDate(end.getTime())
   .setBlockModes("ECB")
   .setEncryptionPaddings("PKCS1Padding")
   .setSignatureAlgorithm("SHA256WithRSAEncryption")
   .build();

// Generate KeyPair depending on KeyProps
KeyPair keyPair = store.generateAsymmetricKey(keyProps);

// Encrypt/Dencrypt data using buffer with or with out Initialisation Vectors
// This additional level of safety is required on 23 API level for
// some algorithms. Specify encryption/decryption block size to use buffer for
// large data when using block based algorithms(such as RSA)

final int encryptionBlockSize = keysize / 8 - 11; // as specified for RSA/ECB/PKCS1Padding keys
final int decryptionBlockSize = keysize / 8; // as specified for RSA/ECB/PKCS1Padding keys

Crypto crypto = new Crypto("RSA/ECB/PKCS1Padding", encryptionBlockSize, decryptionBlockSize);

String text = "Sample text";
String encryptedData = crypto.encrypt(text, key, false);
String decryptedData = crypto.decrypt(encryptedData, key, false);
```

### Download

Add dependency to your app `gradle.build` file:

```java
compile 'com.yakivmospan:scytale:1.0.0'
```

Minimum supported API version is 8.

### License

```
Copyright 2016 Yakiv Mospan

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```