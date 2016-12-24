package com.yakivmospan.scytale;

import android.security.KeyPairGeneratorSpec;
import android.support.annotation.NonNull;
import android.util.Base64;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

/**
 * API to encrypt/decrypt data
 */
public class Crypto extends ErrorHandler {

    private static final String UTF_8 = "UTF-8";
    private static final String IV_SEPARATOR = "]";
    private String mTransformation;
    private int mEncryptionBlockSize;
    private int mDecryptionBlockSize;

    /**
     * Initializes Crypto to encrypt/decrypt data with given transformation.
     *
     * @param transformation is used to encrypt/decrypt data. See {@link Cipher} for more info.
     */
    public Crypto(@NonNull String transformation) {
        mTransformation = transformation;
    }

    /**
     * Initializes Crypto to encrypt/decrypt data using buffer with provided lengths. This might be useful if you
     * want to encrypt/decrypt big amount of data using Block Based Algorithms (such as RSA). By default they can
     * proceed only one block of data, not bigger then a size of a key that was used for encryption/decryption.
     *
     * @param transformation is used to encrypt/decrypt data. See {@link Cipher} for more info.<p>
     * @param encryptionBlockSize block size for keys used with this Crypto for encryption. Depends on API level.
     * For example: 1024 size RSA/ECB/PKCS1Padding key will equal to (keySize / 8) - 11 == (1024 / 8) - 11 == 117
     * but for API 18 it is equal to 245 as there is no possibility to specify key size in {@link
     * KeyPairGeneratorSpec} and 2048 key size is always used there. Use {@link Options#ENCRYPTION_BLOCK_SIZE} in
     * pair with key created by {@link Store#generateSymmetricKey(String, char[])}<p>
     * @param decryptionBlockSize block size for keys used with this Crypto for decryption. Depend on API level. For
     * example: 1024 size RSA/ECB/PKCS1Padding key will equal to (keySize / 8) == (1024 / 8) == 128 but on API 18 it
     * is equal to 256 as there is no possibility to specify key size in {@link KeyPairGeneratorSpec} and 2048 key
     * size is always used there. Use {@link Options#DECRYPTION_BLOCK_SIZE} in pair with key created by {@link
     * Store#generateSymmetricKey(String, char[])}
     */
    public Crypto(@NonNull String transformation, int encryptionBlockSize, int decryptionBlockSize) {
        mTransformation = transformation;
        mEncryptionBlockSize = encryptionBlockSize;
        mDecryptionBlockSize = decryptionBlockSize;
    }

    /**
     * The same as encrypt(data, key.getPublic(), false);
     *
     * @return encrypted data in Base64 String or null if any error occur. Doesn't use Initialisation Vectors
     */
    public String encrypt(@NonNull String data, @NonNull KeyPair key) {
        return encrypt(data, key.getPublic(), false);
    }

    /**
     * The same as encrypt(data, key, true)
     *
     * @return encrypted data in Base64 String or null if any error occur. Does use Initialisation Vectors
     */
    public String encrypt(@NonNull String data, @NonNull SecretKey key) {
        return encrypt(data, key, true);
    }

    /**
     * @param useInitialisationVectors specifies when ever IvParameterSpec should be used in encryption
     *
     * @return encrypted data in Base64 String or null if any error occur. if useInitialisationVectors is true, data
     * also contains iv key inside. In this case data will be returned in this format <iv key>]<encrypted data>
     */
    public String encrypt(@NonNull String data, @NonNull Key key, boolean useInitialisationVectors) {
        String result = "";
        try {
            Cipher cipher = Cipher.getInstance(mTransformation == null ? key.getAlgorithm() : mTransformation);
            cipher.init(Cipher.ENCRYPT_MODE, key);

            if (useInitialisationVectors) {
                byte[] iv = cipher.getIV();
                String ivString = Base64.encodeToString(iv, Base64.DEFAULT);
                result = ivString + IV_SEPARATOR;
            }

            byte[] plainData = data.getBytes(UTF_8);
            byte[] decodedData;
            if (mEncryptionBlockSize == 0 && mDecryptionBlockSize == 0) {
                decodedData = decode(cipher, plainData);
            } else {
                decodedData = decodeWithBuffer(cipher, plainData, mEncryptionBlockSize);
            }

            String encodedString = Base64.encodeToString(decodedData, Base64.DEFAULT);
            result += encodedString;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | BadPaddingException |
                IllegalBlockSizeException | IOException e) {
            onException(e);
        }
        return result;
    }

    /**
     * The same as decrypt(data, key.getPrivate(), false)
     *
     * @param data Base64 encrypted data. Doesn't use Initialisation Vectors
     *
     * @return decrypted data or null if any error occur
     */
    public String decrypt(@NonNull String data, @NonNull KeyPair key) {
        return decrypt(data, key.getPrivate(), false);
    }


    /**
     * The same as decrypt(data, key, true)
     *
     * @param data Base64 encrypted data with iv key. Does use Initialisation Vectors
     *
     * @return decrypted data or null if any error occur
     */
    public String decrypt(@NonNull String data, @NonNull SecretKey key) {
        return decrypt(data, key, true);
    }


    /**
     * @param data Base64 encrypted data. If useInitialisationVectors is enabled, data should contain iv key inside.
     * In this case data should be in this format <iv key>]<encrypted data>
     * @param useInitialisationVectors specifies when ever IvParameterSpec should be used in encryption
     *
     * @return decrypted data or null if any error occur
     */
    public String decrypt(@NonNull String data, @NonNull Key key, boolean useInitialisationVectors) {
        String result = null;
        try {
            String transformation = mTransformation == null ? key.getAlgorithm() : mTransformation;
            Cipher cipher = Cipher.getInstance(transformation);

            String encodedString;

            if (useInitialisationVectors) {
                String[] split = data.split(IV_SEPARATOR);
                String ivString = split[0];
                encodedString = split[1];
                IvParameterSpec ivSpec = new IvParameterSpec(Base64.decode(ivString, Base64.DEFAULT));
                cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
            } else {
                encodedString = data;
                cipher.init(Cipher.DECRYPT_MODE, key);
            }

            byte[] decodedData;
            byte[] encryptedData = Base64.decode(encodedString, Base64.DEFAULT);
            if (mEncryptionBlockSize == 0 && mDecryptionBlockSize == 0) {
                decodedData = decode(cipher, encryptedData);
            } else {
                decodedData = decodeWithBuffer(cipher, encryptedData, mDecryptionBlockSize);
            }
            result = new String(decodedData, UTF_8);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException | IOException | InvalidAlgorithmParameterException e) {
            onException(e);
        }
        return result;
    }

    private byte[] decode(@NonNull Cipher cipher, @NonNull byte[] plainData)
            throws IOException, IllegalBlockSizeException, BadPaddingException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        CipherOutputStream cipherOutputStream = new CipherOutputStream(baos, cipher);
        cipherOutputStream.write(plainData);
        cipherOutputStream.close();
        return baos.toByteArray();
    }

    private byte[] decodeWithBuffer(@NonNull Cipher cipher, @NonNull byte[] plainData, int bufferLength)
            throws IllegalBlockSizeException, BadPaddingException {
        // string initialize 2 buffers.
        // scrambled will hold intermediate results
        byte[] scrambled;

        // toReturn will hold the total result
        byte[] toReturn = new byte[0];

        // holds the bytes that have to be modified in one step
        byte[] buffer = new byte[(plainData.length > bufferLength ? bufferLength : plainData.length)];

        for (int i = 0; i < plainData.length; i++) {
            if ((i > 0) && (i % bufferLength == 0)) {
                //execute the operation
                scrambled = cipher.doFinal(buffer);
                // add the result to our total result.
                toReturn = append(toReturn, scrambled);
                // here we calculate the bufferLength of the next buffer required
                int newLength = bufferLength;

                // if newLength would be longer than remaining bytes in the bytes array we shorten it.
                if (i + bufferLength > plainData.length) {
                    newLength = plainData.length - i;
                }
                // clean the buffer array
                buffer = new byte[newLength];
            }
            // copy byte into our buffer.
            buffer[i % bufferLength] = plainData[i];
        }

        // this step is needed if we had a trailing buffer. should only happen when encrypting.
        // example: we encrypt 110 bytes. 100 bytes per run means we "forgot" the last 10 bytes. they are in the buffer array
        scrambled = cipher.doFinal(buffer);

        // final step before we can return the modified data.
        toReturn = append(toReturn, scrambled);
        return toReturn;
    }

    private byte[] append(byte[] prefix, byte[] suffix) {
        byte[] toReturn = new byte[prefix.length + suffix.length];
        for (int i = 0; i < prefix.length; i++) {
            toReturn[i] = prefix[i];
        }
        for (int i = 0; i < suffix.length; i++) {
            toReturn[i + prefix.length] = suffix[i];
        }
        return toReturn;
    }
}
