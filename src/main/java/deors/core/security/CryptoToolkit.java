package deors.core.security;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;

import deors.core.commons.StringToolkit;

/**
 * Toolkit methods for managing cryptographic operations and creation and verification of digital
 * signatures.
 *
 * @author deors
 * @version 1.0
 */
public final class CryptoToolkit {

    /**
     * Bag for SecureRandom objects, indexed by algorithm id.
     */
    private static final Map<String, SecureRandom> PRNG_BAG = new HashMap<>();

    /**
     * Code for the MD5 digest algorithm.
     */
    public static final String MD5_DIGEST_ALGORITHM = "md5"; //$NON-NLS-1$

    /**
     * Code for the SHA1 digest algorithm.
     */
    public static final String SHA1_DIGEST_ALGORITHM = "sha1"; //$NON-NLS-1$

    /**
     * The certificate store type used in PKCS-7 signatures.
     */
    private static final String COLLECTION_CERT_STORE = "Collection"; //$NON-NLS-1$

    /**
     * Identifier for a CBC block cipher as it appears in the algorithm identification string.
     */
    private static final String CBC_ID = "/CBC/"; //$NON-NLS-1$

    /**
     * The initialization vector for the CBC block cipher.
     */
    private static final byte[] CBC_INITIALIZATION_VECTOR = new byte[] {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    /**
     * Key name in the properties file for <code>SECURITY_PROVIDER</code> property.
     */
    static final String KN_SECURITY_PROVIDER = "crypto.securityProvider"; //$NON-NLS-1$

    /**
     * Default value for <code>SECURITY_PROVIDER</code> property.
     */
    static final String DV_SECURITY_PROVIDER = "BC"; //$NON-NLS-1$

    /**
     * Security provider. Configurable in the properties file using the key referenced by the
     * constant <code>KN_SECURITY_PROVIDER</code> and <code>DV_SECURITY_PROVIDER</code> as the
     * default value.
     *
     * @see SecurityContext#getConfigurationProperty(String, String)
     * @see CryptoToolkit#KN_SECURITY_PROVIDER
     * @see CryptoToolkit#DV_SECURITY_PROVIDER
     */
    static final String SECURITY_PROVIDER =
        SecurityContext.getConfigurationProperty(KN_SECURITY_PROVIDER, DV_SECURITY_PROVIDER);

    /**
     * Key name in the properties file for <code>HASHING_ALGORITHM</code> property.
     */
    static final String KN_HASHING_ALGORITHM = "crypto.hashingAlgorithm"; //$NON-NLS-1$

    /**
     * Default value for <code>HASHING_ALGORITHM</code> property.
     */
    static final String DV_HASHING_ALGORITHM = MD5_DIGEST_ALGORITHM;

    /**
     * Hashing algorithm used for message digests. Configurable in the properties file using the key
     * referenced by the constant <code>KN_HASHING_ALGORITHM</code> and
     * <code>DV_HASHING_ALGORITHM</code> as the default value.
     *
     * @see SecurityContext#getConfigurationProperty(String, String)
     * @see CryptoToolkit#KN_HASHING_ALGORITHM
     * @see CryptoToolkit#DV_HASHING_ALGORITHM
     */
    static final String HASHING_ALGORITHM =
        SecurityContext.getConfigurationProperty(KN_HASHING_ALGORITHM, DV_HASHING_ALGORITHM);

    /**
     * Key name in the properties file for <code>PRNG_ALGORITHM</code> property.
     */
    static final String KN_PRNG_ALGORITHM = "crypto.prngAlgorithm"; //$NON-NLS-1$

    /**
     * Default value for <code>PRNG_ALGORITHM</code> property.
     */
    static final String DV_PRNG_ALGORITHM = "sha1prng"; //$NON-NLS-1$

    /**
     * Pseudo-random number generation algorithm. Configurable in the properties file using the key
     * referenced by the constant <code>KN_PRNG_ALGORITHM</code> and
     * <code>DV_PRNG_ALGORITHM</code> as the default value.
     *
     * @see SecurityContext#getConfigurationProperty(String, String)
     * @see CryptoToolkit#KN_PRNG_ALGORITHM
     * @see CryptoToolkit#DV_PRNG_ALGORITHM
     */
    static final String PRNG_ALGORITHM =
        SecurityContext.getConfigurationProperty(KN_PRNG_ALGORITHM, DV_PRNG_ALGORITHM);

    /**
     * Key name in the properties file for <code>KEY_GEN_ALGORITHM</code> property.
     */
    static final String KN_KEY_GEN_ALGORITHM = "crypto.keyGenAlgorithm"; //$NON-NLS-1$

    /**
     * Default value for <code>KEY_GEN_ALGORITHM</code> property.
     */
    static final String DV_KEY_GEN_ALGORITHM = "DESede"; //$NON-NLS-1$

    /**
     * Key generation algorithm. Configurable in the properties file using the key referenced by the
     * constant <code>KN_KEY_GEN_ALGORITHM</code> and <code>DV_KEY_GEN_ALGORITHM</code> as the
     * default value.
     *
     * @see SecurityContext#getConfigurationProperty(String, String)
     * @see CryptoToolkit#KN_KEY_GEN_ALGORITHM
     * @see CryptoToolkit#DV_KEY_GEN_ALGORITHM
     */
    static final String KEY_GEN_ALGORITHM =
        SecurityContext.getConfigurationProperty(KN_KEY_GEN_ALGORITHM, DV_KEY_GEN_ALGORITHM);

    /**
     * Key name in the properties file for <code>KEY_SIZE_IN_BYTES</code> property.
     */
    static final String KN_KEY_SIZE_IN_BYTES = "crypto.keySizeInBytes"; //$NON-NLS-1$

    /**
     * Default value for <code>KEY_SIZE_IN_BYTES</code> property.
     */
    static final int DV_KEY_SIZE_IN_BYTES = 24;

    /**
     * Key size in bytes. Configurable in the properties file using the key referenced by the
     * constant <code>KN_KEY_SIZE_IN_BYTES</code> and <code>DV_KEY_SIZE_IN_BYTES</code> as the
     * default value.
     *
     * @see SecurityContext#getConfigurationProperty(String, int)
     * @see CryptoToolkit#KN_KEY_SIZE_IN_BYTES
     * @see CryptoToolkit#DV_KEY_SIZE_IN_BYTES
     */
    static final int KEY_SIZE_IN_BYTES =
        SecurityContext.getConfigurationProperty(KN_KEY_SIZE_IN_BYTES, DV_KEY_SIZE_IN_BYTES);

    /**
     * Key name in the properties file for <code>SYMMETRIC_ALGORITHM</code> property.
     */
    static final String KN_SYMMETRIC_ALGORITHM = "crypto.symmetricAlgorithm"; //$NON-NLS-1$

    /**
     * Default value for <code>SYMMETRIC_ALGORITHM</code> property.
     */
    static final String DV_SYMMETRIC_ALGORITHM = "DESede/CBC/PKCS7Padding"; //$NON-NLS-1$

    /**
     * Symmetric encryption/decryption algorithm. Configurable in the properties file using the key
     * referenced by the constant <code>KN_SYMMETRIC_ALGORITHM</code> and
     * <code>DV_SYMMETRIC_ALGORITHM</code> as the default value.
     *
     * @see SecurityContext#getConfigurationProperty(String, String)
     * @see CryptoToolkit#KN_SYMMETRIC_ALGORITHM
     * @see CryptoToolkit#DV_SYMMETRIC_ALGORITHM
     */
    static final String SYMMETRIC_ALGORITHM =
        SecurityContext.getConfigurationProperty(KN_SYMMETRIC_ALGORITHM, DV_SYMMETRIC_ALGORITHM);

    /**
     * Key name in the properties file for <code>ASYMMETRIC_ALGORITHM</code> property.
     */
    static final String KN_ASYMMETRIC_ALGORITHM = "crypto.asymmetricAlgorithm"; //$NON-NLS-1$

    /**
     * Default value for <code>ASYMMETRIC_ALGORITHM</code> property.
     */
    static final String DV_ASYMMETRIC_ALGORITHM = "RSA/NONE/PKCS1Padding"; //$NON-NLS-1$

    /**
     * Asymmetric encryption/decryption algorithm. Configurable in the properties file using the key
     * referenced by the constant <code>KN_ASYMMETRIC_ALGORITHM</code> and
     * <code>DV_ASYMMETRIC_ALGORITHM</code> as the default value.
     *
     * @see SecurityContext#getConfigurationProperty(String, String)
     * @see CryptoToolkit#KN_ASYMMETRIC_ALGORITHM
     * @see CryptoToolkit#DV_ASYMMETRIC_ALGORITHM
     */
    static final String ASYMMETRIC_ALGORITHM =
        SecurityContext.getConfigurationProperty(KN_ASYMMETRIC_ALGORITHM, DV_ASYMMETRIC_ALGORITHM);

    /**
     * Default constructor. This class is a toolkit and therefore it cannot be instantiated.
     */
    private CryptoToolkit() {
        super();
    }

    /**
     * Calculates the stream contents hash using the especified hashing algorithm.
     *
     * @param is the source stream
     * @param algorithm the hashing algorithm
     *
     * @return the hash
     *
     * @throws java.security.NoSuchAlgorithmException the hashing algorithm is not supported
     * @throws java.io.IOException an I/O exception
     */
    public static byte[] calculateHash(java.io.InputStream is, String algorithm)
        throws java.security.NoSuchAlgorithmException,
               java.io.IOException {

        MessageDigest md = MessageDigest.getInstance(algorithm);

        byte[] buffer = new byte[SecurityContext.DEFAULT_BUFFER_SIZE];
        int n;

        while ((n = is.read(buffer)) != -1) {
            md.update(buffer, 0, n);
        }

        return md.digest();
    }

    /**
     * Calculates the stream contents hash using the configured hashing algorithm.
     *
     * @param is the source stream
     *
     * @return the hash
     *
     * @throws java.security.NoSuchAlgorithmException the hashing algorithm is not supported
     * @throws java.io.IOException an I/O exception
     *
     * @see CryptoToolkit#HASHING_ALGORITHM
     */
    public static byte[] calculateHash(java.io.InputStream is)
        throws java.security.NoSuchAlgorithmException,
               java.io.IOException {

        return calculateHash(is, HASHING_ALGORITHM);
    }

    /**
     * Calculates the file contents hash using the specified hashing algorithm.
     *
     * @param file the source file
     * @param algorithm the hashing algorithm
     *
     * @return the hash
     *
     * @throws java.security.NoSuchAlgorithmException the hashing algorithm is not supported
     * @throws java.io.IOException an I/O exception
     */
    public static byte[] calculateHash(java.io.File file, String algorithm)
        throws java.security.NoSuchAlgorithmException,
               java.io.IOException {

        FileInputStream fis = null;
        try {
            fis = new FileInputStream(file);
            return calculateHash(fis, algorithm);
        } finally {
            if (fis != null) {
                fis.close();
            }
        }
    }

    /**
     * Calculates the file contents hash using the configured hashing algorithm.
     *
     * @param file the source file
     *
     * @return the hash
     *
     * @throws java.security.NoSuchAlgorithmException the hashing algorithm is not supported
     * @throws java.io.IOException an I/O exception
     *
     * @see CryptoToolkit#HASHING_ALGORITHM
     */
    public static byte[] calculateHash(java.io.File file)
        throws java.security.NoSuchAlgorithmException,
               java.io.IOException {

        FileInputStream fis = null;
        try {
            fis = new FileInputStream(file);
            return calculateHash(fis, HASHING_ALGORITHM);
        } finally {
            if (fis != null) {
                fis.close();
            }
        }
    }

    /**
     * Calculates the stream contents hash using the specified hashing algorithm and returns it as
     * an hexadecimal string.
     *
     * @param is the source stream
     * @param algorithm the hashing algorithm
     *
     * @return the hash as an hexadecimal string
     *
     * @throws java.security.NoSuchAlgorithmException the hashing algorithm is not supported
     * @throws java.io.IOException an I/O exception
     */
    public static String calculateHashString(java.io.InputStream is, String algorithm)
        throws java.security.NoSuchAlgorithmException,
               java.io.IOException {

        return StringToolkit.asHexadecimalString(calculateHash(is, algorithm));
    }

    /**
     * Calculates the stream contents hash using the configured hashing algorithm and returns it as
     * an hexadecimal string.
     *
     * @param is the source stream
     *
     * @return the hash as an hexadecimal string
     *
     * @throws java.security.NoSuchAlgorithmException the hashing algorithm is not supported
     * @throws java.io.IOException an I/O exception
     *
     * @see CryptoToolkit#HASHING_ALGORITHM
     */
    public static String calculateHashString(java.io.InputStream is)
        throws java.security.NoSuchAlgorithmException,
               java.io.IOException {

        return calculateHashString(is, HASHING_ALGORITHM);
    }

    /**
     * Calculates the file contents hash using the specified hashing algorithm and returns it as an
     * hexadecimal string.
     *
     * @param file the source file
     * @param algorithm the hashing algorithm
     *
     * @return the hash as an hexadecimal string
     *
     * @throws java.security.NoSuchAlgorithmException the hashing algorithm is not supported
     * @throws java.io.IOException an I/O exception
     */
    public static String calculateHashString(java.io.File file, String algorithm)
        throws java.security.NoSuchAlgorithmException,
               java.io.IOException {

        FileInputStream fis = null;
        try {
            fis = new FileInputStream(file);
            return calculateHashString(fis, algorithm);
        } finally {
            if (fis != null) {
                fis.close();
            }
        }
    }

    /**
     * Calculates the file contents hash using the configured hashing algorithm and returns it as an
     * hexadecimal string.
     *
     * @param file the source file
     *
     * @return the hash as an hexadecimal string
     *
     * @throws java.security.NoSuchAlgorithmException the hashing algorithm is not supported
     * @throws java.io.IOException an I/O exception
     *
     * @see CryptoToolkit#HASHING_ALGORITHM
     */
    public static String calculateHashString(java.io.File file)
        throws java.security.NoSuchAlgorithmException,
               java.io.IOException {

        FileInputStream fis = null;
        try {
            fis = new FileInputStream(file);
            return calculateHashString(fis, HASHING_ALGORITHM);
        } finally {
            if (fis != null) {
                fis.close();
            }
        }
    }

    /**
     * Creates and returns a symmetric key using the given pseudo-random number generation
     * algorithm, key generation algorithm, key size and security provider. The pseudo-random
     * number generator is initialized once per algorithm.
     *
     * @param prngAlgorithm the pseudo-random number generation algorithm
     * @param keyGenAlgorithm the key generation algorithm
     * @param keySizeInBytes the key size
     * @param securityProvider the security provider
     *
     * @return the generated key
     *
     * @throws java.security.NoSuchProviderException the security provider is not supported
     * @throws java.security.NoSuchAlgorithmException the pseudo-random number generation algorithm
     *                                                is not supported
     *
     * @see CryptoToolkit#PRNG_BAG
     */
    public static javax.crypto.SecretKey createSymmetricKey(String prngAlgorithm,
                                                            String keyGenAlgorithm,
                                                            int keySizeInBytes,
                                                            String securityProvider)
        throws java.security.NoSuchProviderException,
               java.security.NoSuchAlgorithmException {

        final int bitsPerByte = 8;

        // we get or create a random number generator
        SecureRandom prng = null;
        synchronized (PRNG_BAG) {
            prng = PRNG_BAG.get(prngAlgorithm);
            if (prng == null) {
                prng = SecureRandom.getInstance(prngAlgorithm);
                prng.setSeed(System.currentTimeMillis());
                PRNG_BAG.put(prngAlgorithm, prng);
            }
        }

        // we instantiate the key generator
        javax.crypto.KeyGenerator keygen =
            javax.crypto.KeyGenerator.getInstance(keyGenAlgorithm, securityProvider);

        // we initialize the key generator
        // (key length and random number generator)
        keygen.init(keySizeInBytes * bitsPerByte, prng);

        // we generate the key
        return keygen.generateKey();
    }

    /**
     * Creates and returns a symmetric key using the configured pseudo-random number generation
     * algorithm, key generation algorithm, key size and security provider.
     *
     * @return the generated key
     *
     * @throws java.security.NoSuchProviderException the security provider is not supported
     * @throws java.security.NoSuchAlgorithmException the pseudo-random number generation algorithm
     *                                                is not supported
     *
     * @see CryptoToolkit#PRNG_ALGORITHM
     * @see CryptoToolkit#KEY_GEN_ALGORITHM
     * @see CryptoToolkit#KEY_SIZE_IN_BYTES
     * @see CryptoToolkit#SECURITY_PROVIDER
     */
    public static javax.crypto.SecretKey createSymmetricKey()
        throws java.security.NoSuchProviderException,
               java.security.NoSuchAlgorithmException {

        return createSymmetricKey(PRNG_ALGORITHM, KEY_GEN_ALGORITHM, KEY_SIZE_IN_BYTES,
                                  SECURITY_PROVIDER);
    }

    /**
     * Returns a symmetric key constructed from the given byte array and the given key generation
     * algorithm.
     *
     * @param sourceKey the source key
     * @param keyGenAlgorithm the key generation algorithm
     *
     * @return the constructed key
     */
    public static javax.crypto.SecretKey createSymmetricKey(byte[] sourceKey, String keyGenAlgorithm) {

        return new javax.crypto.spec.SecretKeySpec(sourceKey, keyGenAlgorithm);
    }

    /**
     * Returns a symmetric key constructed from the given byte array and the configured key
     * generation algorithm.
     *
     * @param sourceKey the source key
     *
     * @return the constructed key
     */
    public static javax.crypto.SecretKey createSymmetricKey(byte[] sourceKey) {

        return createSymmetricKey(sourceKey, KEY_GEN_ALGORITHM);
    }

    /**
     * Decrypts a byte array using the given key, decryption algorithm and security provider.
     *
     * @param data the encrypted data
     * @param key the decryption key
     * @param decryptionAlgorithm the decryption algorithm
     * @param securityProvider the security provider
     *
     * @return the decrypted data
     *
     * @throws java.security.NoSuchProviderException the security provider is not supported
     * @throws java.security.NoSuchAlgorithmException the decryption algorithm is not supported
     * @throws java.security.InvalidAlgorithmParameterException the decryption algorithm parameters
     *                                                          are not valid
     * @throws java.security.InvalidKeyException the key is not valid
     * @throws javax.crypto.NoSuchPaddingException the padding method is not supported
     * @throws java.io.IOException an I/O exception
     *
     * @see CryptoToolkit#CBC_INITIALIZATION_VECTOR
     */
    public static byte[] decrypt(byte[] data, Key key, String decryptionAlgorithm,
                                 String securityProvider)
        throws java.security.NoSuchProviderException,
               java.security.NoSuchAlgorithmException,
               java.security.InvalidAlgorithmParameterException,
               java.security.InvalidKeyException,
               javax.crypto.NoSuchPaddingException,
               java.io.IOException {

        javax.crypto.Cipher cipher =
            javax.crypto.Cipher.getInstance(decryptionAlgorithm, securityProvider);

        if (decryptionAlgorithm.indexOf(CBC_ID) == -1) {
            cipher.init(javax.crypto.Cipher.DECRYPT_MODE, key);
        } else {
            cipher.init(javax.crypto.Cipher.DECRYPT_MODE, key,
                new IvParameterSpec(CBC_INITIALIZATION_VECTOR));
        }

        java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
        javax.crypto.CipherOutputStream cos = new javax.crypto.CipherOutputStream(baos, cipher);

        cos.write(data);
        cos.close();

        return baos.toByteArray();
    }

    /**
     * Decrypts a byte array using the given key and the configured asymmetric algorithm and
     * security provider.
     *
     * @param data the encrypted data
     * @param key the decryption key
     *
     * @return the decrypted data
     *
     * @throws java.security.NoSuchProviderException the security provider is not supported
     * @throws java.security.NoSuchAlgorithmException the decryption algorithm is not supported
     * @throws java.security.InvalidAlgorithmParameterException the decryption algorithm parameters
     *                                                          are not valid
     * @throws java.security.InvalidKeyException the key is not valid
     * @throws javax.crypto.NoSuchPaddingException the padding method is not supported
     * @throws java.io.IOException an I/O exception
     *
     * @see CryptoToolkit#ASYMMETRIC_ALGORITHM
     * @see CryptoToolkit#SECURITY_PROVIDER
     */
    public static byte[] decryptAsymmetric(byte[] data, Key key)
        throws java.security.NoSuchProviderException,
               java.security.NoSuchAlgorithmException,
               java.security.InvalidAlgorithmParameterException,
               java.security.InvalidKeyException,
               javax.crypto.NoSuchPaddingException,
               java.io.IOException {

        return decrypt(data, key, ASYMMETRIC_ALGORITHM, SECURITY_PROVIDER);
    }

    /**
     * Decrypts a byte array using the given key and the configured symmetric algorithm and security
     * provider.
     *
     * @param data the encrypted data
     * @param key the decryption key
     *
     * @return the decrypted data
     *
     * @throws java.security.NoSuchProviderException the security provider is not supported
     * @throws java.security.NoSuchAlgorithmException the decryption algorithm is not supported
     * @throws java.security.InvalidAlgorithmParameterException the decryption algorithm parameters
     *                                                          are not valid
     * @throws java.security.InvalidKeyException the key is not valid
     * @throws javax.crypto.NoSuchPaddingException the padding method is not supported
     * @throws java.io.IOException an I/O exception
     *
     * @see CryptoToolkit#SYMMETRIC_ALGORITHM
     * @see CryptoToolkit#SECURITY_PROVIDER
     */
    public static byte[] decryptSymmetric(byte[] data, Key key)
        throws java.security.NoSuchProviderException,
               java.security.NoSuchAlgorithmException,
               java.security.InvalidAlgorithmParameterException,
               java.security.InvalidKeyException,
               javax.crypto.NoSuchPaddingException,
               java.io.IOException {

        return decrypt(data, key, SYMMETRIC_ALGORITHM, SECURITY_PROVIDER);
    }

    /**
     * Decrypts the given stream contents using the given key, decryption algorithm and security
     * provider and writing the decrypted contents in the given output stream. The input and output
     * streams are closed.
     *
     * @param dataStream stream that contains the encrypted data
     * @param decryptedStream stream where to write the decrypted data
     * @param key the decryption key
     * @param decryptionAlgorithm the decryption algorithm
     * @param securityProvider the security provider
     *
     * @throws java.security.NoSuchProviderException the security provider is not supported
     * @throws java.security.NoSuchAlgorithmException the decryption algorithm is not supported
     * @throws java.security.InvalidAlgorithmParameterException the decryption algorithm parameters
     *                                                          are not valid
     * @throws java.security.InvalidKeyException the key is not valid
     * @throws javax.crypto.NoSuchPaddingException the padding method is not supported
     * @throws java.io.IOException an I/O exception
     *
     * @see CryptoToolkit#CBC_INITIALIZATION_VECTOR
     */
    public static void decrypt(InputStream dataStream, OutputStream decryptedStream, Key key,
                               String decryptionAlgorithm, String securityProvider)
        throws java.security.NoSuchProviderException,
               java.security.NoSuchAlgorithmException,
               java.security.InvalidAlgorithmParameterException,
               java.security.InvalidKeyException,
               javax.crypto.NoSuchPaddingException,
               java.io.IOException {

        final int blocksInBuffer = 8;

        javax.crypto.Cipher cipher =
            javax.crypto.Cipher.getInstance(decryptionAlgorithm, securityProvider);

        if (decryptionAlgorithm.indexOf(CBC_ID) == -1) {
            cipher.init(javax.crypto.Cipher.DECRYPT_MODE, key);
        } else {
            cipher.init(javax.crypto.Cipher.DECRYPT_MODE, key,
                new IvParameterSpec(CBC_INITIALIZATION_VECTOR));
        }

        javax.crypto.CipherOutputStream cos =
            new javax.crypto.CipherOutputStream(decryptedStream, cipher);

        byte[] buffer = new byte[cipher.getBlockSize() * blocksInBuffer];

        int read = -1;
        while ((read = dataStream.read(buffer)) != -1) {
            cos.write(buffer, 0, read);
        }

        cos.flush();
        cos.close();

        dataStream.close();
    }

    /**
     * Decrypts the given stream contents using the given key and the configured asymmetric
     * algorithm and security provider and writing the decrypted contents in the given output
     * stream. The input and output streams are closed.
     *
     * @param dataStream stream that contains the encrypted data
     * @param decryptedStream stream where to write the decrypted data
     * @param key the decryption key
     *
     * @throws java.security.NoSuchProviderException the security provider is not supported
     * @throws java.security.NoSuchAlgorithmException the decryption algorithm is not supported
     * @throws java.security.InvalidAlgorithmParameterException the decryption algorithm parameters
     *                                                          are not valid
     * @throws java.security.InvalidKeyException the key is not valid
     * @throws javax.crypto.NoSuchPaddingException the padding method is not supported
     * @throws java.io.IOException an I/O exception
     */
    public static void decryptAsymmetric(InputStream dataStream, OutputStream decryptedStream,
                                         Key key)
        throws java.security.NoSuchProviderException,
               java.security.NoSuchAlgorithmException,
               java.security.InvalidAlgorithmParameterException,
               java.security.InvalidKeyException,
               javax.crypto.NoSuchPaddingException,
               java.io.IOException {

        decrypt(dataStream, decryptedStream, key, ASYMMETRIC_ALGORITHM, SECURITY_PROVIDER);
    }

    /**
     * Decrypts the given stream contents using the given key and the configured symmetric algorithm
     * and security provider and writing the decrypted contents in the given output stream. The
     * input and output streams are closed.
     *
     * @param dataStream stream that contains the encrypted data
     * @param decryptedStream stream where to write the decrypted data
     * @param key the decryption key
     *
     * @throws java.security.NoSuchProviderException the security provider is not supported
     * @throws java.security.NoSuchAlgorithmException the decryption algorithm is not supported
     * @throws java.security.InvalidAlgorithmParameterException the decryption algorithm parameters
     *                                                          are not valid
     * @throws java.security.InvalidKeyException the key is not valid
     * @throws javax.crypto.NoSuchPaddingException the padding method is not supported
     * @throws java.io.IOException an I/O exception
     */
    public static void decryptSymmetric(InputStream dataStream, OutputStream decryptedStream,
                                        Key key)
        throws java.security.NoSuchProviderException,
               java.security.NoSuchAlgorithmException,
               java.security.InvalidAlgorithmParameterException,
               java.security.InvalidKeyException,
               javax.crypto.NoSuchPaddingException,
               java.io.IOException {

        decrypt(dataStream, decryptedStream, key, SYMMETRIC_ALGORITHM, SECURITY_PROVIDER);
    }

    /**
     * Encrypts a byte array using the given key, encryption algorithm and security provider.
     *
     * @param data the source data
     * @param key the encryption key
     * @param encryptionAlgorithm the encryption algorithm
     * @param securityProvider the security provider
     *
     * @return the encrypted data
     *
     * @throws java.security.NoSuchProviderException the security provider is not supported
     * @throws java.security.NoSuchAlgorithmException the encryption algorithm is not supported
     * @throws java.security.InvalidAlgorithmParameterException the encryption algorithm parameters
     *                                                          are not valid
     * @throws java.security.InvalidKeyException the key is not valid
     * @throws javax.crypto.NoSuchPaddingException the padding method is not supported
     * @throws java.io.IOException an I/O exception
     *
     * @see CryptoToolkit#CBC_INITIALIZATION_VECTOR
     */
    public static byte[] encrypt(byte[] data, Key key, String encryptionAlgorithm,
                                 String securityProvider)
        throws java.security.NoSuchProviderException,
               java.security.NoSuchAlgorithmException,
               java.security.InvalidAlgorithmParameterException,
               java.security.InvalidKeyException,
               javax.crypto.NoSuchPaddingException,
               java.io.IOException {

        javax.crypto.Cipher cipher =
            javax.crypto.Cipher.getInstance(encryptionAlgorithm, securityProvider);

        if (encryptionAlgorithm.indexOf(CBC_ID) == -1) {
            cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, key);
        } else {
            cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, key,
                new IvParameterSpec(CBC_INITIALIZATION_VECTOR));
        }

        java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
        javax.crypto.CipherOutputStream cos = new javax.crypto.CipherOutputStream(baos, cipher);

        cos.write(data);
        cos.close();

        return baos.toByteArray();
    }

    /**
     * Encrypts a byte array using the given key and the configured asymmetric algorithm and
     * security provider.
     *
     * @param data the source data
     * @param key the encryption key
     *
     * @return the encrypted data
     *
     * @throws java.security.NoSuchProviderException the security provider is not supported
     * @throws java.security.NoSuchAlgorithmException the encryption algorithm is not supported
     * @throws java.security.InvalidAlgorithmParameterException the encryption algorithm parameters
     *                                                          are not valid
     * @throws java.security.InvalidKeyException the key is not valid
     * @throws javax.crypto.NoSuchPaddingException the padding method is not supported
     * @throws java.io.IOException an I/O exception
     *
     * @see CryptoToolkit#ASYMMETRIC_ALGORITHM
     * @see CryptoToolkit#SECURITY_PROVIDER
     */
    public static byte[] encryptAsymmetric(byte[] data, Key key)
        throws java.security.NoSuchProviderException,
               java.security.NoSuchAlgorithmException,
               java.security.InvalidAlgorithmParameterException,
               java.security.InvalidKeyException,
               javax.crypto.NoSuchPaddingException,
               java.io.IOException {

        return encrypt(data, key, ASYMMETRIC_ALGORITHM, SECURITY_PROVIDER);
    }

    /**
     * Encrypts a byte array using the given key and the configured symmetric algorithm and security
     * provider.
     *
     * @param data the source data
     * @param key the encryption key
     *
     * @return the encrypted data
     *
     * @throws java.security.NoSuchProviderException the security provider is not supported
     * @throws java.security.NoSuchAlgorithmException the encryption algorithm is not supported
     * @throws java.security.InvalidAlgorithmParameterException the encryption algorithm parameters
     *                                                          are not valid
     * @throws java.security.InvalidKeyException the key is not valid
     * @throws javax.crypto.NoSuchPaddingException the padding method is not supported
     * @throws java.io.IOException an I/O exception
     *
     * @see CryptoToolkit#SYMMETRIC_ALGORITHM
     * @see CryptoToolkit#SECURITY_PROVIDER
     */
    public static byte[] encryptSymmetric(byte[] data, Key key)
        throws java.security.NoSuchProviderException,
               java.security.NoSuchAlgorithmException,
               java.security.InvalidAlgorithmParameterException,
               java.security.InvalidKeyException,
               javax.crypto.NoSuchPaddingException,
               java.io.IOException {

        return encrypt(data, key, SYMMETRIC_ALGORITHM, SECURITY_PROVIDER);
    }

    /**
     * Encrypts the given stream contents using the given key, encryption algorithm and security
     * provider and writing the encrypted contents in the given output stream. The input and output
     * streams are closed.
     *
     * @param dataStream stream that contains the data
     * @param encryptedStream stream where to write the encrypted data
     * @param key the encryption key
     * @param encryptionAlgorithm the encryption algorithm
     * @param securityProvider the security provider
     *
     * @throws java.security.NoSuchProviderException the security provider is not supported
     * @throws java.security.NoSuchAlgorithmException the decryption algorithm is not supported
     * @throws java.security.InvalidAlgorithmParameterException the encryption algorithm parameters
     *                                                          are not valid
     * @throws java.security.InvalidKeyException the key is not valid
     * @throws javax.crypto.NoSuchPaddingException the padding method is not supported
     * @throws java.io.IOException an I/O exception
     *
     * @see CryptoToolkit#CBC_INITIALIZATION_VECTOR
     */
    public static void encrypt(InputStream dataStream, OutputStream encryptedStream, Key key,
                               String encryptionAlgorithm, String securityProvider)
        throws java.security.NoSuchProviderException,
               java.security.NoSuchAlgorithmException,
               java.security.InvalidAlgorithmParameterException,
               java.security.InvalidKeyException,
               javax.crypto.NoSuchPaddingException,
               java.io.IOException {

        final int blocksInBuffer = 8;

        javax.crypto.Cipher cipher =
            javax.crypto.Cipher.getInstance(encryptionAlgorithm, securityProvider);

        if (encryptionAlgorithm.indexOf(CBC_ID) == -1) {
            cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, key);
        } else {
            cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, key,
                new IvParameterSpec(CBC_INITIALIZATION_VECTOR));
        }

        javax.crypto.CipherOutputStream cos =
            new javax.crypto.CipherOutputStream(encryptedStream, cipher);

        byte[] buffer = new byte[cipher.getBlockSize() * blocksInBuffer];

        int read = -1;
        while ((read = dataStream.read(buffer)) != -1) {
            cos.write(buffer, 0, read);
        }

        cos.flush();
        cos.close();

        dataStream.close();
    }

    /**
     * Encrypts the given stream contents using the given key and the configured asymmetric
     * algorithm and security provider and writing the encrypted contents in the given output
     * stream. The input and output streams are closed.
     *
     * @param dataStream stream that contains the data
     * @param encryptedStream stream where to write the encrypted data
     * @param key the decryption key
     *
     * @throws java.security.NoSuchProviderException the security provider is not supported
     * @throws java.security.NoSuchAlgorithmException the decryption algorithm is not supported
     * @throws java.security.InvalidAlgorithmParameterException the encryption algorithm parameters
     *                                                          are not valid
     * @throws java.security.InvalidKeyException the key is not valid
     * @throws javax.crypto.NoSuchPaddingException the padding method is not supported
     * @throws java.io.IOException an I/O exception
     */
    public static void encryptAsymmetric(InputStream dataStream, OutputStream encryptedStream,
                                         Key key)
        throws java.security.NoSuchProviderException,
               java.security.NoSuchAlgorithmException,
               java.security.InvalidAlgorithmParameterException,
               java.security.InvalidKeyException,
               javax.crypto.NoSuchPaddingException,
               java.io.IOException {

        encrypt(dataStream, encryptedStream, key, ASYMMETRIC_ALGORITHM, SECURITY_PROVIDER);
    }

    /**
     * Encrypts the given stream contents using the given key and the configured symmetric algorithm
     * and security provider and writing the encrypted contents in the given output stream. The
     * input and output streams are closed.
     *
     * @param dataStream stream that contains the data
     * @param encryptedStream stream where to write the encrypted data
     * @param key the decryption key
     *
     * @throws java.security.NoSuchProviderException the security provider is not supported
     * @throws java.security.NoSuchAlgorithmException the decryption algorithm is not supported
     * @throws java.security.InvalidAlgorithmParameterException the encryption algorithm parameters
     *                                                          are not valid
     * @throws java.security.InvalidKeyException the key is not valid
     * @throws javax.crypto.NoSuchPaddingException the padding method is not supported
     * @throws java.io.IOException an I/O exception
     */
    public static void encryptSymmetric(InputStream dataStream, OutputStream encryptedStream,
                                        Key key)
        throws java.security.NoSuchProviderException,
               java.security.NoSuchAlgorithmException,
               java.security.InvalidAlgorithmParameterException,
               java.security.InvalidKeyException,
               javax.crypto.NoSuchPaddingException,
               java.io.IOException {

        encrypt(dataStream, encryptedStream, key, SYMMETRIC_ALGORITHM, SECURITY_PROVIDER);
    }

    /**
     * Generates a PKCS-1 signature using the given hashing algorithm (actually md5 or sha1),
     * encryption algorithm and security provider.
     *
     * @param data the data to be signed
     * @param privateKey the signing key
     * @param hashingAlgorithm the hashing algorithm
     * @param encryptionAlgorithm the encryption algorithm
     * @param securityProvider the security provider
     *
     * @return the PKCS-1 signature
     *
     * @throws java.security.NoSuchProviderException the security provider is not supported
     * @throws java.security.NoSuchAlgorithmException the encryption algorithm is not supported
     * @throws java.security.InvalidAlgorithmParameterException the encryption algorithm parameters
     *                                                          are not valid
     * @throws java.security.InvalidKeyException the key is not valid
     * @throws javax.crypto.NoSuchPaddingException the padding method is not supported
     * @throws java.io.IOException an I/O exception
     *
     * @see CryptoToolkit#MD5_DIGEST_ALGORITHM
     * @see CryptoToolkit#SHA1_DIGEST_ALGORITHM
     */
    public static byte[] signDataPKCS1(byte[] data, PrivateKey privateKey, String hashingAlgorithm,
                                       String encryptionAlgorithm, String securityProvider)
        throws java.security.NoSuchProviderException,
               java.security.NoSuchAlgorithmException,
               java.security.InvalidAlgorithmParameterException,
               java.security.InvalidKeyException,
               javax.crypto.NoSuchPaddingException,
               java.io.IOException {

        byte[] hash = calculateHash(new ByteArrayInputStream(data), hashingAlgorithm);

        byte[] asn1 = ASN1Toolkit.createASN1Signature(hash, hashingAlgorithm);

        return encrypt(asn1, privateKey, encryptionAlgorithm, securityProvider);
    }

    /**
     * Generates a PKCS-1 signature using the configured hashing algorithm, asymmetric encryption
     * algorithm and security provider.
     *
     * @param data the data to be signed
     * @param privateKey the signing key
     *
     * @return the PKCS-1 signature
     *
     * @throws java.security.NoSuchProviderException the security provider is not supported
     * @throws java.security.NoSuchAlgorithmException the encryption algorithm is not supported
     * @throws java.security.InvalidAlgorithmParameterException the encryption algorithm parameters
     *                                                          are not valid
     * @throws java.security.InvalidKeyException the key is not valid
     * @throws javax.crypto.NoSuchPaddingException the padding method is not supported
     * @throws java.io.IOException an I/O exception
     *
     * @see CryptoToolkit#HASHING_ALGORITHM
     * @see CryptoToolkit#ASYMMETRIC_ALGORITHM
     * @see CryptoToolkit#SECURITY_PROVIDER
     */
    public static byte[] signDataPKCS1(byte[] data, PrivateKey privateKey)
        throws java.security.NoSuchProviderException,
               java.security.NoSuchAlgorithmException,
               java.security.InvalidAlgorithmParameterException,
               java.security.InvalidKeyException,
               javax.crypto.NoSuchPaddingException,
               java.io.IOException {

        return signDataPKCS1(data, privateKey, HASHING_ALGORITHM, ASYMMETRIC_ALGORITHM,
                             SECURITY_PROVIDER);
    }

    /**
     * Verifies a PKCS-1 signature using the given decryption algorithm and security provider.<br>
     *
     * A <code>java.lang.IllegalArgumentException</code> exception is thrown if the hash algorithm
     * in signature is not supported.
     *
     * @param signature the PKCS-1 signature
     * @param data the data to be verified
     * @param certificate the signing certificate
     * @param decryptionAlgorithm the decryption algorithm
     * @param securityProvider the security provider
     *
     * @return whether the signature is valid
     *
     * @throws java.security.NoSuchProviderException the security provider is not supported
     * @throws java.security.NoSuchAlgorithmException the decryption algorithm is not supported
     * @throws java.security.InvalidAlgorithmParameterException the decryption algorithm parameters
     *                                                          are not valid
     * @throws java.security.InvalidKeyException the key is not valid
     * @throws javax.crypto.NoSuchPaddingException the padding method is not supported
     * @throws java.io.IOException an I/O exception
     */
    public static boolean verifySignaturePKCS1(byte[] signature, byte[] data,
                                               X509Certificate certificate,
                                               String decryptionAlgorithm, String securityProvider)
        throws java.security.NoSuchProviderException,
               java.security.NoSuchAlgorithmException,
               java.security.InvalidAlgorithmParameterException,
               java.security.InvalidKeyException,
               javax.crypto.NoSuchPaddingException,
               java.io.IOException {

        byte[] decSign =
            decrypt(signature, certificate.getPublicKey(), decryptionAlgorithm, securityProvider);

        ByteArrayInputStream bais = new ByteArrayInputStream(decSign);
        ASN1InputStream a1is = null;
        DERSequence mainSeq = null;

        try {
            a1is = new ASN1InputStream(bais);
        } finally {
            if (a1is != null) {
                a1is.close();
            }
        }

        mainSeq = (DERSequence) a1is.readObject();

        DERSequence idSeq = (DERSequence) mainSeq.getObjectAt(0);
        DERObjectIdentifier objId = (DERObjectIdentifier) idSeq.getObjectAt(0);

        String algorithm = getMappedInvertedHashingAlgorithm(objId.getId());

        ASN1OctetString hashOctet = (ASN1OctetString) mainSeq.getObjectAt(1);
        byte[] hashFromSign = hashOctet.getOctets();
        byte[] hashFromData = calculateHash(new ByteArrayInputStream(data), algorithm);

        if (hashFromData.length != hashFromSign.length) {
            return false;
        }

        for (int i = 0; i < hashFromData.length; i++) {
            if (hashFromData[i] != hashFromSign[i]) {
                return false;
            }
        }

        return true;
    }

    /**
     * Verifies a PKCS-1 signature using the configured asymmetric decryption algorithm and security
     * provider.<br>
     *
     * A <code>java.lang.IllegalArgumentException</code> exception is thrown if the hash algorithm
     * in signature is not supported.
     *
     * @param signature the PKCS-1 signature
     * @param data the data to be verified
     * @param certificate the signing certificate
     *
     * @return whether the signature is valid
     *
     * @throws java.security.NoSuchProviderException the security provider is not supported
     * @throws java.security.NoSuchAlgorithmException the decryption algorithm is not supported
     * @throws java.security.InvalidAlgorithmParameterException the decryption algorithm parameters
     *                                                          are not valid
     * @throws java.security.InvalidKeyException the key is not valid
     * @throws javax.crypto.NoSuchPaddingException the padding method is not supported
     * @throws java.io.IOException an I/O exception
     *
     * @see CryptoToolkit#ASYMMETRIC_ALGORITHM
     * @see CryptoToolkit#SECURITY_PROVIDER
     */
    public static boolean verifySignaturePKCS1(byte[] signature, byte[] data,
                                               X509Certificate certificate)
        throws java.security.NoSuchProviderException,
               java.security.NoSuchAlgorithmException,
               java.security.InvalidAlgorithmParameterException,
               java.security.InvalidKeyException,
               javax.crypto.NoSuchPaddingException,
               java.io.IOException {

        return verifySignaturePKCS1(signature, data, certificate, ASYMMETRIC_ALGORITHM,
                                    SECURITY_PROVIDER);
    }

    /**
     * Generates a PKCS-7 signature using Bouncy Castle security provider, the given hashing
     * algorithm (actually md5 or sha1) and whether to include the data and the signing certificate
     * in the signature.
     *
     * @param data the data to be signed
     * @param certificate the signing certificate
     * @param privateKey the signing key
     * @param algorithm the hashing algorithm
     * @param dataIncluded whether data is included in signature
     * @param certIncluded whether signing certificate is included in signature
     *
     * @return the PKCS-7 signature
     *
     * @throws java.security.NoSuchProviderException the security provider is not supported
     * @throws java.security.NoSuchAlgorithmException the digest algorithm is not supported
     * @throws java.security.InvalidAlgorithmParameterException error creating the certificate store
     * @throws java.security.cert.CertStoreException error creating the certificate store
     * @throws org.bouncycastle.cms.CMSException error creating the signature
     * @throws java.io.IOException an I/O exception
     *
     * @see CryptoToolkit#MD5_DIGEST_ALGORITHM
     * @see CryptoToolkit#SHA1_DIGEST_ALGORITHM
     */
    public static byte[] signDataPKCS7(byte[] data, X509Certificate certificate,
                                       PrivateKey privateKey, String algorithm,
                                       boolean dataIncluded, boolean certIncluded)
        throws java.security.NoSuchProviderException,
               java.security.NoSuchAlgorithmException,
               java.security.InvalidAlgorithmParameterException,
               java.security.cert.CertStoreException,
               org.bouncycastle.cms.CMSException,
               java.io.IOException {

        CMSSignedDataGenerator sdg = new CMSSignedDataGenerator();

        String algorithmId = getMappedHashingAlgorithm(algorithm);

        sdg.addSigner(privateKey, certificate, algorithmId);

        if (certIncluded) {
            ArrayList certs = new ArrayList();
            certs.add(certificate);

            CertStore store =
                CertStore.getInstance(COLLECTION_CERT_STORE,
                    new CollectionCertStoreParameters(certs), SecurityToolkit.BC_SECURITY_PROVIDER);

            sdg.addCertificatesAndCRLs(store);
        }

        CMSProcessableByteArray pba = new CMSProcessableByteArray(data);

        CMSSignedData sd = sdg.generate(pba, dataIncluded, SecurityToolkit.BC_SECURITY_PROVIDER);

        return sd.getEncoded();
    }

    /**
     * Returns a hashing algorithm id for use in Bouncy Castle from the given
     * algorithm in text form.
     *
     * @param algorithm the hashing algorithm in text form
     *
     * @return the hashing algorithm id for use in Bouncy Castle
     *
     * @see CryptoToolkit#MD5_DIGEST_ALGORITHM
     * @see CryptoToolkit#SHA1_DIGEST_ALGORITHM
     */
    private static String getMappedHashingAlgorithm(String algorithm) {

        String algorithmId = null;

        if (algorithm.equalsIgnoreCase(MD5_DIGEST_ALGORITHM)) {
            algorithmId = CMSSignedDataGenerator.DIGEST_MD5;
        } else if (algorithm.equalsIgnoreCase(SHA1_DIGEST_ALGORITHM)) {
            algorithmId = CMSSignedDataGenerator.DIGEST_SHA1;
        } else {
            throw new IllegalArgumentException(SecurityContext.getMessage("CRYPTO_ERR_INVALID_HASH")); //$NON-NLS-1$
        }

        return algorithmId;
    }

    /**
     * Returns a hashing algorithm in text form from the given algorithm
     * id for use in Bouncy Castle.
     *
     * @param algorithmId the hashing algorithm id for use in Bouncy Castle
     *
     * @return the hashing algorithm in text form
     *
     * @see CryptoToolkit#MD5_DIGEST_ALGORITHM
     * @see CryptoToolkit#SHA1_DIGEST_ALGORITHM
     */
    private static String getMappedInvertedHashingAlgorithm(String algorithmId) {

        String algorithm = null;

        if (algorithmId.equals(CMSSignedDataGenerator.DIGEST_MD5)) {
            algorithm = MD5_DIGEST_ALGORITHM;
        } else if (algorithmId.equals(CMSSignedDataGenerator.DIGEST_SHA1)) {
            algorithm = SHA1_DIGEST_ALGORITHM;
        } else {
            throw new IllegalArgumentException(SecurityContext.getMessage("CRYPTO_ERR_INVALID_HASH")); //$NON-NLS-1$
        }

        return algorithm;
    }

    /**
     * Generates a PKCS-7 signature using the configured hashing algorithm without including the
     * data nor the signing certificate in the signature.
     *
     * @param data the data to be signed
     * @param certificate the signing certificate
     * @param privateKey the signing key
     *
     * @return the PKCS-7 signature
     *
     * @throws java.security.NoSuchProviderException the security provider is not supported
     * @throws java.security.NoSuchAlgorithmException the digest algorithm is not supported
     * @throws java.security.InvalidAlgorithmParameterException error creating the certificate store
     * @throws java.security.cert.CertStoreException error creating the certificate store
     * @throws org.bouncycastle.cms.CMSException error creating the signature
     * @throws java.io.IOException an I/O exception
     *
     * @see CryptoToolkit#HASHING_ALGORITHM
     */
    public static byte[] signDataPKCS7(byte[] data, X509Certificate certificate,
                                       PrivateKey privateKey)
        throws java.security.NoSuchProviderException,
               java.security.NoSuchAlgorithmException,
               java.security.InvalidAlgorithmParameterException,
               java.security.cert.CertStoreException,
               org.bouncycastle.cms.CMSException,
               java.io.IOException {

        return signDataPKCS7(data, certificate, privateKey, HASHING_ALGORITHM, false, false);
    }

    /**
     * Verifies a PKCS-7 signature using Bouncy Castle security provider.
     *
     * @param signature the PKCS-7 signature
     * @param data the data to be verified
     * @param certificate the signing certificate
     *
     * @return whether the signature is valid
     *
     * @throws java.security.NoSuchProviderException the security provider is not supported
     * @throws java.security.NoSuchAlgorithmException the digest algorithm is not supported
     * @throws java.security.cert.CertificateNotYetValidException the certificate is not yet valid
     * @throws java.security.cert.CertificateExpiredException the certificate has expired
     * @throws org.bouncycastle.cms.CMSException error reading the signature
     */
    public static boolean verifySignaturePKCS7(byte[] signature, byte[] data,
                                               X509Certificate certificate)
        throws java.security.NoSuchProviderException,
               java.security.NoSuchAlgorithmException,
               java.security.cert.CertificateNotYetValidException,
               java.security.cert.CertificateExpiredException,
               org.bouncycastle.cms.CMSException {

        CMSProcessableByteArray pba = new CMSProcessableByteArray(data);

        CMSSignedData sd = new CMSSignedData(pba, signature);

        SignerInformationStore sis = sd.getSignerInfos();
        Collection c = sis.getSigners();
        Iterator it = c.iterator();

        if (!it.hasNext()) {
            return false;
        }

        SignerInformation signer = (SignerInformation) it.next();

        return signer.verify(certificate, SecurityToolkit.BC_SECURITY_PROVIDER);
    }
}
