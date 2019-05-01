package deors.core.security;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.MissingResourceException;
import java.util.Properties;
import java.util.ResourceBundle;

import javax.crypto.SecretKey;

/**
 * Implementation of a cryptographic session based on a set of properties that defines the
 * algorithms and other settings used in the cryptographic operations.
 *
 * @author deors
 * @version 1.0
 */
public final class CryptoSession {

    /**
     * Security provider. Its default value is <code>CryptoToolkit.SECURITY_PROVIDER</code>.
     *
     * @see CryptoSession#getSecurityProvider()
     * @see CryptoSession#setSecurityProvider(String)
     * @see CryptoToolkit#SECURITY_PROVIDER
     */
    private String securityProvider;

    /**
     * Digest algorithm used for message digests. Its default value is
     * <code>CryptoToolkit.DIGEST_ALGORITHM</code>.
     *
     * @see CryptoSession#getDigestAlgorithm()
     * @see CryptoSession#setDigestAlgorithm(String)
     * @see CryptoToolkit#DIGEST_ALGORITHM
     */
    private String digestAlgorithm;

    /**
     * Hashing algorithm used for message digests. Its default value is
     * <code>CryptoToolkit.HASHING_ALGORITHM</code>.
     *
     * @see CryptoSession#getHashingAlgorithm()
     * @see CryptoSession#setHashingAlgorithm(String)
     * @see CryptoToolkit#HASHING_ALGORITHM
     */
    private String hashingAlgorithm;

    /**
     * Pseudo-random number generation algorithm. Its default value is
     * <code>CryptoToolkit.PRNG_ALGORITHM</code>.
     *
     * @see CryptoSession#getPrngAlgorithm()
     * @see CryptoSession#setPrngAlgorithm(String)
     * @see CryptoToolkit#PRNG_ALGORITHM
     */
    private String prngAlgorithm;

    /**
     * Key generation algorithm. Its default value is <code>CryptoToolkit.KEY_GEN_ALGORITHM</code>.
     *
     * @see CryptoSession#getKeyGenAlgorithm()
     * @see CryptoSession#setKeyGenAlgorithm(String)
     * @see CryptoToolkit#KEY_GEN_ALGORITHM
     */
    private String keyGenAlgorithm;

    /**
     * Key size in bytes. Its default value is <code>CryptoToolkit.KEY_SIZE_IN_BYTES</code>.
     *
     * @see CryptoSession#getKeySizeInBytes()
     * @see CryptoSession#setKeySizeInBytes(int)
     * @see CryptoToolkit#KEY_SIZE_IN_BYTES
     */
    private int keySizeInBytes = -1;

    /**
     * Symmetric encryption/decryption algorithm. Its default value is
     * <code>CryptoToolkit.SYMMETRIC_ALGORITHM</code>.
     *
     * @see CryptoSession#getSymmetricAlgorithm()
     * @see CryptoSession#setSymmetricAlgorithm(String)
     * @see CryptoToolkit#SYMMETRIC_ALGORITHM
     */
    private String symmetricAlgorithm;

    /**
     * Asymmetric encryption/decryption algorithm. Its default value is
     * <code>CryptoToolkit.ASYMMETRIC_ALGORITHM</code>.
     *
     * @see CryptoSession#getAsymmetricAlgorithm()
     * @see CryptoSession#setAsymmetricAlgorithm(String)
     * @see CryptoToolkit#ASYMMETRIC_ALGORITHM
     */
    private String asymmetricAlgorithm;

    /**
     * Constructor that sets session properties using the configured values in the
     * <code>CryptoToolkit</code> class.
     *
     * @see CryptoToolkit#SECURITY_PROVIDER
     * @see CryptoToolkit#HASHING_ALGORITHM
     * @see CryptoToolkit#PRNG_ALGORITHM
     * @see CryptoToolkit#KEY_GEN_ALGORITHM
     * @see CryptoToolkit#KEY_SIZE_IN_BYTES
     * @see CryptoToolkit#SYMMETRIC_ALGORITHM
     * @see CryptoToolkit#ASYMMETRIC_ALGORITHM
     */
    public CryptoSession() {

        super();

        this.securityProvider = CryptoToolkit.SECURITY_PROVIDER;
        this.digestAlgorithm = CryptoToolkit.DIGEST_ALGORITHM;
        this.hashingAlgorithm = CryptoToolkit.HASHING_ALGORITHM;
        this.prngAlgorithm = CryptoToolkit.PRNG_ALGORITHM;
        this.keyGenAlgorithm = CryptoToolkit.KEY_GEN_ALGORITHM;
        this.keySizeInBytes = CryptoToolkit.KEY_SIZE_IN_BYTES;
        this.symmetricAlgorithm = CryptoToolkit.SYMMETRIC_ALGORITHM;
        this.asymmetricAlgorithm = CryptoToolkit.ASYMMETRIC_ALGORITHM;
    }

    /**
     * Constructor that sets session properties using the given
     * <code>java.util.ResourceBundle</code> object. The expected key names are the same required
     * in the <code>CryptoToolkit</code> class. If one property is missing, the configured value
     * for this property is used.
     *
     * @param bundle the resource bundle
     *
     * @see CryptoToolkit#KN_SECURITY_PROVIDER
     * @see CryptoToolkit#KN_DIGEST_ALGORITHM
     * @see CryptoToolkit#KN_HASHING_ALGORITHM
     * @see CryptoToolkit#KN_PRNG_ALGORITHM
     * @see CryptoToolkit#KN_KEY_GEN_ALGORITHM
     * @see CryptoToolkit#KN_KEY_SIZE_IN_BYTES
     * @see CryptoToolkit#KN_SYMMETRIC_ALGORITHM
     * @see CryptoToolkit#KN_ASYMMETRIC_ALGORITHM
     * @see CryptoToolkit#SECURITY_PROVIDER
     * @see CryptoToolkit#DIGEST_ALGORITHM
     * @see CryptoToolkit#HASHING_ALGORITHM
     * @see CryptoToolkit#PRNG_ALGORITHM
     * @see CryptoToolkit#KEY_GEN_ALGORITHM
     * @see CryptoToolkit#KEY_SIZE_IN_BYTES
     * @see CryptoToolkit#SYMMETRIC_ALGORITHM
     * @see CryptoToolkit#ASYMMETRIC_ALGORITHM
     */
    public CryptoSession(ResourceBundle bundle) {

        super();

        try {
            this.securityProvider = bundle.getString(CryptoToolkit.KN_SECURITY_PROVIDER);
        } catch (MissingResourceException mre) {
            this.securityProvider = CryptoToolkit.SECURITY_PROVIDER;
        }

        try {
            this.digestAlgorithm = bundle.getString(CryptoToolkit.KN_DIGEST_ALGORITHM);
        } catch (MissingResourceException mre) {
            this.digestAlgorithm = CryptoToolkit.DIGEST_ALGORITHM;
        }

        try {
            this.hashingAlgorithm = bundle.getString(CryptoToolkit.KN_HASHING_ALGORITHM);
        } catch (MissingResourceException mre) {
            this.hashingAlgorithm = CryptoToolkit.HASHING_ALGORITHM;
        }

        try {
            this.prngAlgorithm = bundle.getString(CryptoToolkit.KN_PRNG_ALGORITHM);
        } catch (MissingResourceException mre) {
            this.prngAlgorithm = CryptoToolkit.PRNG_ALGORITHM;
        }

        try {
            this.keyGenAlgorithm = bundle.getString(CryptoToolkit.KN_KEY_GEN_ALGORITHM);
        } catch (MissingResourceException mre) {
            this.keyGenAlgorithm = CryptoToolkit.KEY_GEN_ALGORITHM;
        }

        try {
            this.keySizeInBytes =
                Integer.parseInt(bundle.getString(CryptoToolkit.KN_KEY_SIZE_IN_BYTES));
        } catch (MissingResourceException | NumberFormatException e) {
            this.keySizeInBytes = CryptoToolkit.KEY_SIZE_IN_BYTES;
        }

        try {
            this.symmetricAlgorithm = bundle.getString(CryptoToolkit.KN_SYMMETRIC_ALGORITHM);
        } catch (MissingResourceException mre) {
            this.symmetricAlgorithm = CryptoToolkit.SYMMETRIC_ALGORITHM;
        }

        try {
            this.asymmetricAlgorithm = bundle.getString(CryptoToolkit.KN_ASYMMETRIC_ALGORITHM);
        } catch (MissingResourceException mre) {
            this.asymmetricAlgorithm = CryptoToolkit.ASYMMETRIC_ALGORITHM;
        }
    }

    /**
     * Constructor that sets session properties from the given <code>java.util.Properties</code>
     * object. The expected key names are the same required in the <code>CryptoToolkit</code>
     * class. If one property is missing, the configured value for this property is used.
     *
     * @param properties the properties collection
     *
     * @see CryptoToolkit#KN_SECURITY_PROVIDER
     * @see CryptoToolkit#KN_DIGEST_ALGORITHM
     * @see CryptoToolkit#KN_HASHING_ALGORITHM
     * @see CryptoToolkit#KN_PRNG_ALGORITHM
     * @see CryptoToolkit#KN_KEY_GEN_ALGORITHM
     * @see CryptoToolkit#KN_KEY_SIZE_IN_BYTES
     * @see CryptoToolkit#KN_SYMMETRIC_ALGORITHM
     * @see CryptoToolkit#KN_ASYMMETRIC_ALGORITHM
     * @see CryptoToolkit#SECURITY_PROVIDER
     * @see CryptoToolkit#DIGEST_ALGORITHM
     * @see CryptoToolkit#HASHING_ALGORITHM
     * @see CryptoToolkit#PRNG_ALGORITHM
     * @see CryptoToolkit#KEY_GEN_ALGORITHM
     * @see CryptoToolkit#KEY_SIZE_IN_BYTES
     * @see CryptoToolkit#SYMMETRIC_ALGORITHM
     * @see CryptoToolkit#ASYMMETRIC_ALGORITHM
     */
    public CryptoSession(Properties properties) {

        super();

        this.securityProvider = properties.getProperty(
            CryptoToolkit.KN_SECURITY_PROVIDER,
            CryptoToolkit.SECURITY_PROVIDER);

        this.digestAlgorithm = properties.getProperty(
            CryptoToolkit.KN_DIGEST_ALGORITHM,
            CryptoToolkit.DIGEST_ALGORITHM);

        this.hashingAlgorithm = properties.getProperty(
            CryptoToolkit.KN_HASHING_ALGORITHM,
            CryptoToolkit.HASHING_ALGORITHM);

        this.prngAlgorithm = properties.getProperty(
            CryptoToolkit.KN_PRNG_ALGORITHM,
            CryptoToolkit.PRNG_ALGORITHM);

        this.keyGenAlgorithm = properties.getProperty(
            CryptoToolkit.KN_KEY_GEN_ALGORITHM,
            CryptoToolkit.KEY_GEN_ALGORITHM);

        try {
            this.keySizeInBytes = Integer.parseInt(properties.getProperty(
                CryptoToolkit.KN_KEY_SIZE_IN_BYTES,
                Integer.toString(CryptoToolkit.KEY_SIZE_IN_BYTES)));
        } catch (NumberFormatException nfe) {
            this.keySizeInBytes = CryptoToolkit.KEY_SIZE_IN_BYTES;
        }

        this.symmetricAlgorithm = properties.getProperty(
            CryptoToolkit.KN_SYMMETRIC_ALGORITHM,
            CryptoToolkit.SYMMETRIC_ALGORITHM);

        this.asymmetricAlgorithm = properties.getProperty(
            CryptoToolkit.KN_ASYMMETRIC_ALGORITHM,
            CryptoToolkit.ASYMMETRIC_ALGORITHM);
    }

    /**
     * Constructor that sets session properties from the given <code>CryptoSession</code> object.
     * The source session string properties are cloned, not referenced.
     *
     * @param sourceSession the source session
     */
    public CryptoSession(CryptoSession sourceSession) {

        super();

        this.securityProvider = sourceSession.securityProvider;
        this.digestAlgorithm = sourceSession.digestAlgorithm;
        this.hashingAlgorithm = sourceSession.hashingAlgorithm;
        this.prngAlgorithm = sourceSession.prngAlgorithm;
        this.keyGenAlgorithm = sourceSession.keyGenAlgorithm;
        this.keySizeInBytes = sourceSession.keySizeInBytes;
        this.symmetricAlgorithm = sourceSession.symmetricAlgorithm;
        this.asymmetricAlgorithm = sourceSession.asymmetricAlgorithm;
    }

    /**
     * Constructor that sets the session properties from the given parameters. The parameters are
     * referenced in the new session. If a string property is null or its length is zero, the
     * configured value for this property is used. If the given key size is less than 1, the
     * configured value for this property is used.
     *
     * @param securityProvider the security provider
     * @param digestAlgorithm the digest algorithm for message digests
     * @param hashingAlgorithm the hashing algorithm for message digests
     * @param prngAlgorithm the pseudo-random number generation algorithm
     * @param keyGenAlgorithm the key generation algorithm
     * @param keySizeInBytes the key size in bytes
     * @param symmetricAlgorithm the symmetric encryption/decryption algorithm
     * @param asymmetricAlgorithm the asymmetric encryption/decryption algorithm
     *
     * @see CryptoToolkit#SECURITY_PROVIDER
     * @see CryptoToolkit#DIGEST_ALGORITHM
     * @see CryptoToolkit#HASHING_ALGORITHM
     * @see CryptoToolkit#PRNG_ALGORITHM
     * @see CryptoToolkit#KEY_GEN_ALGORITHM
     * @see CryptoToolkit#KEY_SIZE_IN_BYTES
     * @see CryptoToolkit#SYMMETRIC_ALGORITHM
     * @see CryptoToolkit#ASYMMETRIC_ALGORITHM
     */
    public CryptoSession(String securityProvider, String digestAlgorithm,
                         String hashingAlgorithm, String prngAlgorithm,
                         String keyGenAlgorithm, int keySizeInBytes,
                         String symmetricAlgorithm, String asymmetricAlgorithm) {

        super();

        this.securityProvider = securityProvider;
        this.digestAlgorithm = digestAlgorithm;
        this.hashingAlgorithm = hashingAlgorithm;
        this.prngAlgorithm = prngAlgorithm;
        this.keyGenAlgorithm = keyGenAlgorithm;
        this.keySizeInBytes = keySizeInBytes;
        this.symmetricAlgorithm = symmetricAlgorithm;
        this.asymmetricAlgorithm = asymmetricAlgorithm;

        if (this.securityProvider == null || this.securityProvider.length() == 0) {
            this.securityProvider = CryptoToolkit.SECURITY_PROVIDER;
        }

        if (this.digestAlgorithm == null || this.digestAlgorithm.length() == 0) {
            this.digestAlgorithm = CryptoToolkit.DIGEST_ALGORITHM;
        }

        if (this.hashingAlgorithm == null || this.hashingAlgorithm.length() == 0) {
            this.hashingAlgorithm = CryptoToolkit.HASHING_ALGORITHM;
        }

        if (this.prngAlgorithm == null || this.prngAlgorithm.length() == 0) {
            this.prngAlgorithm = CryptoToolkit.PRNG_ALGORITHM;
        }

        if (this.keyGenAlgorithm == null || this.keyGenAlgorithm.length() == 0) {
            this.keyGenAlgorithm = CryptoToolkit.KEY_GEN_ALGORITHM;
        }

        if (this.keySizeInBytes < 1) {
            this.keySizeInBytes = CryptoToolkit.KEY_SIZE_IN_BYTES;
        }

        if (this.symmetricAlgorithm == null || this.symmetricAlgorithm.length() == 0) {
            this.symmetricAlgorithm = CryptoToolkit.SYMMETRIC_ALGORITHM;
        }

        if (this.asymmetricAlgorithm == null || this.asymmetricAlgorithm.length() == 0) {
            this.asymmetricAlgorithm = CryptoToolkit.ASYMMETRIC_ALGORITHM;
        }
    }

    /**
     * Returns the <code>securityProvider</code> property value.
     *
     * @return the property value
     *
     * @see CryptoSession#securityProvider
     * @see CryptoSession#setSecurityProvider(String)
     */
    public String getSecurityProvider() {
        return securityProvider;
    }

    /**
     * Returns the <code>digestAlgorithm</code> property value.
     *
     * @return the property value
     *
     * @see CryptoSession#digestAlgorithm
     * @see CryptoSession#setDigestAlgorithm(String)
     */
    public String getDigestAlgorithm() {
        return digestAlgorithm;
    }

    /**
     * Returns the <code>hashingAlgorithm</code> property value.
     *
     * @return the property value
     *
     * @see CryptoSession#hashingAlgorithm
     * @see CryptoSession#setHashingAlgorithm(String)
     */
    public String getHashingAlgorithm() {
        return hashingAlgorithm;
    }

    /**
     * Returns the <code>prngAlgorithm</code> property value.
     *
     * @return the property value
     *
     * @see CryptoSession#prngAlgorithm
     * @see CryptoSession#setPrngAlgorithm(String)
     */
    public String getPrngAlgorithm() {
        return prngAlgorithm;
    }

    /**
     * Returns the <code>keyGenAlgorithm</code> property value.
     *
     * @return the property value
     *
     * @see CryptoSession#keyGenAlgorithm
     * @see CryptoSession#setKeyGenAlgorithm(String)
     */
    public String getKeyGenAlgorithm() {
        return keyGenAlgorithm;
    }

    /**
     * Returns the <code>keySizeInBytes</code> property value.
     *
     * @return the property value
     *
     * @see CryptoSession#keySizeInBytes
     * @see CryptoSession#setKeySizeInBytes(int)
     */
    public int getKeySizeInBytes() {
        return keySizeInBytes;
    }

    /**
     * Returns the <code>symmetricAlgorithm</code> property value.
     *
     * @return the property value
     *
     * @see CryptoSession#symmetricAlgorithm
     * @see CryptoSession#setSymmetricAlgorithm(String)
     */
    public String getSymmetricAlgorithm() {
        return symmetricAlgorithm;
    }

    /**
     * Returns the <code>asymmetricAlgorithm</code> property value.
     *
     * @return the property value
     *
     * @see CryptoSession#asymmetricAlgorithm
     * @see CryptoSession#setAsymmetricAlgorithm(String)
     */
    public String getAsymmetricAlgorithm() {
        return asymmetricAlgorithm;
    }

    /**
     * Changes the <code>securityProvider</code> property.
     *
     * @param securityProvider the property new value
     *
     * @see CryptoSession#securityProvider
     * @see CryptoSession#getSecurityProvider()
     */
    public void setSecurityProvider(String securityProvider) {
        this.securityProvider = securityProvider;
    }

    /**
     * Changes the <code>digestAlgorithm</code> property.
     *
     * @param digestAlgorithm the property new value
     *
     * @see CryptoSession#digestAlgorithm
     * @see CryptoSession#getDigestAlgorithm()
     */
    public void setDigestAlgorithm(String digestAlgorithm) {
        this.digestAlgorithm = digestAlgorithm;
    }

    /**
     * Changes the <code>hashingAlgorithm</code> property.
     *
     * @param hashingAlgorithm the property new value
     *
     * @see CryptoSession#hashingAlgorithm
     * @see CryptoSession#getHashingAlgorithm()
     */
    public void setHashingAlgorithm(String hashingAlgorithm) {
        this.hashingAlgorithm = hashingAlgorithm;
    }

    /**
     * Changes the <code>prngAlgorithm</code> property.
     *
     * @param prngAlgorithm the property new value
     *
     * @see CryptoSession#prngAlgorithm
     * @see CryptoSession#getPrngAlgorithm()
     */
    public void setPrngAlgorithm(String prngAlgorithm) {
        this.prngAlgorithm = prngAlgorithm;
    }

    /**
     * Changes the <code>keyGenAlgorithm</code> property.
     *
     * @param keyGenAlgorithm the property new value
     *
     * @see CryptoSession#keyGenAlgorithm
     * @see CryptoSession#getKeyGenAlgorithm()
     */
    public void setKeyGenAlgorithm(String keyGenAlgorithm) {
        this.keyGenAlgorithm = keyGenAlgorithm;
    }

    /**
     * Changes the <code>keySizeInBytes</code> property.
     *
     * @param keySizeInBytes the property new value
     *
     * @see CryptoSession#keySizeInBytes
     * @see CryptoSession#getKeySizeInBytes()
     */
    public void setKeySizeInBytes(int keySizeInBytes) {
        this.keySizeInBytes = keySizeInBytes;
    }

    /**
     * Changes the <code>symmetricAlgorithm</code> property.
     *
     * @param symmetricAlgorithm the property new value
     *
     * @see CryptoSession#symmetricAlgorithm
     * @see CryptoSession#getSymmetricAlgorithm()
     */
    public void setSymmetricAlgorithm(String symmetricAlgorithm) {
        this.symmetricAlgorithm = symmetricAlgorithm;
    }

    /**
     * Changes the <code>asymmetricAlgorithm</code> property.
     *
     * @param asymmetricAlgorithm the property new value
     *
     * @see CryptoSession#asymmetricAlgorithm
     * @see CryptoSession#getAsymmetricAlgorithm()
     */
    public void setAsymmetricAlgorithm(String asymmetricAlgorithm) {
        this.asymmetricAlgorithm = asymmetricAlgorithm;
    }

    /**
     * Calculates the stream contents hash using the session hashing algorithm.
     *
     * @param is the source stream
     *
     * @return the hash
     *
     * @throws java.io.IOException an I/O exception
     * @throws java.security.NoSuchAlgorithmException the hashing algorithm is not supported
     *
     * @see CryptoToolkit#calculateHash(java.io.InputStream, String)
     */
    public byte[] calculateHash(java.io.InputStream is)
        throws java.io.IOException,
               java.security.NoSuchAlgorithmException {

        return CryptoToolkit.calculateHash(is, hashingAlgorithm);
    }

    /**
     * Calculates the file contents hash using the session hashing algorithm.
     *
     * @param file the source file
     *
     * @return the hash
     *
     * @throws java.io.IOException an I/O exception
     * @throws java.security.NoSuchAlgorithmException the hashing algorithm is not supported
     *
     * @see CryptoToolkit#calculateHash(java.io.File, String)
     */
    public byte[] calculateHash(java.io.File file)
        throws java.io.IOException,
               java.security.NoSuchAlgorithmException {

        return CryptoToolkit.calculateHash(file, hashingAlgorithm);
    }

    /**
     * Calculates the stream contents hash using the session hashing algorithm and returns it as an
     * hexadecimal string.
     *
     * @param is the source stream
     *
     * @return the hash as an hexadecimal string
     *
     * @throws java.io.IOException an I/O exception
     * @throws java.security.NoSuchAlgorithmException the hashing algorithm is not supported
     *
     * @see CryptoToolkit#calculateHashString(java.io.InputStream, String)
     */
    public String calculateHashString(java.io.InputStream is)
        throws java.io.IOException,
               java.security.NoSuchAlgorithmException {

        return CryptoToolkit.calculateHashString(is, hashingAlgorithm);
    }

    /**
     * Calculates the file contents hash using the session hashing algorithm and returns it as an
     * hexadecimal string.
     *
     * @param file the source file
     *
     * @return the hash as an hexadecimal string
     *
     * @throws java.io.IOException an I/O exception
     * @throws java.security.NoSuchAlgorithmException the hashing algorithm is not supported
     *
     * @see CryptoToolkit#calculateHashString(java.io.File, String)
     */
    public String calculateHashString(java.io.File file)
        throws java.io.IOException,
               java.security.NoSuchAlgorithmException {

        return CryptoToolkit.calculateHashString(file, hashingAlgorithm);
    }

    /**
     * Creates and returns a symmetric key using the session pseudo-random number generation
     * algorithm, key generation algorithm, key size and security provider.
     *
     * @return the generated key
     *
     * @throws java.security.NoSuchProviderException the security provider is not supported
     * @throws java.security.NoSuchAlgorithmException the pseudo-random number generation algorithm
     *         is not supported
     *
     * @see CryptoToolkit#createSymmetricKey(String, String, int, String)
     */
    public SecretKey createSymmetricKey()
        throws java.security.NoSuchProviderException,
               java.security.NoSuchAlgorithmException {

        return CryptoToolkit.createSymmetricKey(prngAlgorithm, keyGenAlgorithm, keySizeInBytes,
                                                securityProvider);
    }

    /**
     * Returns a symmetric key constructed from the given byte array using the session key
     * generation algorithm.
     *
     * @param sourceKey the source key
     *
     * @return the constructed key
     *
     * @see CryptoToolkit#createSymmetricKey(byte[], String)
     */
    public SecretKey createSymmetricKey(byte[] sourceKey) {

        return CryptoToolkit.createSymmetricKey(sourceKey, keyGenAlgorithm);
    }

    /**
     * Decrypts a byte array using the given key and the session asymmetric algorithm and security
     * provider.
     *
     * @param data the encrypted data
     * @param key the decryption key
     *
     * @return the decrypted data
     *
     * @throws java.io.IOException an I/O exception
     * @throws java.security.NoSuchProviderException the security provider is not supported
     * @throws java.security.NoSuchAlgorithmException the decryption algorithm is not supported
     * @throws java.security.InvalidAlgorithmParameterException the decryption algorithm parameters
     *                                                          are not valid
     * @throws java.security.InvalidKeyException the key is not valid
     * @throws javax.crypto.NoSuchPaddingException the padding method is not supported
     *
     * @see CryptoToolkit#decrypt(byte[], java.security.Key, String, String)
     */
    public byte[] decryptAsymmetric(byte[] data, Key key)
        throws java.io.IOException,
               java.security.NoSuchProviderException,
               java.security.NoSuchAlgorithmException,
               java.security.InvalidAlgorithmParameterException,
               java.security.InvalidKeyException,
               javax.crypto.NoSuchPaddingException {

        return CryptoToolkit.decrypt(data, key, asymmetricAlgorithm, securityProvider);
    }

    /**
     * Decrypts a byte array using the given key and the session symmetric algorithm and security
     * provider.
     *
     * @param data the encrypted data
     * @param key the decryption key
     *
     * @return the decrypted data
     *
     * @throws java.io.IOException an I/O exception
     * @throws java.security.NoSuchProviderException the security provider is not supported
     * @throws java.security.NoSuchAlgorithmException the decryption algorithm is not supported
     * @throws java.security.InvalidAlgorithmParameterException the decryption algorithm parameters
     *                                                          are not valid
     * @throws java.security.InvalidKeyException the key is not valid
     * @throws javax.crypto.NoSuchPaddingException the padding method is not supported
     *
     * @see CryptoToolkit#decrypt(byte[], java.security.Key, String, String)
     */
    public byte[] decryptSymmetric(byte[] data, Key key)
        throws java.io.IOException,
               java.security.NoSuchProviderException,
               java.security.NoSuchAlgorithmException,
               java.security.InvalidAlgorithmParameterException,
               java.security.InvalidKeyException,
               javax.crypto.NoSuchPaddingException {

        return CryptoToolkit.decrypt(data, key, symmetricAlgorithm, securityProvider);
    }

    /**
     * Decrypts the given stream contents using the given key and the session asymmetric algorithm
     * and security provider and writing the decrypted contents in the given output stream. The
     * input and output streams are closed.
     *
     * @param dataStream stream that contains the encrypted data
     * @param decryptedStream stream where to write the decrypted data
     * @param key the decryption key
     *
     * @throws java.io.IOException an I/O exception
     * @throws java.security.NoSuchProviderException the security provider is not supported
     * @throws java.security.NoSuchAlgorithmException the decryption algorithm is not supported
     * @throws java.security.InvalidAlgorithmParameterException the decryption algorithm parameters
     *                                                          are not valid
     * @throws java.security.InvalidKeyException the key is not valid
     * @throws javax.crypto.NoSuchPaddingException the padding method is not supported
     *
     * @see CryptoToolkit#decrypt(InputStream, OutputStream, Key, String, String)
     */
    public void decryptAsymmetric(InputStream dataStream, OutputStream decryptedStream, Key key)
        throws java.io.IOException,
               java.security.NoSuchProviderException,
               java.security.NoSuchAlgorithmException,
               java.security.InvalidAlgorithmParameterException,
               java.security.InvalidKeyException,
               javax.crypto.NoSuchPaddingException {

        CryptoToolkit.decrypt(dataStream, decryptedStream, key, asymmetricAlgorithm,
                              securityProvider);
    }

    /**
     * Decrypts the given stream contents using the given key and the session symmetric algorithm
     * and security provider and writing the decrypted contents in the given output stream. The
     * input and output streams are closed.
     *
     * @param dataStream stream that contains the encrypted data
     * @param decryptedStream stream where to write the decrypted data
     * @param key the decryption key
     *
     * @throws java.io.IOException an I/O exception
     * @throws java.security.NoSuchProviderException the security provider is not supported
     * @throws java.security.NoSuchAlgorithmException the decryption algorithm is not supported
     * @throws java.security.InvalidAlgorithmParameterException the decryption algorithm parameters
     *                                                          are not valid
     * @throws java.security.InvalidKeyException the key is not valid
     * @throws javax.crypto.NoSuchPaddingException the padding method is not supported
     *
     * @see CryptoToolkit#decrypt(InputStream, OutputStream, Key, String, String)
     */
    public void decryptSymmetric(InputStream dataStream, OutputStream decryptedStream, Key key)
        throws java.io.IOException,
               java.security.NoSuchProviderException,
               java.security.NoSuchAlgorithmException,
               java.security.InvalidAlgorithmParameterException,
               java.security.InvalidKeyException,
               javax.crypto.NoSuchPaddingException {

        CryptoToolkit.decrypt(dataStream, decryptedStream, key, symmetricAlgorithm,
                              securityProvider);
    }

    /**
     * Encrypts a byte array using the given key and the session asymmetric algorithm and security
     * provider.
     *
     * @param data the source data
     * @param key the encryption key
     *
     * @return the encrypted data
     *
     * @throws java.io.IOException an I/O exception
     * @throws java.security.NoSuchProviderException the security provider is not supported
     * @throws java.security.NoSuchAlgorithmException the encryption algorithm is not supported
     * @throws java.security.InvalidAlgorithmParameterException the encryption algorithm parameters
     *                                                          are not valid
     * @throws java.security.InvalidKeyException the key is not valid
     * @throws javax.crypto.NoSuchPaddingException the padding method is not supported
     *
     * @see CryptoToolkit#encrypt(byte[], java.security.Key, String, String)
     */
    public byte[] encryptAsymmetric(byte[] data, Key key)
        throws java.io.IOException,
               java.security.NoSuchProviderException,
               java.security.NoSuchAlgorithmException,
               java.security.InvalidAlgorithmParameterException,
               java.security.InvalidKeyException,
               javax.crypto.NoSuchPaddingException {

        return CryptoToolkit.encrypt(data, key, asymmetricAlgorithm, securityProvider);
    }

    /**
     * Encrypts a byte array using the given key and the session symmetric algorithm and security
     * provider.
     *
     * @param data the source data
     * @param key the encryption key
     *
     * @return the encrypted data
     *
     * @throws java.io.IOException an I/O exception
     * @throws java.security.NoSuchProviderException the security provider is not supported
     * @throws java.security.NoSuchAlgorithmException the encryption algorithm is not supported
     * @throws java.security.InvalidAlgorithmParameterException the encryption algorithm parameters
     *                                                          are not valid
     * @throws java.security.InvalidKeyException the key is not valid
     * @throws javax.crypto.NoSuchPaddingException the padding method is not supported
     *
     * @see CryptoToolkit#encrypt(byte[], java.security.Key, String, String)
     */
    public byte[] encryptSymmetric(byte[] data, Key key)
        throws java.io.IOException,
               java.security.NoSuchProviderException,
               java.security.NoSuchAlgorithmException,
               java.security.InvalidAlgorithmParameterException,
               java.security.InvalidKeyException,
               javax.crypto.NoSuchPaddingException {

        return CryptoToolkit.encrypt(data, key, symmetricAlgorithm, securityProvider);
    }

    /**
     * Encrypts the given stream contents using the given key and the session asymmetric algorithm
     * and security provider and writing the encrypted contents in the given output stream. The
     * input and output streams are closed.
     *
     * @param dataStream stream that contains the data
     * @param encryptedStream stream where to write the encrypted data
     * @param key the decryption key
     *
     * @throws java.io.IOException an I/O exception
     * @throws java.security.NoSuchProviderException the security provider is not supported
     * @throws java.security.NoSuchAlgorithmException the encryption algorithm is not supported
     * @throws java.security.InvalidAlgorithmParameterException the encryption algorithm parameters
     *                                                          are not valid
     * @throws java.security.InvalidKeyException the key is not valid
     * @throws java.security.cert.CertificateEncodingException error with certificate encoding
     * @throws javax.crypto.NoSuchPaddingException the padding method is not supported
     *
     * @see CryptoToolkit#encrypt(InputStream, OutputStream, Key, String, String)
     */
    public void encryptAsymmetric(InputStream dataStream, OutputStream encryptedStream, Key key)
        throws java.io.IOException,
               java.security.NoSuchProviderException,
               java.security.NoSuchAlgorithmException,
               java.security.InvalidAlgorithmParameterException,
               java.security.InvalidKeyException,
               java.security.cert.CertificateEncodingException,
               javax.crypto.NoSuchPaddingException {

        CryptoToolkit.encrypt(dataStream, encryptedStream, key, asymmetricAlgorithm,
                              securityProvider);
    }

    /**
     * Encrypts the given stream contents using the given key and the session symmetric algorithm
     * and security provider and writing the encrypted contents in the given output stream. The
     * input and output streams are closed.
     *
     * @param dataStream stream that contains the data
     * @param encryptedStream stream where to write the encrypted data
     * @param key the decryption key
     *
     * @throws java.io.IOException an I/O exception
     * @throws java.security.NoSuchProviderException the security provider is not supported
     * @throws java.security.NoSuchAlgorithmException the encryption algorithm is not supported
     * @throws java.security.InvalidAlgorithmParameterException the encryption algorithm parameters
     *                                                          are not valid
     * @throws java.security.InvalidKeyException the key is not valid
     * @throws java.security.cert.CertificateEncodingException error with certificate encoding
     * @throws javax.crypto.NoSuchPaddingException the padding method is not supported
     *
     * @see CryptoToolkit#encrypt(InputStream, OutputStream, Key, String, String)
     */
    public void encryptSymmetric(InputStream dataStream, OutputStream encryptedStream, Key key)
        throws java.io.IOException,
               java.security.NoSuchProviderException,
               java.security.NoSuchAlgorithmException,
               java.security.InvalidAlgorithmParameterException,
               java.security.InvalidKeyException,
               java.security.cert.CertificateEncodingException,
               javax.crypto.NoSuchPaddingException {

        CryptoToolkit.encrypt(dataStream, encryptedStream, key, symmetricAlgorithm,
                              securityProvider);
    }

    /**
     * Generates a PKCS-1 signature using the session hashing algorithm, asymmetric encryption
     * algorithm and security provider.
     *
     * @param data the data to be signed
     * @param privateKey the signing key
     *
     * @return the PKCS-1 signature
     *
     * @throws java.io.IOException an I/O exception
     * @throws java.security.NoSuchProviderException the security provider is not supported
     * @throws java.security.NoSuchAlgorithmException the encryption algorithm is not supported
     * @throws java.security.InvalidAlgorithmParameterException the encryption algorithm parameters
     *                                                          are not valid
     * @throws java.security.InvalidKeyException the key is not valid
     * @throws javax.crypto.NoSuchPaddingException the padding method is not supported
     *
     * @see CryptoToolkit#signDataPKCS1(byte[], java.security.PrivateKey, String, String, String)
     */
    public byte[] signDataPKCS1(byte[] data, PrivateKey privateKey)
        throws java.io.IOException,
               java.security.NoSuchProviderException,
               java.security.NoSuchAlgorithmException,
               java.security.InvalidAlgorithmParameterException,
               java.security.InvalidKeyException,
               javax.crypto.NoSuchPaddingException {

        return CryptoToolkit.signDataPKCS1(data, privateKey, hashingAlgorithm, asymmetricAlgorithm,
                                           securityProvider);
    }

    /**
     * Verifies a PKCS-1 signature using the session asymmetric decryption algorithm and security
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
     * @throws java.io.IOException an I/O exception
     * @throws java.security.NoSuchProviderException the security provider is not supported
     * @throws java.security.NoSuchAlgorithmException the decryption algorithm is not supported
     * @throws java.security.InvalidAlgorithmParameterException the decryption algorithm parameters
     *                                                          are not valid
     * @throws java.security.InvalidKeyException the key is not valid
     * @throws javax.crypto.NoSuchPaddingException the padding method is not supported
     *
     * @see CryptoToolkit#verifySignaturePKCS1(byte[], byte[], java.security.cert.X509Certificate,
     *      String, String)
     */
    public boolean verifySignaturePKCS1(byte[] signature, byte[] data, X509Certificate certificate)
        throws java.io.IOException,
               java.security.NoSuchProviderException,
               java.security.NoSuchAlgorithmException,
               java.security.InvalidAlgorithmParameterException,
               java.security.InvalidKeyException,
               javax.crypto.NoSuchPaddingException {

        return CryptoToolkit.verifySignaturePKCS1(signature, data, certificate,
                                                  asymmetricAlgorithm, securityProvider);
    }

    /**
     * Generates a PKCS-7 signature using the session digest algorithm and whether
     * to include the data and the signing certificate in the signature.
     *
     * @param data the data to be signed
     * @param certificate the signing certificate
     * @param privateKey the signing key
     * @param dataIncluded whether data is included in signature
     * @param certIncluded whether signing certificate is included in signature
     *
     * @return the PKCS-7 signature
     *
     * @throws java.io.IOException an I/O exception
     * @throws java.security.NoSuchProviderException the security provider is not supported
     * @throws java.security.cert.CertificateEncodingException error with certificate encoding
     * @throws java.security.cert.CertStoreException error creating the certificate store
     * @throws org.bouncycastle.cms.CMSException the signature could not be created
     * @throws org.bouncycastle.operator.OperatorCreationException error creating the operator
     *
     * @see CryptoToolkit#signDataPKCS7(byte[], X509Certificate, PrivateKey)
     */
    public byte[] signDataPKCS7(byte[] data, X509Certificate certificate, PrivateKey privateKey,
                                boolean dataIncluded, boolean certIncluded)
        throws java.io.IOException,
               java.security.NoSuchProviderException,
               java.security.cert.CertificateEncodingException,
               java.security.cert.CertStoreException,
               org.bouncycastle.cms.CMSException,
               org.bouncycastle.operator.OperatorCreationException {

        return CryptoToolkit.signDataPKCS7(data, certificate, privateKey, digestAlgorithm,
                                           dataIncluded, certIncluded);
    }

    /**
     * Generates a PKCS-7 signature using the session digest algorithm without
     * including the data nor the signing certificate in the signature.
     *
     * @param data the data to be signed
     * @param certificate the signing certificate
     * @param privateKey the signing key
     *
     * @return the PKCS-7 signature
     *
     * @throws java.io.IOException an I/O exception
     * @throws java.security.NoSuchProviderException the security provider is not supported
     * @throws java.security.cert.CertificateEncodingException error with certificate encoding
     * @throws java.security.cert.CertStoreException error creating the certificate store
     * @throws org.bouncycastle.cms.CMSException the signature could not be created
     * @throws org.bouncycastle.operator.OperatorCreationException error creating the operator
     *
     * @see CryptoToolkit#signDataPKCS7(byte[], java.security.cert.X509Certificate,
     *      java.security.PrivateKey, String, boolean, boolean)
     */
    public byte[] signDataPKCS7(byte[] data, X509Certificate certificate, PrivateKey privateKey)
        throws java.io.IOException,
               java.security.NoSuchProviderException,
               java.security.cert.CertificateEncodingException,
               java.security.cert.CertStoreException,
               org.bouncycastle.cms.CMSException,
               org.bouncycastle.operator.OperatorCreationException {

        return CryptoToolkit.signDataPKCS7(data, certificate, privateKey, digestAlgorithm,
                                           false, false);
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
     * @throws java.io.IOException an I/O exception
     * @throws java.security.NoSuchProviderException the security provider is not supported
     * @throws java.security.cert.CertificateNotYetValidException the certificate is not yet valid
     * @throws java.security.cert.CertificateExpiredException the certificate has expired
     * @throws org.bouncycastle.cms.CMSException the signature could not be created
     * @throws org.bouncycastle.operator.OperatorCreationException error creating the operator
     *
     * @see CryptoToolkit#verifySignaturePKCS7(byte[], byte[], java.security.cert.X509Certificate)
     */
    public boolean verifySignaturePKCS7(byte[] signature, byte[] data, X509Certificate certificate)
        throws java.io.IOException,
               java.security.NoSuchProviderException,
               java.security.cert.CertificateNotYetValidException,
               java.security.cert.CertificateExpiredException,
               org.bouncycastle.cms.CMSException,
               org.bouncycastle.operator.OperatorCreationException {

        return CryptoToolkit.verifySignaturePKCS7(signature, data, certificate);
    }
}
