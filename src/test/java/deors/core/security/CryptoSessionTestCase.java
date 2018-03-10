package deors.core.security;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertStoreException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Properties;
import java.util.ResourceBundle;

import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import org.bouncycastle.cms.CMSException;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public class CryptoSessionTestCase {

    private static final String NEW_LINE = System.getProperty("line.separator");
    private static final String WIN_NEW_LINE = "\r\n";

    private CryptoSession session = new CryptoSession();

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    public CryptoSessionTestCase() {

        super();
    }

    @BeforeClass
    public static void prepareProdiverBC() {

        SecurityToolkit.prepareProviderBC();
    }

    @AfterClass
    public static void removeProdiverBC() {

        SecurityToolkit.removeProviderBC();
    }

    @Test
    public void testGetSet() {

        CryptoSession s1 = new CryptoSession();

        assertEquals("BC", s1.getSecurityProvider());
        assertEquals("sha1prng", s1.getPrngAlgorithm());
        assertEquals("DESede", s1.getKeyGenAlgorithm());
        assertEquals(24, s1.getKeySizeInBytes());
        assertEquals("md5", s1.getHashingAlgorithm());
        assertEquals("DESede/CBC/PKCS7Padding", s1.getSymmetricAlgorithm());
        assertEquals("RSA/NONE/PKCS1Padding", s1.getAsymmetricAlgorithm());

        s1.setSecurityProvider("sp");
        s1.setPrngAlgorithm("pa");
        s1.setKeyGenAlgorithm("ka");
        s1.setKeySizeInBytes(2);
        s1.setHashingAlgorithm("ha");
        s1.setSymmetricAlgorithm("sa");
        s1.setAsymmetricAlgorithm("aa");

        assertEquals("sp", s1.getSecurityProvider());
        assertEquals("pa", s1.getPrngAlgorithm());
        assertEquals("ka", s1.getKeyGenAlgorithm());
        assertEquals(2, s1.getKeySizeInBytes());
        assertEquals("ha", s1.getHashingAlgorithm());
        assertEquals("sa", s1.getSymmetricAlgorithm());
        assertEquals("aa", s1.getAsymmetricAlgorithm());
    }

    @Test
    public void testCustomSession() {

        CryptoSession s1 = new CryptoSession(
            "sp", "ha", "pa", "ka", 2, "sa", "aa");

        assertEquals("sp", s1.getSecurityProvider());
        assertEquals("pa", s1.getPrngAlgorithm());
        assertEquals("ka", s1.getKeyGenAlgorithm());
        assertEquals(2, s1.getKeySizeInBytes());
        assertEquals("ha", s1.getHashingAlgorithm());
        assertEquals("sa", s1.getSymmetricAlgorithm());
        assertEquals("aa", s1.getAsymmetricAlgorithm());

        CryptoSession s2 = new CryptoSession(s1);
        s2.setKeySizeInBytes(8);

        assertEquals(2, s1.getKeySizeInBytes());
        assertEquals("sp", s2.getSecurityProvider());
        assertEquals("pa", s2.getPrngAlgorithm());
        assertEquals("ka", s2.getKeyGenAlgorithm());
        assertEquals(8, s2.getKeySizeInBytes());
        assertEquals("ha", s2.getHashingAlgorithm());
        assertEquals("sa", s2.getSymmetricAlgorithm());
        assertEquals("aa", s2.getAsymmetricAlgorithm());

        s1.setKeySizeInBytes(16);
        assertEquals(16, s1.getKeySizeInBytes());
        assertEquals(8, s2.getKeySizeInBytes());
    }

    @Test
    public void testInvalidSession() {

        CryptoSession s1 = new CryptoSession(
            null, null, null, null, 0, null, null);

        assertEquals("BC", s1.getSecurityProvider());
        assertEquals("sha1prng", s1.getPrngAlgorithm());
        assertEquals("DESede", s1.getKeyGenAlgorithm());
        assertEquals(24, s1.getKeySizeInBytes());
        assertEquals("md5", s1.getHashingAlgorithm());
        assertEquals("DESede/CBC/PKCS7Padding", s1.getSymmetricAlgorithm());
        assertEquals("RSA/NONE/PKCS1Padding", s1.getAsymmetricAlgorithm());
    }

    @Test
    public void testBundleSession() {

        ResourceBundle bundle = ResourceBundle.getBundle("session");
        CryptoSession s1 = new CryptoSession(bundle);

        assertEquals("sp", s1.getSecurityProvider());
        assertEquals("pa", s1.getPrngAlgorithm());
        assertEquals("ka", s1.getKeyGenAlgorithm());
        assertEquals(2, s1.getKeySizeInBytes());
        assertEquals("ha", s1.getHashingAlgorithm());
        assertEquals("sa", s1.getSymmetricAlgorithm());
        assertEquals("aa", s1.getAsymmetricAlgorithm());
    }

    @Test
    public void testBundleSessionInvalid() {

        ResourceBundle bundle = ResourceBundle.getBundle("invalidsession");
        CryptoSession s1 = new CryptoSession(bundle);

        assertEquals("BC", s1.getSecurityProvider());
        assertEquals("sha1prng", s1.getPrngAlgorithm());
        assertEquals("DESede", s1.getKeyGenAlgorithm());
        assertEquals(24, s1.getKeySizeInBytes());
        assertEquals("md5", s1.getHashingAlgorithm());
        assertEquals("DESede/CBC/PKCS7Padding", s1.getSymmetricAlgorithm());
        assertEquals("RSA/NONE/PKCS1Padding", s1.getAsymmetricAlgorithm());
    }

    @Test
    public void testBundleSessionInvalidNumber() {

        ResourceBundle bundle = ResourceBundle.getBundle("invalidnumber");
        CryptoSession s1 = new CryptoSession(bundle);

        assertEquals("sp", s1.getSecurityProvider());
        assertEquals("pa", s1.getPrngAlgorithm());
        assertEquals("ka", s1.getKeyGenAlgorithm());
        assertEquals(24, s1.getKeySizeInBytes());
        assertEquals("ha", s1.getHashingAlgorithm());
        assertEquals("sa", s1.getSymmetricAlgorithm());
        assertEquals("aa", s1.getAsymmetricAlgorithm());
    }

    @Test
    public void testPropertiesSession()
        throws IOException {

        Properties prop = new Properties();
        prop.load(this.getClass().getResourceAsStream("/session.properties"));
        CryptoSession s1 = new CryptoSession(prop);

        assertEquals("sp", s1.getSecurityProvider());
        assertEquals("pa", s1.getPrngAlgorithm());
        assertEquals("ka", s1.getKeyGenAlgorithm());
        assertEquals(2, s1.getKeySizeInBytes());
        assertEquals("ha", s1.getHashingAlgorithm());
        assertEquals("sa", s1.getSymmetricAlgorithm());
        assertEquals("aa", s1.getAsymmetricAlgorithm());
    }

    @Test
    public void testPropertiesSessionInvalid()
        throws IOException {

        Properties prop = new Properties();
        prop.load(this.getClass().getResourceAsStream("/invalidsession.properties"));
        CryptoSession s1 = new CryptoSession(prop);

        assertEquals("BC", s1.getSecurityProvider());
        assertEquals("sha1prng", s1.getPrngAlgorithm());
        assertEquals("DESede", s1.getKeyGenAlgorithm());
        assertEquals(24, s1.getKeySizeInBytes());
        assertEquals("md5", s1.getHashingAlgorithm());
        assertEquals("DESede/CBC/PKCS7Padding", s1.getSymmetricAlgorithm());
        assertEquals("RSA/NONE/PKCS1Padding", s1.getAsymmetricAlgorithm());
    }

    @Test
    public void testPropertiesSessionInvalidNumber()
        throws IOException {

        Properties prop = new Properties();
        prop.load(this.getClass().getResourceAsStream("/invalidnumber.properties"));
        CryptoSession s1 = new CryptoSession(prop);

        assertEquals("sp", s1.getSecurityProvider());
        assertEquals("pa", s1.getPrngAlgorithm());
        assertEquals("ka", s1.getKeyGenAlgorithm());
        assertEquals(24, s1.getKeySizeInBytes());
        assertEquals("ha", s1.getHashingAlgorithm());
        assertEquals("sa", s1.getSymmetricAlgorithm());
        assertEquals("aa", s1.getAsymmetricAlgorithm());
    }

    @Test
    public void testCalculateHashNull()
        throws IOException, NoSuchAlgorithmException {

        thrown.expect(NullPointerException.class);

        session.calculateHash((InputStream) null);
    }

    @Test
    public void testCalculateHash()
        throws IOException, NoSuchAlgorithmException {

        InputStream is = this.getClass().getResourceAsStream("/samplefile.txt");
        byte[] hash = session.calculateHash(is);
        assertNotNull(hash);
        byte[] expected;
        if (NEW_LINE.equals(WIN_NEW_LINE)) {
            expected = new byte[] {
                54, 16, 65, -53, 72, -47, -125, -111, 87, 59, 42, 54, 44, -121, 49, 55
            };
        } else {
            expected = new byte[] {
                    -30, -83, 32, -36, -2, -93, -1, 45, 99, -101, -36, -11, -46, 54, -25, -95
            };
        }
        assertArrayEquals(expected, hash);
    }

    @Test
    public void testCalculateHashFileNull()
        throws IOException, NoSuchAlgorithmException {

        thrown.expect(NullPointerException.class);

        session.calculateHash((File) null);
    }

    @Test
    public void testCalculateHashFile()
        throws IOException, URISyntaxException, NoSuchAlgorithmException {

        URL url = this.getClass().getResource("/samplefile.txt");
        File f = new File(url.toURI());
        byte[] hash = session.calculateHash(f);
        assertNotNull(hash);
        byte[] expected;

        if (NEW_LINE.equals(WIN_NEW_LINE)) {
                expected = new byte[] {
                    54, 16, 65, -53, 72, -47, -125, -111, 87, 59, 42, 54, 44, -121, 49, 55
            };
        } else {
                expected = new byte[] {
                        -30, -83, 32, -36, -2, -93, -1, 45, 99, -101, -36, -11, -46, 54, -25, -95
                    };
        }

        assertArrayEquals(expected, hash);
    }

    @Test
    public void testCalculateHashStringNull()
        throws IOException, NoSuchAlgorithmException {

        thrown.expect(NullPointerException.class);

        session.calculateHashString((InputStream) null);
    }

    @Test
    public void testCalculateHashString()
        throws IOException, NoSuchAlgorithmException {

        InputStream is = this.getClass().getResourceAsStream("/samplefile.txt");
        String hash = session.calculateHashString(is);
        assertNotNull(hash);
        String expected;
        if (NEW_LINE.equals(WIN_NEW_LINE)) {
            expected = "361041CB48D18391573B2A362C873137";
        } else {
                expected = "E2AD20DCFEA3FF2D639BDCF5D236E7A1";
        }

        assertEquals(expected, hash);
    }

    @Test
    public void testCalculateHashStringFileNull()
        throws IOException, NoSuchAlgorithmException {

        thrown.expect(NullPointerException.class);

        session.calculateHashString((File) null);
    }

    @Test
    public void testCalculateHashStringFile()
        throws IOException, URISyntaxException, NoSuchAlgorithmException {

        URL url = this.getClass().getResource("/samplefile.txt");
        File f = new File(url.toURI());
        String hash = session.calculateHashString(f);
        assertNotNull(hash);
        String expected;
        if (NEW_LINE.equals(WIN_NEW_LINE))
                expected = "361041CB48D18391573B2A362C873137";
        else
                expected = "E2AD20DCFEA3FF2D639BDCF5D236E7A1";

        assertEquals(expected, hash);
    }

    @Test
    public void testCreateSymmetric()
        throws NoSuchAlgorithmException, NoSuchProviderException {

        SecretKey key = session.createSymmetricKey();
        assertNotNull(key);
    }

    @Test
    public void testCreateSymmetricFromKey()
        throws NoSuchAlgorithmException, NoSuchProviderException {

        SecretKey key = session.createSymmetricKey();
        assertNotNull(key);
        SecretKey key2 = session.createSymmetricKey(key.getEncoded());
        assertNotNull(key2);
        assertEquals(key, key2);
    }

    @Test
    public void testEncryptDecryptSymmetric()
        throws NoSuchAlgorithmException, NoSuchProviderException, IOException,
               NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {

        SecretKey key = session.createSymmetricKey();
        byte[] data = new byte[] {
            -97, 91, -72, -127, -33, 76, 6, 89, -100, -15,
            -110, 26, -34, 41, 9, 22, 109, 16, 60, -2
        };
        byte[] enc = session.encryptSymmetric(data, key);
        assertNotNull(enc);

        byte[] dec = session.decryptSymmetric(enc, key);
        assertArrayEquals(data, dec);
    }

    @Test
    public void testEncryptDecryptAsymmetric()
        throws CertificateException, KeyStoreException, UnrecoverableKeyException,
               IOException, NoSuchAlgorithmException, NoSuchProviderException,
               NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {

        KeyStore ks = CertificateToolkit.readJKSKeyStore(
            this.getClass().getResourceAsStream("/certificate3.jks"), "changeit".toCharArray());
        X509Certificate cert = (X509Certificate) ks.getCertificate("jorge.hidalgo");
        Key publicKey = cert.getPublicKey();
        Key privateKey = ks.getKey("jorge.hidalgo", "changeit".toCharArray());
        byte[] data = new byte[] {
            -97, 91, -72, -127, -33, 76, 6, 89, -100, -15,
            -110, 26, -34, 41, 9, 22, 109, 16, 60, -2
        };
        byte[] enc = session.encryptAsymmetric(data, privateKey);
        assertNotNull(enc);

        byte[] dec = session.decryptAsymmetric(enc, publicKey);
        assertArrayEquals(data, dec);
    }

    @Test
    public void testEncryptDecryptStreamsSymmetric()
        throws NoSuchAlgorithmException, NoSuchProviderException, IOException,
               NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {

        SecretKey key = session.createSymmetricKey();
        byte[] data = new byte[] {
            -97, 91, -72, -127, -33, 76, 6, 89, -100, -15,
            -110, 26, -34, 41, 9, 22, 109, 16, 60, -2
        };
        ByteArrayInputStream bais = new ByteArrayInputStream(data);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        session.encryptSymmetric(bais, baos, key);
        byte[] enc = baos.toByteArray();
        assertNotNull(enc);

        bais = new ByteArrayInputStream(enc);
        baos = new ByteArrayOutputStream();
        session.decryptSymmetric(bais, baos, key);
        byte[] dec = baos.toByteArray();
        assertArrayEquals(data, dec);
    }

    @Test
    public void testEncryptDecryptStreamsAsymmetric()
        throws CertificateException, KeyStoreException, UnrecoverableKeyException,
               IOException, NoSuchAlgorithmException, NoSuchProviderException,
               NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {

        KeyStore ks = CertificateToolkit.readJKSKeyStore(
            this.getClass().getResourceAsStream("/certificate3.jks"), "changeit".toCharArray());
        X509Certificate cert = (X509Certificate) ks.getCertificate("jorge.hidalgo");
        Key publicKey = cert.getPublicKey();
        Key privateKey = ks.getKey("jorge.hidalgo", "changeit".toCharArray());
        byte[] data = new byte[] {
            -97, 91, -72, -127, -33, 76, 6, 89, -100, -15,
            -110, 26, -34, 41, 9, 22, 109, 16, 60, -2
        };
        ByteArrayInputStream bais = new ByteArrayInputStream(data);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        session.encryptAsymmetric(bais, baos, privateKey);
        byte[] enc = baos.toByteArray();
        assertNotNull(enc);

        bais = new ByteArrayInputStream(enc);
        baos = new ByteArrayOutputStream();
        session.decryptAsymmetric(bais, baos, publicKey);
        byte[] dec = baos.toByteArray();
        assertArrayEquals(data, dec);
    }

    @Test
    public void testSignVerifyPKCS1()
        throws CertificateException, KeyStoreException, UnrecoverableKeyException,
               IOException,NoSuchAlgorithmException, NoSuchProviderException,
               NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {

        KeyStore ks = CertificateToolkit.readJKSKeyStore(
            this.getClass().getResourceAsStream("/certificate3.jks"), "changeit".toCharArray());
        X509Certificate cert = (X509Certificate) ks.getCertificate("jorge.hidalgo");
        PrivateKey privateKey = (PrivateKey) ks.getKey("jorge.hidalgo", "changeit".toCharArray());
        byte[] data = new byte[] {
            -97, 91, -72, -127, -33, 76, 6, 89, -100, -15,
            -110, 26, -34, 41, 9, 22, 109, 16, 60, -2
        };
        byte[] signature = session.signDataPKCS1(data, privateKey);
        assertNotNull(signature);

        assertTrue(session.verifySignaturePKCS1(signature, data, cert));
    }

    @Test
    public void testSignVerifyPKCS7()
        throws CertificateException, KeyStoreException, UnrecoverableKeyException,
               IOException,NoSuchAlgorithmException, NoSuchProviderException, CMSException,
               CertStoreException, InvalidAlgorithmParameterException {

        String alias = "12d7d9ce-22e1-4b44-9186-12df32a9cd71";
        KeyStore ks = CertificateToolkit.readPKCS12KeyStore(
            this.getClass().getResourceAsStream("/certificate6.p12"), "1234".toCharArray());
        X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
        PrivateKey privateKey = (PrivateKey) ks.getKey(alias, "1234".toCharArray());
        assertNotNull(privateKey);

        byte[] data = new byte[] {
            -97, 91, -72, -127, -33, 76, 6, 89, -100, -15,
            -110, 26, -34, 41, 9, 22, 109, 16, 60, -2
        };
        byte[] signature = session.signDataPKCS7(data, cert, privateKey);
        assertNotNull(signature);

        assertTrue(session.verifySignaturePKCS7(signature, data, cert));
    }

    @Test
    public void testSignVerifyPKCS7Alternate()
        throws CertificateException, KeyStoreException, UnrecoverableKeyException,
               IOException,NoSuchAlgorithmException, NoSuchProviderException, CMSException,
               CertStoreException, InvalidAlgorithmParameterException {

        String alias = "12d7d9ce-22e1-4b44-9186-12df32a9cd71";
        KeyStore ks = CertificateToolkit.readPKCS12KeyStore(
            this.getClass().getResourceAsStream("/certificate6.p12"), "1234".toCharArray());
        X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
        PrivateKey privateKey = (PrivateKey) ks.getKey(alias, "1234".toCharArray());
        assertNotNull(privateKey);

        byte[] data = new byte[] {
            -97, 91, -72, -127, -33, 76, 6, 89, -100, -15,
            -110, 26, -34, 41, 9, 22, 109, 16, 60, -2
        };
        byte[] signature = session.signDataPKCS7(data, cert, privateKey, true, true);
        assertNotNull(signature);

        assertTrue(session.verifySignaturePKCS7(signature, data, cert));
    }
}
