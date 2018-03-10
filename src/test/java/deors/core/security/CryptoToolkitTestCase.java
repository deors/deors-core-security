package deors.core.security;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
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
import java.util.ArrayList;
import java.util.List;

import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import org.bouncycastle.cms.CMSException;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import deors.core.commons.StringToolkit;

public class CryptoToolkitTestCase {

    private static final String NEW_LINE = System.getProperty("line.separator");
    private static final String WIN_NEW_LINE = "\r\n";

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    public CryptoToolkitTestCase() {

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
    public void testCalculateHashNull()
        throws IOException, NoSuchAlgorithmException {

        thrown.expect(NullPointerException.class);

        CryptoToolkit.calculateHash((InputStream) null);
    }

    @Test
    public void testCalculateHash()
        throws IOException, NoSuchAlgorithmException {

        InputStream is = this.getClass().getResourceAsStream("/samplefile.txt");
        byte[] hash = CryptoToolkit.calculateHash(is);
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
    public void testCalculateHashAlternate()
        throws IOException, NoSuchAlgorithmException {

        InputStream is = this.getClass().getResourceAsStream("/samplefile.txt");
        byte[] hash = CryptoToolkit.calculateHash(is, CryptoToolkit.SHA1_DIGEST_ALGORITHM);
        assertNotNull(hash);
        byte[] expected;
        if (NEW_LINE.equals(WIN_NEW_LINE)) {
                expected = new byte[] {
                -97, 91, -72, -127, -33, 76, 6, 89, -100, -15,
                -110, 26, -34, 41, 9, 22, 109, 16, 60, -2
            };
        } else {
                expected = new byte[] {
                        -114, 109, -119, -54, -127, -84, 99, -76, -108,
                        19, -118, 22, 86, 52, -46, -21, -28, 19, 2, -29
            };
        }
        assertArrayEquals(expected, hash);
    }

    @Test
    public void testCalculateHashInvalid()
        throws IOException, NoSuchAlgorithmException {

        thrown.expect(NoSuchAlgorithmException.class);

        InputStream is = this.getClass().getResourceAsStream("/samplefile.txt");
        CryptoToolkit.calculateHash(is, "invalid");
    }

    @Test
    public void testCalculateHashFileNull()
        throws IOException, NoSuchAlgorithmException {

        thrown.expect(NullPointerException.class);

        CryptoToolkit.calculateHash((File) null);
    }

    @Test
    public void testCalculateHashFile()
        throws IOException, URISyntaxException, NoSuchAlgorithmException {

        URL url = this.getClass().getResource("/samplefile.txt");
        File f = new File(url.toURI());
        byte[] hash = CryptoToolkit.calculateHash(f);
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
    public void testCalculateHashFileAlternate()
        throws IOException, URISyntaxException, NoSuchAlgorithmException {

        URL url = this.getClass().getResource("/samplefile.txt");
        File f = new File(url.toURI());
        byte[] hash = CryptoToolkit.calculateHash(f, CryptoToolkit.SHA1_DIGEST_ALGORITHM);
        assertNotNull(hash);
        byte[] expected;
        if (NEW_LINE.equals(WIN_NEW_LINE)) {
                expected = new byte[] {
                -97, 91, -72, -127, -33, 76, 6, 89, -100, -15,
                -110, 26, -34, 41, 9, 22, 109, 16, 60, -2
            };
        } else {
                expected = new byte[] {
                        -114, 109, -119, -54, -127, -84, 99, -76, -108,
                    19, -118, 22, 86, 52, -46, -21, -28, 19, 2, -29
                };
        }

        assertArrayEquals(expected, hash);
    }

    @Test
    public void testCalculateHashFileInvalid()
        throws IOException, URISyntaxException, NoSuchAlgorithmException {

        thrown.expect(NoSuchAlgorithmException.class);

        URL url = this.getClass().getResource("/samplefile.txt");
        File f = new File(url.toURI());
        CryptoToolkit.calculateHash(f, "invalid");
    }

    @Test
    public void testCalculateHashStringNull()
        throws IOException, NoSuchAlgorithmException {

        thrown.expect(NullPointerException.class);

        CryptoToolkit.calculateHashString((InputStream) null);
    }

    @Test
    public void testCalculateHashString()
        throws IOException, NoSuchAlgorithmException {

        InputStream is = this.getClass().getResourceAsStream("/samplefile.txt");
        String hash = CryptoToolkit.calculateHashString(is);
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
    public void testCalculateHashStringAlternate()
        throws IOException, NoSuchAlgorithmException {

        InputStream is = this.getClass().getResourceAsStream("/samplefile.txt");
        String hash = CryptoToolkit.calculateHashString(is, CryptoToolkit.SHA1_DIGEST_ALGORITHM);
        assertNotNull(hash);
        String expected;
        if (NEW_LINE.equals(WIN_NEW_LINE)) {
                expected = "9F5BB881DF4C06599CF1921ADE2909166D103CFE";
        } else {
                expected = "8E6D89CA81AC63B494138A165634D2EBE41302E3";
        }
        assertEquals(expected, hash);
    }

    @Test
    public void testCalculateHashStringInvalid()
        throws IOException, NoSuchAlgorithmException {

        thrown.expect(NoSuchAlgorithmException.class);

        InputStream is = this.getClass().getResourceAsStream("/samplefile.txt");
        CryptoToolkit.calculateHashString(is, "invalid");
    }

    @Test
    public void testCalculateHashStringFileNull()
        throws IOException, NoSuchAlgorithmException {

        thrown.expect(NullPointerException.class);

        CryptoToolkit.calculateHashString((File) null);
    }

    @Test
    public void testCalculateHashStringFile()
        throws IOException, URISyntaxException, NoSuchAlgorithmException {

        URL url = this.getClass().getResource("/samplefile.txt");
        File f = new File(url.toURI());
        String hash = CryptoToolkit.calculateHashString(f);
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
    public void testCalculateHashStringFileAlternate()
        throws IOException, URISyntaxException, NoSuchAlgorithmException {

        URL url = this.getClass().getResource("/samplefile.txt");
        File f = new File(url.toURI());
        String hash = CryptoToolkit.calculateHashString(f, CryptoToolkit.SHA1_DIGEST_ALGORITHM);
        assertNotNull(hash);
        String expected;
        if (NEW_LINE.equals(WIN_NEW_LINE)) {
                expected = "9F5BB881DF4C06599CF1921ADE2909166D103CFE";
        } else {
                expected = "8E6D89CA81AC63B494138A165634D2EBE41302E3";
        }
        assertEquals(expected, hash);
    }

    @Test
    public void testCalculateHashStringFileInvalid()
        throws IOException, URISyntaxException, NoSuchAlgorithmException {

        thrown.expect(NoSuchAlgorithmException.class);

        URL url = this.getClass().getResource("/samplefile.txt");
        File f = new File(url.toURI());
        CryptoToolkit.calculateHashString(f, "invalid");
    }

    @Test
    public void testCreateSymmetric()
        throws NoSuchAlgorithmException, NoSuchProviderException {

        SecretKey key = CryptoToolkit.createSymmetricKey();
        assertNotNull(key);
        SecretKey key2 = CryptoToolkit.createSymmetricKey();
        assertNotNull(key2);
        assertFalse(key.equals(key2));
    }

    @Test
    public void testCreateSymmetricStress()
        throws NoSuchAlgorithmException, NoSuchProviderException {

        List<SecretKey> keys = new ArrayList<SecretKey>();
        int total = 50;
        for (int i = 0; i < total; i++) {
            SecretKey key = CryptoToolkit.createSymmetricKey();
            keys.add(key);
            System.out.println(StringToolkit.asHexadecimalString(key.getEncoded()));
        }

        for (int i = 0; i < total; i++) {
            SecretKey key1 = keys.get(i);
            SecretKey key2 = i == total - 1 ? keys.get(0) : keys.get(i + 1);
            assertFalse("same keys generated", key1.equals(key2));
        }
    }

    @Test
    public void testCreateSymmetricAlternate()
        throws NoSuchAlgorithmException, NoSuchProviderException {

        SecretKey key = CryptoToolkit.createSymmetricKey("sha1prng", "DESede", 24, "BC");
        assertNotNull(key);
        SecretKey key2 = CryptoToolkit.createSymmetricKey("sha1prng", "DESede", 16, "BC");
        assertNotNull(key2);
        assertFalse(key.equals(key2));
    }

    @Test
    public void testCreateSymmetricFromKey()
        throws NoSuchAlgorithmException, NoSuchProviderException {

        SecretKey key = CryptoToolkit.createSymmetricKey();
        assertNotNull(key);
        SecretKey key2 = CryptoToolkit.createSymmetricKey(key.getEncoded());
        assertNotNull(key2);
        assertEquals(key, key2);
    }

    @Test
    public void testCreateSymmetricFromKeyAlternate()
        throws NoSuchAlgorithmException, NoSuchProviderException {

        SecretKey key = CryptoToolkit.createSymmetricKey();
        assertNotNull(key);
        SecretKey key2 = CryptoToolkit.createSymmetricKey(key.getEncoded(), "DES");
        assertNotNull(key2);
        assertFalse(key.equals(key2));
    }

    @Test
    public void testCreateSymmetricInvalidProvider()
        throws NoSuchAlgorithmException, NoSuchProviderException {

        thrown.expect(NoSuchProviderException.class);

        CryptoToolkit.createSymmetricKey("sha1prng", "DESede", 24, "invalid");
    }

    @Test
    public void testEncryptDecrypt()
        throws NoSuchAlgorithmException, NoSuchProviderException, IOException,
               NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {

        SecretKey key = CryptoToolkit.createSymmetricKey();
        byte[] data = new byte[] {
            -97, 91, -72, -127, -33, 76, 6, 89, -100, -15,
            -110, 26, -34, 41, 9, 22, 109, 16, 60, -2
        };
        byte[] enc = CryptoToolkit.encrypt(data, key, "DESede/CBC/PKCS7Padding", "BC");
        assertNotNull(enc);

        byte[] dec = CryptoToolkit.decrypt(enc, key, "DESede/CBC/PKCS7Padding", "BC");
        assertArrayEquals(data, dec);
    }

    @Test
    public void testEncryptDecryptSymmetric()
        throws NoSuchAlgorithmException, NoSuchProviderException, IOException,
               NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {

        SecretKey key = CryptoToolkit.createSymmetricKey();
        byte[] data = new byte[] {
            -97, 91, -72, -127, -33, 76, 6, 89, -100, -15,
            -110, 26, -34, 41, 9, 22, 109, 16, 60, -2
        };
        byte[] enc = CryptoToolkit.encryptSymmetric(data, key);
        assertNotNull(enc);

        byte[] dec = CryptoToolkit.decryptSymmetric(enc, key);
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
        byte[] enc = CryptoToolkit.encryptAsymmetric(data, privateKey);
        assertNotNull(enc);

        byte[] dec = CryptoToolkit.decryptAsymmetric(enc, publicKey);
        assertArrayEquals(data, dec);
    }

    @Test
    public void testEncryptDecryptStreams()
        throws NoSuchAlgorithmException, NoSuchProviderException, IOException,
               NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {

        SecretKey key = CryptoToolkit.createSymmetricKey();
        byte[] data = new byte[] {
            -97, 91, -72, -127, -33, 76, 6, 89, -100, -15,
            -110, 26, -34, 41, 9, 22, 109, 16, 60, -2
        };
        ByteArrayInputStream bais = new ByteArrayInputStream(data);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        CryptoToolkit.encrypt(bais, baos, key, "DESede/CBC/PKCS7Padding", "BC");
        byte[] enc = baos.toByteArray();
        assertNotNull(enc);

        bais = new ByteArrayInputStream(enc);
        baos = new ByteArrayOutputStream();
        CryptoToolkit.decrypt(bais, baos, key, "DESede/CBC/PKCS7Padding", "BC");
        byte[] dec = baos.toByteArray();
        assertArrayEquals(data, dec);
    }

    @Test
    public void testEncryptDecryptStreamsSymmetric()
        throws NoSuchAlgorithmException, NoSuchProviderException, IOException,
               NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {

        SecretKey key = CryptoToolkit.createSymmetricKey();
        byte[] data = new byte[] {
            -97, 91, -72, -127, -33, 76, 6, 89, -100, -15,
            -110, 26, -34, 41, 9, 22, 109, 16, 60, -2
        };
        ByteArrayInputStream bais = new ByteArrayInputStream(data);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        CryptoToolkit.encryptSymmetric(bais, baos, key);
        byte[] enc = baos.toByteArray();
        assertNotNull(enc);

        bais = new ByteArrayInputStream(enc);
        baos = new ByteArrayOutputStream();
        CryptoToolkit.decryptSymmetric(bais, baos, key);
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
        CryptoToolkit.encryptAsymmetric(bais, baos, privateKey);
        byte[] enc = baos.toByteArray();
        assertNotNull(enc);

        bais = new ByteArrayInputStream(enc);
        baos = new ByteArrayOutputStream();
        CryptoToolkit.decryptAsymmetric(bais, baos, publicKey);
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
        byte[] signature = CryptoToolkit.signDataPKCS1(data, privateKey);
        assertNotNull(signature);

        assertTrue(CryptoToolkit.verifySignaturePKCS1(signature, data, cert));
    }

    @Test
    public void testSignVerifyPKCS1Alternate()
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
        byte[] signature = CryptoToolkit.signDataPKCS1(data, privateKey, CryptoToolkit.SHA1_DIGEST_ALGORITHM, "RSA/NONE/PKCS1Padding", "BC");
        assertNotNull(signature);

        assertTrue(CryptoToolkit.verifySignaturePKCS1(signature, data, cert, "RSA/NONE/PKCS1Padding", "BC"));
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
        byte[] signature = CryptoToolkit.signDataPKCS7(data, cert, privateKey);
        assertNotNull(signature);

        assertTrue(CryptoToolkit.verifySignaturePKCS7(signature, data, cert));
    }

    @Test
    public void testSignVerifyPKCS7Invalid()
        throws CertificateException, KeyStoreException, UnrecoverableKeyException,
               IOException,NoSuchAlgorithmException, NoSuchProviderException, CMSException,
               CertStoreException, InvalidAlgorithmParameterException {

        thrown.expect(IllegalArgumentException.class);
        thrown.expectMessage(SecurityContext.getMessage("CRYPTO_ERR_INVALID_HASH"));

        CryptoToolkit.signDataPKCS7(null, null, null, "invalid", true, true);
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
        byte[] signature = CryptoToolkit.signDataPKCS7(data, cert, privateKey, CryptoToolkit.SHA1_DIGEST_ALGORITHM, true, true);
        assertNotNull(signature);

        assertTrue(CryptoToolkit.verifySignaturePKCS7(signature, data, cert));
    }
}
