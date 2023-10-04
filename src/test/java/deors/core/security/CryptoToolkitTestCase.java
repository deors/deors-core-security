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
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import deors.core.commons.StringToolkit;
import deors.core.commons.io.IOToolkit;

public class CryptoToolkitTestCase {

    private static final String NEW_LINE = "\n";

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

        // text files might have different line endings depending on Git configuration
        // normalize to Linux line endings
        InputStream is = this.getClass().getResourceAsStream("/samplefile.txt");
        List<String> strings = IOToolkit.readTextStream(is);
        String combined = StringToolkit.combine(strings, NEW_LINE);
        ByteArrayInputStream bais = new ByteArrayInputStream(combined.getBytes("ISO-8859-1"));

        byte[] hash = CryptoToolkit.calculateHash(bais);
        assertNotNull(hash);
        byte[] expected = new byte[] {112, 17, -103, 17, 124, 30, -87, 21, -91, 5, -114, 17, -95, 126, -28, -69};
        assertArrayEquals(expected, hash);
    }

    @Test
    public void testCalculateHashAlternate()
        throws IOException, NoSuchAlgorithmException {

        // text files might have different line endings depending on Git configuration
        // normalize to Linux line endings
        InputStream is = this.getClass().getResourceAsStream("/samplefile.txt");
        List<String> strings = IOToolkit.readTextStream(is);
        String combined = StringToolkit.combine(strings, NEW_LINE);
        ByteArrayInputStream bais = new ByteArrayInputStream(combined.getBytes("ISO-8859-1"));

        byte[] hash = CryptoToolkit.calculateHash(bais, CryptoToolkit.SHA1_HASHING_ALGORITHM);
        assertNotNull(hash);
        byte[] expected = new byte[] {
            126, 105, 119, -97, 127, -38, -116, 79, -119, -116,
            25, 64, 122, 119, 11, 67, -55, 83, -105, 58
        };
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

        // text files might have different line endings depending on Git configuration
        // normalize to Linux line endings
        InputStream is = this.getClass().getResourceAsStream("/samplefile.txt");
        List<String> strings = IOToolkit.readTextStream(is);
        String combined = StringToolkit.combine(strings, NEW_LINE);
        File f = IOToolkit.writeFile(combined.getBytes("ISO-8859-1"));

        byte[] hash = CryptoToolkit.calculateHash(f);
        assertNotNull(hash);
        byte[] expected = new byte[] {112, 17, -103, 17, 124, 30, -87, 21, -91, 5, -114, 17, -95, 126, -28, -69};
        assertArrayEquals(expected, hash);
    }

    @Test
    public void testCalculateHashFileAlternate()
        throws IOException, URISyntaxException, NoSuchAlgorithmException {

        // text files might have different line endings depending on Git configuration
        // normalize to Linux line endings
        InputStream is = this.getClass().getResourceAsStream("/samplefile.txt");
        List<String> strings = IOToolkit.readTextStream(is);
        String combined = StringToolkit.combine(strings, NEW_LINE);
        File f = IOToolkit.writeFile(combined.getBytes("ISO-8859-1"));

        byte[] hash = CryptoToolkit.calculateHash(f, CryptoToolkit.SHA1_HASHING_ALGORITHM);
        assertNotNull(hash);
        byte[] expected = new byte[] {
            126, 105, 119, -97, 127, -38, -116, 79, -119, -116,
            25, 64, 122, 119, 11, 67, -55, 83, -105, 58
        };

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

        // text files might have different line endings depending on Git configuration
        // normalize to Linux line endings
        InputStream is = this.getClass().getResourceAsStream("/samplefile.txt");
        List<String> strings = IOToolkit.readTextStream(is);
        String combined = StringToolkit.combine(strings, NEW_LINE);
        ByteArrayInputStream bais = new ByteArrayInputStream(combined.getBytes("ISO-8859-1"));

        String hash = CryptoToolkit.calculateHashString(bais);
        assertNotNull(hash);
        String expected = "701199117C1EA915A5058E11A17EE4BB";
        assertEquals(expected, hash);
    }

    @Test
    public void testCalculateHashStringAlternate()
        throws IOException, NoSuchAlgorithmException {

        // text files might have different line endings depending on Git configuration
        // normalize to Linux line endings
        InputStream is = this.getClass().getResourceAsStream("/samplefile.txt");
        List<String> strings = IOToolkit.readTextStream(is);
        String combined = StringToolkit.combine(strings, NEW_LINE);
        ByteArrayInputStream bais = new ByteArrayInputStream(combined.getBytes("ISO-8859-1"));

        String hash = CryptoToolkit.calculateHashString(bais, CryptoToolkit.SHA1_HASHING_ALGORITHM);
        assertNotNull(hash);
        String expected = "7E69779F7FDA8C4F898C19407A770B43C953973A";
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

        // text files might have different line endings depending on Git configuration
        // normalize to Linux line endings
        InputStream is = this.getClass().getResourceAsStream("/samplefile.txt");
        List<String> strings = IOToolkit.readTextStream(is);
        String combined = StringToolkit.combine(strings, NEW_LINE);
        File f = IOToolkit.writeFile(combined.getBytes("ISO-8859-1"));

        String hash = CryptoToolkit.calculateHashString(f);
        assertNotNull(hash);
        String expected = "701199117C1EA915A5058E11A17EE4BB";
        assertEquals(expected, hash);
    }

    @Test
    public void testCalculateHashStringFileAlternate()
        throws IOException, URISyntaxException, NoSuchAlgorithmException {

        // text files might have different line endings depending on Git configuration
        // normalize to Linux line endings
        InputStream is = this.getClass().getResourceAsStream("/samplefile.txt");
        List<String> strings = IOToolkit.readTextStream(is);
        String combined = StringToolkit.combine(strings, NEW_LINE);
        File f = IOToolkit.writeFile(combined.getBytes("ISO-8859-1"));

        String hash = CryptoToolkit.calculateHashString(f, CryptoToolkit.SHA1_HASHING_ALGORITHM);
        assertNotNull(hash);
        String expected = "7E69779F7FDA8C4F898C19407A770B43C953973A";
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
            assertEquals("the key is expected to be 24 bytes long",
                24, key.getEncoded().length);
            assertEquals("the 24-byte key is expected to be encoded in base64 as a 48 character string",
                48, StringToolkit.asHexadecimalString(key.getEncoded()).length());
            keys.add(key);
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
               NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException,
               CertificateEncodingException {

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
               NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException,
               CertificateEncodingException {

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
        byte[] signature = CryptoToolkit.signDataPKCS1(data, privateKey, CryptoToolkit.SHA1_HASHING_ALGORITHM, "RSA/NONE/PKCS1Padding", "BC");
        assertNotNull(signature);

        assertTrue(CryptoToolkit.verifySignaturePKCS1(signature, data, cert, "RSA/NONE/PKCS1Padding", "BC"));
    }

    @Test
    public void testSignVerifyPKCS7()
        throws CertificateException, KeyStoreException, UnrecoverableKeyException,
               IOException,NoSuchAlgorithmException, NoSuchProviderException, CMSException,
               CertStoreException, InvalidAlgorithmParameterException,
               OperatorCreationException {

        String alias = "cn=ficticio activo\\, ciudadano (firma), gn=ciudadano, sn=ficticio, serialnumber=99999018d, c=es";
        KeyStore ks = CertificateToolkit.readPKCS12KeyStore(
            this.getClass().getResourceAsStream("/Ciudadano_firma_activo.pfx"), "123456".toCharArray());
        X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
        PrivateKey privateKey = (PrivateKey) ks.getKey(alias, "123456".toCharArray());
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
               CertStoreException, InvalidAlgorithmParameterException,
               OperatorCreationException {

        thrown.expect(IllegalArgumentException.class);
        thrown.expectMessage("Unknown signature type requested: INVALID");

        CryptoToolkit.signDataPKCS7(null, null, null, "invalid", true, true);
    }

    @Test
    public void testSignVerifyPKCS7Alternate()
        throws CertificateException, KeyStoreException, UnrecoverableKeyException,
               IOException,NoSuchAlgorithmException, NoSuchProviderException, CMSException,
               CertStoreException, InvalidAlgorithmParameterException,
               OperatorCreationException {

        String alias = "cn=ficticio activo\\, ciudadano (firma), gn=ciudadano, sn=ficticio, serialnumber=99999018d, c=es";
        KeyStore ks = CertificateToolkit.readPKCS12KeyStore(
            this.getClass().getResourceAsStream("/Ciudadano_firma_activo.pfx"), "123456".toCharArray());
        X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
        PrivateKey privateKey = (PrivateKey) ks.getKey(alias, "123456".toCharArray());
        assertNotNull(privateKey);

        byte[] data = new byte[] {
            -97, 91, -72, -127, -33, 76, 6, 89, -100, -15,
            -110, 26, -34, 41, 9, 22, 109, 16, 60, -2
        };
        byte[] signature = CryptoToolkit.signDataPKCS7(data, cert, privateKey, CryptoToolkit.SHA1RSA_DIGEST_ALGORITHM, true, true);
        assertNotNull(signature);

        assertTrue(CryptoToolkit.verifySignaturePKCS7(signature, data, cert));
    }
}
