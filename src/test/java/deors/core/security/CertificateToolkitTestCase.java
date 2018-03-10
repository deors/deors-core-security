package deors.core.security;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.junit.Test;

public class CertificateToolkitTestCase {

    public CertificateToolkitTestCase() {

        super();
    }

    @Test
    public void testReadX509Certificate()
        throws IOException, CertificateException {

        X509Certificate cert = CertificateToolkit.readX509Certificate(
            this.getClass().getResourceAsStream("/certificate1.cer"));
        assertNotNull(cert);
        assertEquals(new BigInteger("65127682925515534142206025450410665930"), cert.getSerialNumber());
        assertEquals("EMAILADDRESS=jorge.hidalgo@gmail.com, CN=Thawte Freemail Member", cert.getSubjectDN().getName());
    }

    @Test
    public void testReadX509Certificates()
        throws IOException, CertificateException {

        List<X509Certificate> certs = CertificateToolkit.readX509Certificates(
            this.getClass().getResourceAsStream("/certificate2.der"));
        assertNotNull(certs);
        assertEquals(1, certs.size());
        assertEquals(new BigInteger("65127682925515534142206025450410665930"), certs.get(0).getSerialNumber());
        assertEquals("EMAILADDRESS=jorge.hidalgo@gmail.com, CN=Thawte Freemail Member", certs.get(0).getSubjectDN().getName());
    }

    @Test
    public void testReadJKSKeyStore()
        throws IOException, CertificateException, KeyStoreException,
               NoSuchAlgorithmException, NoSuchProviderException, UnrecoverableKeyException {

        KeyStore ks = CertificateToolkit.readJKSKeyStore(
            this.getClass().getResourceAsStream("/certificate3.jks"), "changeit".toCharArray());
        assertNotNull(ks);
        assertTrue(ks.containsAlias("jorge.hidalgo"));

        X509Certificate cert = (X509Certificate) ks.getCertificate("jorge.hidalgo");
        assertEquals("EMAILADDRESS=jorge.hidalgo@gmail.com, CN=Thawte Freemail Member", cert.getSubjectDN().getName());

        Key k = ks.getKey("jorge.hidalgo", "changeit".toCharArray());
        assertNotNull(k);
    }

    @Test
    public void testReadPKCS12KeyStore()
        throws IOException, CertificateException, KeyStoreException,
               NoSuchAlgorithmException, NoSuchProviderException, UnrecoverableKeyException {

        KeyStore ks = CertificateToolkit.readPKCS12KeyStore(
            this.getClass().getResourceAsStream("/certificate4.p12"), "changeit".toCharArray());
        assertNotNull(ks);
        assertTrue(ks.containsAlias("jorge.hidalgo"));

        X509Certificate cert = (X509Certificate) ks.getCertificate("jorge.hidalgo");
        assertEquals("EMAILADDRESS=jorge.hidalgo@gmail.com, CN=Thawte Freemail Member", cert.getSubjectDN().getName());

        Key k = ks.getKey("jorge.hidalgo", "changeit".toCharArray());
        assertNotNull(k);
    }

    @Test
    public void testGetKeyStoreEntriesEmpty()
        throws IOException, CertificateException, KeyStoreException,
               NoSuchAlgorithmException, NoSuchProviderException, UnrecoverableKeyException {

        KeyStore ks = CertificateToolkit.readJKSKeyStore(
            this.getClass().getResourceAsStream("/empty.jks"), "changeit".toCharArray());
        List<KeyStoreEntry> l = CertificateToolkit.getKeyStoreEntries(ks, "changeit".toCharArray());
        assertNotNull(l);
        assertEquals(0, l.size());
    }

    @Test
    public void testGetKeyStoreEntries()
        throws IOException, CertificateException, KeyStoreException,
               NoSuchAlgorithmException, NoSuchProviderException, UnrecoverableKeyException {

        KeyStore ks = CertificateToolkit.readPKCS12KeyStore(
            this.getClass().getResourceAsStream("/certificate4.p12"), "changeit".toCharArray());
        List<KeyStoreEntry> l = CertificateToolkit.getKeyStoreEntries(ks, "changeit".toCharArray());
        assertNotNull(l);
        assertEquals(1, l.size());
        assertEquals("jorge.hidalgo", l.get(0).getAlias());
        assertEquals("EMAILADDRESS=jorge.hidalgo@gmail.com, CN=Thawte Freemail Member", l.get(0).getCertificate().getSubjectDN().getName());
        assertNotNull(l.get(0).getPrivateKey());
    }

    @Test
    public void testGetKeyStoreEntryEmpty()
        throws IOException, CertificateException, KeyStoreException,
               NoSuchAlgorithmException, NoSuchProviderException, UnrecoverableKeyException {

        KeyStore ks = CertificateToolkit.readJKSKeyStore(
            this.getClass().getResourceAsStream("/empty.jks"), "changeit".toCharArray());
        KeyStoreEntry kse = CertificateToolkit.getKeyStoreEntry("jorge.hidalgo", ks, "changeit".toCharArray());
        assertNull(kse);
    }

    @Test
    public void testGetKeyStoreEntry()
        throws IOException, CertificateException, KeyStoreException,
               NoSuchAlgorithmException, NoSuchProviderException, UnrecoverableKeyException {

        KeyStore ks = CertificateToolkit.readPKCS12KeyStore(
            this.getClass().getResourceAsStream("/certificate4.p12"), "changeit".toCharArray());
        KeyStoreEntry kse = CertificateToolkit.getKeyStoreEntry("jorge.hidalgo", ks, "changeit".toCharArray());
        assertNotNull(kse);
        assertEquals("jorge.hidalgo", kse.getAlias());
        assertEquals("EMAILADDRESS=jorge.hidalgo@gmail.com, CN=Thawte Freemail Member", kse.getCertificate().getSubjectDN().getName());
        assertNotNull(kse.getPrivateKey());
    }

    @Test
    public void testGetKeyStoreFirstEntryEmpty()
        throws IOException, CertificateException, KeyStoreException,
               NoSuchAlgorithmException, NoSuchProviderException, UnrecoverableKeyException {

        KeyStore ks = CertificateToolkit.readJKSKeyStore(
            this.getClass().getResourceAsStream("/empty.jks"), "changeit".toCharArray());
        KeyStoreEntry kse = CertificateToolkit.getKeyStoreFirstEntry(ks, "changeit".toCharArray());
        assertNull(kse);
    }

    @Test
    public void testGetKeyStoreFirstEntry()
        throws IOException, CertificateException, KeyStoreException,
               NoSuchAlgorithmException, NoSuchProviderException, UnrecoverableKeyException {

        KeyStore ks = CertificateToolkit.readPKCS12KeyStore(
            this.getClass().getResourceAsStream("/certificate4.p12"), "changeit".toCharArray());
        KeyStoreEntry kse = CertificateToolkit.getKeyStoreFirstEntry(ks, "changeit".toCharArray());
        assertNotNull(kse);
        assertEquals("jorge.hidalgo", kse.getAlias());
        assertEquals("EMAILADDRESS=jorge.hidalgo@gmail.com, CN=Thawte Freemail Member", kse.getCertificate().getSubjectDN().getName());
        assertNotNull(kse.getPrivateKey());
    }

    @Test
    public void testGetCRLDistributionPointsEmpty()
        throws IOException, CertificateException {

        X509Certificate cert = CertificateToolkit.readX509Certificate(
            this.getClass().getResourceAsStream("/certificate1.cer"));
        List<CRLDistributionPoint> dp = CertificateToolkit.getCRLDistributionPoints(cert);
        assertNotNull(dp);
        assertEquals(0, dp.size());
    }

    @Test
    public void testGetCRLDistributionPointsX500()
        throws IOException, CertificateException {

        X509Certificate cert = CertificateToolkit.readX509Certificate(
            this.getClass().getResourceAsStream("/certificate5.cer"));
        List<CRLDistributionPoint> dp = CertificateToolkit.getCRLDistributionPoints(cert);
        assertNotNull(dp);
        assertEquals(1, dp.size());
        assertEquals(CRLDistributionPoint.CRL_IN_X500, dp.get(0).getType());
        assertEquals("2.5.4.3=CRL1756,2.5.4.11=FNMT Clase 2 CA,2.5.4.10=FNMT,2.5.4.6=ES", dp.get(0).getTarget());
    }

    @Test
    public void testGetCRLDistributionPointsURL()
        throws IOException, CertificateException {

        X509Certificate cert = CertificateToolkit.readX509Certificate(
            this.getClass().getResourceAsStream("/certificate8.cer"));
        List<CRLDistributionPoint> dp = CertificateToolkit.getCRLDistributionPoints(cert);
        assertNotNull(dp);
        assertEquals(2, dp.size());
        assertEquals(CRLDistributionPoint.CRL_IN_URL, dp.get(0).getType());
        assertEquals(CRLDistributionPoint.CRL_IN_URL, dp.get(1).getType());
        assertEquals("https://crl.accenture.com/classa.crl", dp.get(0).getTarget());
        assertEquals("https://crl1.accenture.com/classa.crl", dp.get(1).getTarget());
    }

    @Test
    public void testGetSubjectAlternativeNames1()
        throws IOException, CertificateException {

        X509Certificate cert = CertificateToolkit.readX509Certificate(
            this.getClass().getResourceAsStream("/certificate5.cer"));
        Map<Integer, Map<String, String>> map = CertificateToolkit.getSubjectAlternativeNames(cert);
        assertNotNull(map);

        Map<String, String> rfc822 = map.get(CertificateToolkit.SUBJECT_ALT_NAMES_TAG_RFC822_ADDRESS);
        assertNotNull(rfc822);
        assertEquals(1, rfc822.size());
        assertEquals("jorge.hidalgo@gmail.com", rfc822.entrySet().iterator().next().getKey());
        assertEquals("jorge.hidalgo@gmail.com", rfc822.entrySet().iterator().next().getValue());

        Map<String, String> dir = map.get(CertificateToolkit.SUBJECT_ALT_NAMES_TAG_DIRECTORY_NAME);
        assertNotNull(dir);
        assertEquals(4, dir.size());
        assertEquals("JORGE MANUEL", dir.get(CertificateToolkit.OID_FNMT_NOMBRE));
        assertEquals("HIDALGO", dir.get(CertificateToolkit.OID_FNMT_APELLIDO1));
        assertEquals("SANCHEZ", dir.get(CertificateToolkit.OID_FNMT_APELLIDO2));
        assertEquals("44266120K", dir.get(CertificateToolkit.OID_FNMT_NIF));
    }

    @Test
    public void testGetSubjectAlternativeNames2()
        throws IOException, CertificateException {

        X509Certificate cert = CertificateToolkit.readX509Certificate(
            this.getClass().getResourceAsStream("/certificate8.cer"));
        Map<Integer, Map<String, String>> map = CertificateToolkit.getSubjectAlternativeNames(cert);
        assertNotNull(map);

        Map<String, String> other = map.get(CertificateToolkit.SUBJECT_ALT_NAMES_TAG_OTHER_NAME);
        assertNotNull(other);
        assertEquals(1, other.size());
        assertEquals("1.3.6.1.4.1.311.20.2.3", other.entrySet().iterator().next().getKey());
        assertEquals("jorge.hidalgo@accenture.com", other.entrySet().iterator().next().getValue());

        Map<String, String> rfc822 = map.get(CertificateToolkit.SUBJECT_ALT_NAMES_TAG_RFC822_ADDRESS);
        assertNotNull(rfc822);
        assertEquals(1, rfc822.size());
        assertEquals("jorge.hidalgo@accenture.com", rfc822.entrySet().iterator().next().getKey());
        assertEquals("jorge.hidalgo@accenture.com", rfc822.entrySet().iterator().next().getValue());

        Map<String, String> dir = map.get(CertificateToolkit.SUBJECT_ALT_NAMES_TAG_DIRECTORY_NAME);
        assertNotNull(dir);
        assertEquals(1, dir.size());
        assertEquals("2.5.4.3", dir.entrySet().iterator().next().getKey());
        assertEquals("jorge.hidalgo@accenture.com", dir.entrySet().iterator().next().getValue());
}

    @Test
    public void testGetSubjectDirectoryNameEmpty()
        throws IOException, CertificateException {

        X509Certificate cert = CertificateToolkit.readX509Certificate(
            this.getClass().getResourceAsStream("/certificate1.cer"));
        Map<String, String> dir = CertificateToolkit.getSubjectDirectoryName(cert);
        assertNull(dir);
    }

    @Test
    public void testGetSubjectDirectoryName()
        throws IOException, CertificateException {

        X509Certificate cert = CertificateToolkit.readX509Certificate(
            this.getClass().getResourceAsStream("/certificate5.cer"));
        Map<String, String> dir = CertificateToolkit.getSubjectDirectoryName(cert);
        assertNotNull(dir);
        assertEquals(4, dir.size());
        assertEquals("JORGE MANUEL", dir.get(CertificateToolkit.OID_FNMT_NOMBRE));
        assertEquals("HIDALGO", dir.get(CertificateToolkit.OID_FNMT_APELLIDO1));
        assertEquals("SANCHEZ", dir.get(CertificateToolkit.OID_FNMT_APELLIDO2));
        assertEquals("44266120K", dir.get(CertificateToolkit.OID_FNMT_NIF));
    }

    @Test
    public void testValidateX509Certificate1()
        throws IOException, CertificateException {

        X509Certificate cert = CertificateToolkit.readX509Certificate(
            this.getClass().getResourceAsStream("/certificate1.cer"));
        assertFalse(CertificateToolkit.validateX509Certificate(cert));
    }

    @Test
    public void testValidateX509Certificate2()
        throws IOException, CertificateException {

        X509Certificate cert = CertificateToolkit.readX509Certificate(
            this.getClass().getResourceAsStream("/certificate2.der"));
        assertFalse(CertificateToolkit.validateX509Certificate(cert));
    }

    @Test
    public void testValidateX509Certificate3()
        throws IOException, CertificateException {

        X509Certificate cert = CertificateToolkit.readX509Certificate(
            this.getClass().getResourceAsStream("/certificate5.cer"));
        assertFalse(CertificateToolkit.validateX509Certificate(cert));
    }

    @Test
    public void testValidateX509Certificate4()
        throws IOException, CertificateException {

        X509Certificate cert = CertificateToolkit.readX509Certificate(
            this.getClass().getResourceAsStream("/ac13406900.cer"));
        assertFalse(CertificateToolkit.validateX509Certificate(cert));
    }

    @Test
    public void testValidateX509Certificate5()
        throws IOException, CertificateException {

        X509Certificate cert = CertificateToolkit.readX509Certificate(
            this.getClass().getResourceAsStream("/FNMTClasePCA.der"));
        assertTrue(CertificateToolkit.validateX509Certificate(cert));
    }

    @Test
    public void testValidateX509CertificateWithCA()
        throws IOException, CertificateException {

        X509Certificate cert = CertificateToolkit.readX509Certificate(
            this.getClass().getResourceAsStream("/ac13406900.cer"));
        X509Certificate caCert = CertificateToolkit.readX509Certificate(
            this.getClass().getResourceAsStream("/FNMTClasePCA.der"));
        assertFalse(CertificateToolkit.validateX509Certificate(cert, caCert));
    }

    @Test
    public void testValidateX509CertificateWithCAInvalid()
        throws IOException, CertificateException {

        X509Certificate cert = CertificateToolkit.readX509Certificate(
            this.getClass().getResourceAsStream("/FNMTClasePCA.der"));
        X509Certificate caCert = CertificateToolkit.readX509Certificate(
            this.getClass().getResourceAsStream("/FNMTClase2CA.cer"));
        assertFalse(CertificateToolkit.validateX509Certificate(cert, caCert));
    }

    @Test
    public void testValidateX509CertificateWithCAValid()
        throws IOException, CertificateException {

        X509Certificate cert = CertificateToolkit.readX509Certificate(
            this.getClass().getResourceAsStream("/FNMTClasePCA.der"));
        X509Certificate caCert = CertificateToolkit.readX509Certificate(
            this.getClass().getResourceAsStream("/FNMTClasePCA.der"));
        assertTrue(CertificateToolkit.validateX509Certificate(cert, caCert));
    }

    @Test
    public void testValidateX509CertificateWithCAList()
        throws IOException, CertificateException {

        X509Certificate cert = CertificateToolkit.readX509Certificate(
            this.getClass().getResourceAsStream("/ac13406900.cer"));
        X509Certificate caCert = CertificateToolkit.readX509Certificate(
            this.getClass().getResourceAsStream("/FNMTClasePCA.der"));
        List<X509Certificate> caList = new ArrayList<X509Certificate>();
        caList.add(caCert);
        assertFalse(CertificateToolkit.validateX509Certificate(cert, caCert, caList));
    }

    @Test
    public void testValidateX509CertificateWithCAListValid()
        throws IOException, CertificateException {

        X509Certificate cert = CertificateToolkit.readX509Certificate(
            this.getClass().getResourceAsStream("/FNMTClasePCA.der"));
        X509Certificate caCert = CertificateToolkit.readX509Certificate(
            this.getClass().getResourceAsStream("/FNMTClasePCA.der"));
        List<X509Certificate> caList = new ArrayList<X509Certificate>();
        caList.add(caCert);
        assertTrue(CertificateToolkit.validateX509Certificate(cert, caCert, caList));
    }

    @Test
    public void testValidateX509CertificateCANotTrusted()
        throws IOException, CertificateException {

        X509Certificate cert = CertificateToolkit.readX509Certificate(
            this.getClass().getResourceAsStream("/FNMTClasePCA.der"));
        X509Certificate caCert = CertificateToolkit.readX509Certificate(
            this.getClass().getResourceAsStream("/FNMTClasePCA.der"));
        List<X509Certificate> caList = new ArrayList<X509Certificate>();
        X509Certificate caCert2 = CertificateToolkit.readX509Certificate(
            this.getClass().getResourceAsStream("/FNMTClase2CA.cer"));
        caList.add(caCert2);
        assertFalse(CertificateToolkit.validateX509Certificate(cert, caCert, caList));
    }
}
