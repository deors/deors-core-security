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
    public void testGetKeyStoreEntriesOk()
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
    public void testGetKeyStoreEntryOk()
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
    public void testGetKeyStoreFirstEntryOk()
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
    public void testGetCRLDistributionPointsInURL()
        throws IOException, CertificateException {

        X509Certificate cert = CertificateToolkit.readX509Certificate(
            this.getClass().getResourceAsStream("/EIDAS_CERTIFICADO_PRUEBAS___99999999R.cer"));
        List<CRLDistributionPoint> dp = CertificateToolkit.getCRLDistributionPoints(cert);
        assertNotNull(dp);
        assertEquals(1, dp.size());
        assertEquals(CRLDistributionPoint.CRL_IN_URL, dp.get(0).getType());
        assertEquals("ldap://ldapusu.cert.fnmt.es/cn=CRL3748,cn=AC%20FNMT%20Usuarios,ou=CERES,o=FNMT-RCM,c=ES?certificateRevocationList;binary?base?objectclass=cRLDistributionPoint", dp.get(0).getTarget());
    }

    @Test
    public void testGetSubjectAlternativeNames()
        throws IOException, CertificateException {

        X509Certificate cert = CertificateToolkit.readX509Certificate(
            this.getClass().getResourceAsStream("/EIDAS_CERTIFICADO_PRUEBAS___99999999R.cer"));
        Map<Integer, Map<String, String>> subj = CertificateToolkit.getSubjectAlternativeNames(cert);
        assertNotNull(subj);
        assertFalse("returned map should have data", subj.isEmpty());

        Map<String, String> rfc822 = subj.get(CertificateToolkit.SUBJECT_ALT_NAMES_TAG_RFC822_ADDRESS);
        assertNotNull(rfc822);
        assertEquals(1, rfc822.size());
        assertEquals("soporte_tecnico_ceres@fnmt.es", rfc822.entrySet().iterator().next().getKey());
        assertEquals("soporte_tecnico_ceres@fnmt.es", rfc822.entrySet().iterator().next().getValue());

        Map<String, String> dir = subj.get(CertificateToolkit.SUBJECT_ALT_NAMES_TAG_DIRECTORY_NAME);
        assertNotNull(dir);
        assertEquals(4, dir.size());
        assertEquals("PRUEBAS", dir.get(CertificateToolkit.OID_FNMT_NOMBRE));
        assertEquals("EIDAS", dir.get(CertificateToolkit.OID_FNMT_APELLIDO1));
        assertEquals("CERTIFICADO", dir.get(CertificateToolkit.OID_FNMT_APELLIDO2));
        assertEquals("99999999R", dir.get(CertificateToolkit.OID_FNMT_NIF));
    }

    @Test
    public void testGetSubjectDirectoryNameEmpty()
        throws IOException, CertificateException {

        X509Certificate cert = CertificateToolkit.readX509Certificate(
            this.getClass().getResourceAsStream("/certificate1.cer"));
        Map<String, String> dir = CertificateToolkit.getSubjectDirectoryName(cert);
        assertNotNull(dir);
        assertTrue("returned map should be empty", dir.isEmpty());
    }

    @Test
    public void testGetSubjectDirectoryNameOk()
        throws IOException, CertificateException {

        X509Certificate cert = CertificateToolkit.readX509Certificate(
            this.getClass().getResourceAsStream("/EIDAS_CERTIFICADO_PRUEBAS___99999999R.cer"));
        Map<String, String> dir = CertificateToolkit.getSubjectDirectoryName(cert);
        assertNotNull(dir);
        assertFalse("returned map should have data", dir.isEmpty());
        assertEquals(4, dir.size());
        assertEquals("PRUEBAS", dir.get(CertificateToolkit.OID_FNMT_NOMBRE));
        assertEquals("EIDAS", dir.get(CertificateToolkit.OID_FNMT_APELLIDO1));
        assertEquals("CERTIFICADO", dir.get(CertificateToolkit.OID_FNMT_APELLIDO2));
        assertEquals("99999999R", dir.get(CertificateToolkit.OID_FNMT_NIF));
    }

    @Test
    public void testValidateX509CertificateInvalid1()
        throws IOException, CertificateException {

        X509Certificate cert = CertificateToolkit.readX509Certificate(
            this.getClass().getResourceAsStream("/certificate1.cer"));
        assertFalse(CertificateToolkit.validateX509Certificate(cert));
    }

    @Test
    public void testValidateX509CertificateInvalid2()
        throws IOException, CertificateException {

        X509Certificate cert = CertificateToolkit.readX509Certificate(
            this.getClass().getResourceAsStream("/certificate2.der"));
        assertFalse(CertificateToolkit.validateX509Certificate(cert));
    }

    @Test
    public void testValidateX509CertificateValid()
        throws IOException, CertificateException {

        X509Certificate cert = CertificateToolkit.readX509Certificate(
            this.getClass().getResourceAsStream("/EIDAS_CERTIFICADO_PRUEBAS___99999999R.cer"));
        assertTrue(CertificateToolkit.validateX509Certificate(cert));
    }

    @Test
    public void testValidateX509CertificateWithCAInvalid()
        throws IOException, CertificateException {

        X509Certificate cert = CertificateToolkit.readX509Certificate(
            this.getClass().getResourceAsStream("/Ciudadano_autenticacion_activo.cer"));
        X509Certificate caCert = CertificateToolkit.readX509Certificate(
            this.getClass().getResourceAsStream("/AC-DNIE-003.crt"));
        assertFalse(CertificateToolkit.validateX509Certificate(cert, caCert));
    }

    @Test
    public void testValidateX509CertificateWithCAValid()
        throws IOException, CertificateException {

        X509Certificate cert = CertificateToolkit.readX509Certificate(
            this.getClass().getResourceAsStream("/AC-DNIE-004.crt"));
        X509Certificate caCert = CertificateToolkit.readX509Certificate(
            this.getClass().getResourceAsStream("/AC-RAIZ-DNIE-2.crt"));
        assertTrue(CertificateToolkit.validateX509Certificate(cert, caCert));
    }

    @Test
    public void testValidateX509CertificateWithCAListInvalid()
        throws IOException, CertificateException {

        X509Certificate cert = CertificateToolkit.readX509Certificate(
            this.getClass().getResourceAsStream("/Ciudadano_autenticacion_activo.cer"));
        X509Certificate subCaCert = CertificateToolkit.readX509Certificate(
            this.getClass().getResourceAsStream("/AC-DNIE-003.crt"));
        X509Certificate rootCaCert = CertificateToolkit.readX509Certificate(
            this.getClass().getResourceAsStream("/AC-RAIZ-DNIE-2.crt"));
        List<X509Certificate> caList = new ArrayList<X509Certificate>();
        caList.add(subCaCert);
        caList.add(rootCaCert);
        assertFalse(CertificateToolkit.validateX509Certificate(cert, subCaCert, caList));
    }

    @Test
    public void testValidateX509CertificateWithCAListValid()
        throws IOException, CertificateException {

        X509Certificate cert = CertificateToolkit.readX509Certificate(
            this.getClass().getResourceAsStream("/Ciudadano_autenticacion_activo.cer"));
        X509Certificate subCaCert = CertificateToolkit.readX509Certificate(
            this.getClass().getResourceAsStream("/AC-DNIE-004.crt"));
        X509Certificate rootCaCert = CertificateToolkit.readX509Certificate(
            this.getClass().getResourceAsStream("/AC-RAIZ-DNIE-2.crt"));
        List<X509Certificate> caList = new ArrayList<X509Certificate>();
        caList.add(subCaCert);
        caList.add(rootCaCert);
        assertTrue(CertificateToolkit.validateX509Certificate(cert, subCaCert, caList));
    }

    @Test
    public void testValidateX509CertificateCANotTrusted()
        throws IOException, CertificateException {

        X509Certificate cert = CertificateToolkit.readX509Certificate(
            this.getClass().getResourceAsStream("/Ciudadano_autenticacion_activo.cer"));
        X509Certificate subCaCert = CertificateToolkit.readX509Certificate(
            this.getClass().getResourceAsStream("/AC-DNIE-004.crt"));
        X509Certificate otherCaCert = CertificateToolkit.readX509Certificate(
            this.getClass().getResourceAsStream("/AC-DNIE-006.crt"));
        List<X509Certificate> caList = new ArrayList<X509Certificate>();
        caList.add(otherCaCert);
        assertFalse(CertificateToolkit.validateX509Certificate(cert, subCaCert, caList));
    }
}
