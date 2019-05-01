package deors.core.security;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;

import deors.core.directory.DirectoryException;
import deors.core.directory.DirectoryManager;

/**
 * Toolkit methods for managing X.509 certificates, PKCS-12 profiles
 * and certificate revocation lists.
 *
 * @author deors
 * @version 1.0
 */
public final class CertificateToolkit {

    /**
     * The SubjectAlternativeNames extension OID.
     */
    private static final String OID_EXTENSION_SUBJECT_ALTERNATIVE_NAMES = "2.5.29.17"; //$NON-NLS-1$

    /**
     * The CRLDistributionPoints extension OID.
     */
    private static final String OID_EXTENSION_CRL_DISTRIBUTION_POINTS = "2.5.29.31"; //$NON-NLS-1$

    /**
     * The X.500 common name (CN) attribute OID.
     */
    public static final String OID_X500_CN = "2.5.4.3"; //$NON-NLS-1$

    /**
     * The X.500 country (C) attribute OID.
     */
    public static final String OID_X500_C = "2.5.4.6"; //$NON-NLS-1$

    /**
     * The X.500 organization (O) attribute OID.
     */
    public static final String OID_X500_O = "2.5.4.10"; //$NON-NLS-1$

    /**
     * The X.500 organizational unit (OU) attribute OID.
     */
    public static final String OID_X500_OU = "2.5.4.11"; //$NON-NLS-1$

    /**
     * The principal name attribute OID.
     */
    public static final String OID_PRINCIPAL_NAME = "1.3.6.1.4.1.311.20.2.3"; //$NON-NLS-1$

    /**
     * The RCM-FNMT's 'Nombre' attribute OID.
     */
    public static final String OID_FNMT_NOMBRE = "1.3.6.1.4.1.5734.1.1"; //$NON-NLS-1$

    /**
     * The RCM-FNMT's 'Apellido1' attribute OID.
     */
    public static final String OID_FNMT_APELLIDO1 = "1.3.6.1.4.1.5734.1.2"; //$NON-NLS-1$

    /**
     * The RCM-FNMT's 'Apellido2' attribute OID.
     */
    public static final String OID_FNMT_APELLIDO2 = "1.3.6.1.4.1.5734.1.3"; //$NON-NLS-1$

    /**
     * The RCM-FNMT's 'NIF' attribute OID.
     */
    public static final String OID_FNMT_NIF = "1.3.6.1.4.1.5734.1.4"; //$NON-NLS-1$

    /**
     * The RCM-FNMT's 'Componente' attribute OID.
     */
    public static final String OID_FNMT_COMPONENTE = "1.3.6.1.4.1.5734.1.8"; //$NON-NLS-1$

    /**
     * The RCM-FNMT's 'Entidad' attribute OID.
     */
    public static final String OID_FNMT_ENTIDAD = "1.3.6.1.4.1.5734.1.14"; //$NON-NLS-1$

    /**
     * The RCM-FNMT's 'CIF' attribute OID.
     */
    public static final String OID_FNMT_CIF = "1.3.6.1.4.1.5734.1.15"; //$NON-NLS-1$

    /**
     * Tag number for otherName subject alternative name.
     */
    public static final Integer SUBJECT_ALT_NAMES_TAG_OTHER_NAME = Integer.valueOf(0);

    /**
     * Tag number for rfc822Address subject alternative name.
     */
    public static final Integer SUBJECT_ALT_NAMES_TAG_RFC822_ADDRESS = Integer.valueOf(1);

    /**
     * Tag number for directoryName subject alternative name.
     */
    public static final Integer SUBJECT_ALT_NAMES_TAG_DIRECTORY_NAME = Integer.valueOf(4);

    /**
     * The Sun JCE security provider.
     */
    static final String JCE_SECURITY_PROVIDER = "SunJCE"; //$NON-NLS-1$

    /**
     * The Sun JSSE security provider.
     */
    static final String JSSE_SECURITY_PROVIDER = "SunJSSE"; //$NON-NLS-1$

    /**
     * The JKS key store identifier.
     */
    static final String KEY_STORE_JKS = "JCEKS"; //$NON-NLS-1$

    /**
     * The PKCS-12 key store identifier.
     */
    static final String KEY_STORE_P12 = "pkcs12"; //$NON-NLS-1$

    /**
     * The certificate type.
     */
    static final String CERTIFICATE_TYPE = "X509"; //$NON-NLS-1$

    /**
     * The attribute used in X.500 directories to store a CRL.
     */
    private static final String CRL_ATTRIBUTE_NAME = "certificateRevocationList;binary"; //$NON-NLS-1$

    /**
     * Revocation verification is performed using CRL's.
     */
    private static final String REVOCATION_VERIFICATION_CRL = "crl"; //$NON-NLS-1$

    /**
     * Revocation verification is performed using OCSP.
     */
    private static final String REVOCATION_VERIFICATION_OCSP = "ocsp"; //$NON-NLS-1$

    /**
     * Key name in the properties file for <code>DEFAULT_LDAP_HOST</code> property.
     */
    private static final String KN_DEFAULT_LDAP_HOST = "cert.defaultLDAPHost"; //$NON-NLS-1$

    /**
     * Default value for <code>DEFAULT_LDAP_HOST</code> property.
     */
    private static final String DV_DEFAULT_LDAP_HOST = "ldap.cert.fnmt.es"; //$NON-NLS-1$

    /**
     * Default LDAP host used to access X.500 directories. Configurable in the properties file using
     * the key referenced by the constant <code>KN_DEFAULT_LDAP_HOST</code> and
     * <code>DV_DEFAULT_LDAP_HOST</code> as the default value.
     *
     * @see SecurityContext#getConfigurationProperty(String, String)
     * @see CertificateToolkit#KN_DEFAULT_LDAP_HOST
     * @see CertificateToolkit#DV_DEFAULT_LDAP_HOST
     */
    private static final String DEFAULT_LDAP_HOST =
        SecurityContext.getConfigurationProperty(KN_DEFAULT_LDAP_HOST, DV_DEFAULT_LDAP_HOST);

    /**
     * Key name in the properties file for <code>DEFAULT_LDAP_PORT</code> property.
     */
    private static final String KN_DEFAULT_LDAP_PORT = "cert.defaultLDAPPort"; //$NON-NLS-1$

    /**
     * Default value for <code>DEFAULT_LDAP_PORT</code> property.
     */
    private static final int DV_DEFAULT_LDAP_PORT = 389;

    /**
     * Default LDAP port used to access X.500 directories. Configurable in the properties file using
     * the key referenced by the constant <code>KN_DEFAULT_LDAP_PORT</code> and
     * <code>DV_DEFAULT_LDAP_PORT</code> as the default value.
     *
     * @see SecurityContext#getConfigurationProperty(String, int)
     * @see CertificateToolkit#KN_DEFAULT_LDAP_PORT
     * @see CertificateToolkit#DV_DEFAULT_LDAP_PORT
     */
    private static final int DEFAULT_LDAP_PORT =
        SecurityContext.getConfigurationProperty(KN_DEFAULT_LDAP_PORT, DV_DEFAULT_LDAP_PORT);

    /**
     * Key name in the properties file for <code>DEFAULT_REVOCATION_VERIFICATION</code> property.
     */
    private static final String KN_DEFAULT_REVOCATION_VERIFICATION =
        "cert.defaultRevocationVerification"; //$NON-NLS-1$

    /**
     * Default value for <code>DEFAULT_REVOCATION_VERIFICATION</code> property.
     */
    private static final String DV_DEFAULT_REVOCATION_VERIFICATION = REVOCATION_VERIFICATION_CRL;

    /**
     * Default revocation verification mode. Valid values are those symbolized by constants
     * <code>REVOCATION_VERIFICATION_CRL</code> and <code>REVOCATION_VERIFICATION_OCSP</code>.
     * Configurable in the properties file using the key referenced by the constant
     * <code>KN_DEFAULT_REVOCATION_VERIFICATION</code> and
     * <code>DV_DEFAULT_REVOCATION_VERIFICATION</code> as the default value.
     *
     * @see SecurityContext#getConfigurationProperty(String, String)
     * @see CertificateToolkit#KN_DEFAULT_REVOCATION_VERIFICATION
     * @see CertificateToolkit#DV_DEFAULT_REVOCATION_VERIFICATION
     */
    private static final String DEFAULT_REVOCATION_VERIFICATION =
        SecurityContext.getConfigurationProperty(KN_DEFAULT_REVOCATION_VERIFICATION,
            DV_DEFAULT_REVOCATION_VERIFICATION);

    /**
     * Default constructor. This class is a toolkit and therefore it cannot be instantiated.
     */
    private CertificateToolkit() {
        super();
    }

    /**
     * Reads an X.509 certificate from a stream. If the given stream contains more than one
     * certificate, only the first is read. The stream is closed after being read.
     *
     * @param isCertificate stream pointing to the X.509 certificate file
     *
     * @return the certificate
     *
     * @throws java.io.IOException an I/O exception
     * @throws java.security.cert.CertificateException there is a problem reading the
     *                                                 certificate file
     */
    public static X509Certificate readX509Certificate(InputStream isCertificate)
        throws java.io.IOException,
               java.security.cert.CertificateException {

        CertificateFactory certFactory = CertificateFactory.getInstance(CERTIFICATE_TYPE);
        X509Certificate cert = (X509Certificate) certFactory.generateCertificate(isCertificate);
        isCertificate.close();

        return cert;
    }

    /**
     * Reads X.509 certificates from a stream. The stream is closed after being read.
     *
     * @param isCertificate stream pointing to the X.509 certificate file
     *
     * @return the certificates
     *
     * @throws java.io.IOException an I/O exception
     * @throws java.security.cert.CertificateException there is a problem reading the
     *                                                 certificate file
     */
    public static List<X509Certificate> readX509Certificates(InputStream isCertificate)
        throws java.io.IOException,
               java.security.cert.CertificateException {

        CertificateFactory certFactory = CertificateFactory.getInstance(CERTIFICATE_TYPE);
        Collection certs = certFactory.generateCertificates(isCertificate);
        isCertificate.close();

        List<X509Certificate> list = new ArrayList<>();
        list.addAll(certs);

        return list;
    }

    /**
     * Reads a JKS (Java Key Store) key store from a stream and returns a key store object. The
     * stream is closed after being read.
     *
     * @param isCertificate stream pointing to the JKS key store
     * @param password the key store password
     *
     * @return the key store
     *
     * @throws java.io.IOException an I/O exception
     * @throws java.security.NoSuchProviderException the security provider is not supported
     * @throws java.security.NoSuchAlgorithmException the key algorithm is not supported
     * @throws java.security.KeyStoreException there is a problem creating the key store
     * @throws java.security.cert.CertificateException there is a problem reading the certificate
     */
    public static KeyStore readJKSKeyStore(InputStream isCertificate, char[] password)
        throws java.io.IOException,
               java.security.NoSuchProviderException,
               java.security.NoSuchAlgorithmException,
               java.security.KeyStoreException,
               java.security.cert.CertificateException {

        KeyStore ks = KeyStore.getInstance(KEY_STORE_JKS, JCE_SECURITY_PROVIDER);
        ks.load(isCertificate, password);
        isCertificate.close();

        return ks;
    }

    /**
     * Reads a PKCS-12 key store from a stream and returns a key store object. The stream is closed
     * after being read.
     *
     * @param isCertificate stream pointing to the PKCS-12 key store
     * @param password the key store password
     *
     * @return the key store
     *
     * @throws java.io.IOException an I/O exception
     * @throws java.security.NoSuchProviderException the security provider is not supported
     * @throws java.security.NoSuchAlgorithmException the key algorithm is not supported
     * @throws java.security.KeyStoreException there is a problem creating the key store
     * @throws java.security.cert.CertificateException there is a problem reading the certificate
     */
    public static KeyStore readPKCS12KeyStore(InputStream isCertificate, char[] password)
        throws java.io.IOException,
               java.security.NoSuchProviderException,
               java.security.NoSuchAlgorithmException,
               java.security.KeyStoreException,
               java.security.cert.CertificateException {

        KeyStore ks = KeyStore.getInstance(KEY_STORE_P12, JSSE_SECURITY_PROVIDER);
        ks.load(isCertificate, password);
        isCertificate.close();

        return ks;
    }

    /**
     * Reads a key store and returns all entries (alias, X.509 certificate and private key).
     *
     * @param keyStore the key store
     * @param password the key store password
     *
     * @return the entries contained in the given key store or <code>null</code> if the key store
     *         is empty
     *
     * @throws java.security.NoSuchAlgorithmException the key algorithm is not supported
     * @throws java.security.KeyStoreException there is a problem reading the key store
     * @throws java.security.UnrecoverableKeyException the certificate in the key store does not
     *                                                 have a private key
     */
    public static List<KeyStoreEntry> getKeyStoreEntries(KeyStore keyStore, char[] password)
        throws java.security.NoSuchAlgorithmException,
               java.security.KeyStoreException,
               java.security.UnrecoverableKeyException {

        Enumeration<String> aliases = keyStore.aliases();

        List<KeyStoreEntry> entries = new ArrayList<>();

        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            X509Certificate certificate = (X509Certificate) keyStore.getCertificate(alias);
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, password);

            entries.add(new KeyStoreEntry(alias, certificate, privateKey));
        }

        return entries;
    }

    /**
     * Reads a key store and returns the entry which alias is the given one.
     *
     * @param alias the entry alias
     * @param keyStore the key store
     * @param password the key store password
     *
     * @return the entry or <code>null</code> if the given alias is not found in the given key
     *         store
     *
     * @throws java.security.NoSuchAlgorithmException the key algorithm is not supported
     * @throws java.security.KeyStoreException there is a problem reading the key store
     * @throws java.security.UnrecoverableKeyException the certificate in the key store does not
     *                                                 have a private key
     */
    public static KeyStoreEntry getKeyStoreEntry(String alias, KeyStore keyStore, char[] password)
        throws java.security.NoSuchAlgorithmException,
               java.security.KeyStoreException,
               java.security.UnrecoverableKeyException {

        if (!keyStore.containsAlias(alias)) {
            return null;
        }

        X509Certificate certificate = (X509Certificate) keyStore.getCertificate(alias);
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, password);

        return new KeyStoreEntry(alias, certificate, privateKey);
    }

    /**
     * Reads a key store and returns its first entry.
     *
     * @param keyStore the key store
     * @param password the key store password
     *
     * @return the first entry in the given key store or <code>null</code> if the key store is
     *         empty
     *
     * @throws java.security.NoSuchAlgorithmException the key algorithm is not supported
     * @throws java.security.KeyStoreException there is a problem reading the key store
     * @throws java.security.UnrecoverableKeyException the certificate in the key store does not
     *                                                 have a private key
     */
    public static KeyStoreEntry getKeyStoreFirstEntry(KeyStore keyStore, char[] password)
        throws java.security.NoSuchAlgorithmException,
               java.security.KeyStoreException,
               java.security.UnrecoverableKeyException {

        Enumeration<String> aliases = keyStore.aliases();

        if (!aliases.hasMoreElements()) {
            return null;
        }

        String alias = aliases.nextElement();
        X509Certificate certificate = (X509Certificate) keyStore.getCertificate(alias);
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, password);

        return new KeyStoreEntry(alias, certificate, privateKey);
    }

    /**
     * Downloads a CRL from an URL.
     *
     * @param urlName the URL to the CRL
     *
     * @return the CRL
     *
     * @throws java.io.IOException an I/O exception
     * @throws java.security.cert.CertificateException an exception creating the certificate factory
     * @throws java.security.cert.CRLException an exception generating the CRL
     */
    public static X509CRL getCRLFromURL(String urlName)
        throws java.io.IOException,
               java.security.cert.CertificateException,
               java.security.cert.CRLException {

        URL url = new URL(urlName);

        URLConnection urlconn = url.openConnection();

        urlconn = SecurityToolkit.checkURLConnectionForSSLTunneling(urlconn);

        urlconn.setAllowUserInteraction(false);
        urlconn.setDoInput(true);
        urlconn.setDoOutput(false);
        urlconn.setUseCaches(false);

        urlconn.connect();

        InputStream is = urlconn.getInputStream();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        byte[] buffer = new byte[SecurityContext.DEFAULT_BUFFER_SIZE];

        int read = -1;
        while ((read = is.read(buffer)) != -1) {
            baos.write(buffer, 0, read);
        }

        is.close();
        baos.flush();
        byte[] crlData = baos.toByteArray();
        baos.close();

        is = new ByteArrayInputStream(crlData);
        CertificateFactory cf = CertificateFactory.getInstance(CERTIFICATE_TYPE);
        X509CRL crl = (X509CRL) cf.generateCRL(is);
        is.close();

        return crl;
    }

    /**
     * Gets a CRL from an X.500 directory using the configured LDAP host and port.
     *
     * @param crlDN the distinguished name that contains the CRL
     *
     * @return the CRL or <code>null</code> if the CRL was not found in the configured directory
     *
     * @throws java.io.IOException an I/O exception
     * @throws java.security.cert.CertificateException an exception creating the certificate factory
     * @throws java.security.cert.CRLException an exception generating the CRL
     * @throws deors.core.directory.DirectoryException a directory exception
     */
    public static X509CRL getCRLFromX500Directory(String crlDN)
        throws java.io.IOException,
               java.security.cert.CertificateException,
               java.security.cert.CRLException,
               deors.core.directory.DirectoryException {

        return getCRLFromX500Directory(crlDN, DEFAULT_LDAP_HOST, DEFAULT_LDAP_PORT);
    }

    /**
     * Gets a CRL from an X.500 directory.
     *
     * @param crlDN the distinguished name that contains the CRL
     * @param dirHost the directory host name
     * @param dirPort the directory port
     *
     * @return the CRL or <code>null</code> if the CRL was not found in the given directory
     *
     * @throws java.io.IOException an I/O exception
     * @throws java.security.cert.CertificateException an exception creating the certificate factory
     * @throws java.security.cert.CRLException an exception generating the CRL
     * @throws deors.core.directory.DirectoryException a directory exception
     */
    public static X509CRL getCRLFromX500Directory(String crlDN, String dirHost, int dirPort)
        throws java.io.IOException,
               java.security.cert.CertificateException,
               java.security.cert.CRLException,
               deors.core.directory.DirectoryException {

        DirectoryManager dirMgr = new DirectoryManager(dirHost, dirPort);
        byte[] crl = dirMgr.getAttributeValueBytes(crlDN, CRL_ATTRIBUTE_NAME);

        InputStream is = new ByteArrayInputStream(crl);
        CertificateFactory cf = CertificateFactory.getInstance(CERTIFICATE_TYPE);

        try {
            return (X509CRL) cf.generateCRL(is);
        } finally {
            if (is != null) {
                is.close();
            }
        }
    }

    /**
     * Parses a <code>X509Certificate</code> object and returns the CRL distribution points for
     * the certificate.
     *
     * @param cert the certificate
     *
     * @return the CRL distribution points
     *
     * @throws java.io.IOException an I/O exception
     */
    public static List<CRLDistributionPoint> getCRLDistributionPoints(X509Certificate cert)
        throws java.io.IOException {

        byte[] extensionData = cert.getExtensionValue(OID_EXTENSION_CRL_DISTRIBUTION_POINTS);

        return ASN1Toolkit.parseCRLDistributionPoints(convertExtensionData(extensionData));
    }

    /**
     * Parses the 2.5.29.17 extension from the given certificate (subjectAlternativeNames) and gets
     * the data from all tags. The returned hash table, indexed by tag number (of type
     * <code>java.lang.Integer</code>), has strings when the alternative name is a string, e.g. a
     * RFC-822 e-mail address, or hash tables when the alternative name is composed of several
     * entries, with every alternative name indexed by its OID.
     *
     * @param cert the certificate
     *
     * @return the subject alternative names or <code>null</code> if the subjectAlternativeNames
     *         extension is not found in the given certificate
     *
     * @throws java.io.IOException an I/O exception
     */
    public static Map<Integer, Map<String, String>> getSubjectAlternativeNames(X509Certificate cert)
        throws java.io.IOException {

        byte[] extensionData = cert.getExtensionValue(OID_EXTENSION_SUBJECT_ALTERNATIVE_NAMES);

        return ASN1Toolkit.parseSubjectAlternativeNames(convertExtensionData(extensionData));
    }

    /**
     * Parses the 2.5.29.17 extension from the given certificate (subjectAlternativeNames) and gets
     * the data from tag number 4 (directoryName). The returned hash table has the directory name
     * entries indexed by the OID of each entry.
     *
     * @param cert the certificate
     *
     * @return the subject directory name or <code>null</code> if the subjectAlternativeNames
     *         extension or the tag directoryName are not found in the given certificate
     *
     * @throws java.io.IOException an I/O exception
     *
     * @see CertificateToolkit#SUBJECT_ALT_NAMES_TAG_DIRECTORY_NAME
     */
    public static Map<String, String> getSubjectDirectoryName(X509Certificate cert)
        throws java.io.IOException {

        byte[] extensionData = cert.getExtensionValue(OID_EXTENSION_SUBJECT_ALTERNATIVE_NAMES);

        return ASN1Toolkit.parseSubjectDirectoryName(convertExtensionData(extensionData));
    }

    /**
     * Converts a byte array containing data from a <code>X509Certificate</code>
     * extension into an ASN.1 sequence.
     *
     * @param extensionData the byte array holding the extension data
     *
     * @return the extension data as an ASN.1 sequence
     *
     * @throws java.io.IOException an I/O exception
     */
    private static ASN1Sequence convertExtensionData(byte[] extensionData)
        throws java.io.IOException {

        if (extensionData == null || extensionData.length == 0) {
            return null;
        }

        ASN1InputStream a1is = null;

        try {
            ByteArrayInputStream bais = new ByteArrayInputStream(extensionData);
            a1is = new ASN1InputStream(bais);

            ASN1OctetString mainOct = (ASN1OctetString) a1is.readObject();

            bais = new ByteArrayInputStream(mainOct.getOctets());

            a1is.close();
            a1is = new ASN1InputStream(bais);

            return (ASN1Sequence) a1is.readObject();
        } finally {
            if (a1is != null) {
                a1is.close();
            }
        }
    }

    /**
     * Validates the given X.509 certificate <code>notBefore</code> and <code>notAfter</code>
     * dates.<br>
     *
     * A <code>java.lang.IllegalArgumentException</code> exception is thrown if the given
     * certificate is <code>null</code>.
     *
     * @param cert the certificate to be validated
     *
     * @return whether the given certificate is valid
     */
    public static boolean validateX509Certificate(X509Certificate cert) {

        return validateX509Certificate(cert, null, null);
    }

    /**
     * Validates the given X.509 certificate <code>notBefore</code> and <code>notAfter</code>
     * dates, and if the CA X.509 certificate is given, also validates the CA dates and whether the
     * CA is the actual CA that issued the given X.509 certificate.<br>
     *
     * A <code>java.lang.IllegalArgumentException</code> exception is thrown if the given
     * certificate is <code>null</code>.
     *
     * @param cert the certificate to be validated
     * @param caCert the certificate of the CA that issued the certificate <code>cert</code>
     *
     * @return whether the given certificate is valid
     */
    public static boolean validateX509Certificate(X509Certificate cert, X509Certificate caCert) {

        return validateX509Certificate(cert, caCert, null);
    }

    /**
     * Validates the given X.509 certificate <code>notBefore</code> and <code>notAfter</code>
     * dates, and if the CA X.509 certificate is given, also validates the CA dates and whether the
     * CA is the actual CA that issued the given X.509 certificate, and if the trusted CA
     * certificates are given, validates the CA is one of the trusted ones.
     *
     * @param cert the certificate to be validated
     * @param caCert the certificate of the CA that issued the certificate <code>cert</code>
     * @param trustedCACerts list that contains the trusted CA's certificates
     *
     * @return whether the given certificate is valid
     */
    public static boolean validateX509Certificate(X509Certificate cert, X509Certificate caCert,
                                                  List<X509Certificate> trustedCACerts) {

        // validates the certificate dates
        try {
            cert.checkValidity();
        } catch (CertificateNotYetValidException | CertificateExpiredException e) {
            return false;
        }

        if (caCert == null) {
            return true;
        }

        // validates the CA certificate dates
        // and validates if the CA certificate IS the
        // actual CA for the given certificate
        try {
            caCert.checkValidity();
        } catch (CertificateNotYetValidException | CertificateExpiredException e) {
            return false;
        }

        if (!cert.getIssuerDN().getName().equals(caCert.getSubjectDN().getName())) {
            return false;
        }

        /*
         * validation not tested
         * boolean[] caCertIDInCert = cert.getIssuerUniqueID();
         * boolean[] caCertID = caCert.getSubjectUniqueID();
         * if (caCertIDInCert != null && caCertID != null) {
         *     if (caCertIDInCert.length != caCertID.length) {
         *         return false;
         *     }
         *     for (int i = 0; i < caCertID.length; i++) {
         *         if (caCertIDInCert[i] != caCertID[i]) {
         *             return false;
         *         }
         *     }
         * }
         */

        if (trustedCACerts != null && !trustedCACerts.isEmpty()) {
            // checks whether the CA is one of the given
            // trusted ones
            boolean caFound = false;
            for (X509Certificate trustedCACert : trustedCACerts) {
                if (trustedCACert.equals(caCert)) {
                    caFound = true;
                    break;
                }
            }

            if (!caFound) {
                return false;
            }
        }

        return true;
    }

    /**
     * Verifies the revocation status of the given certificate using the configured mode (CRL/OCSP).
     *
     * @param cert the certificate to be verified
     * @param caCert the certificate of the CA that issued the certificates; this value is used only
     *        in OCSP verifications
     *
     * @return whether the certificate has not been revoked
     *
     * @throws java.io.IOException an I/O exception
     * @throws java.security.NoSuchProviderException the security provider is not supported
     * @throws java.security.cert.CertificateException there is a problem reading the certificate
     *                                                 file
     * @throws java.security.cert.CRLException an exception generating the CRL
     * @throws org.bouncycastle.cert.ocsp.OCSPException an exception preparing the OCSP request
     *                                                  or parsing the OCSP response
     * @throws org.bouncycastle.operator.OperatorCreationException error creating the operator
     * @throws deors.core.directory.DirectoryException a directory exception
     *
     * @see CertificateToolkit#DEFAULT_REVOCATION_VERIFICATION
     * @see CertificateToolkit#REVOCATION_VERIFICATION_CRL
     * @see CertificateToolkit#REVOCATION_VERIFICATION_OCSP
     */
    public static boolean verifyX509Certificate(X509Certificate cert, X509Certificate caCert)
        throws java.io.IOException,
               java.security.NoSuchProviderException,
               java.security.cert.CertificateException,
               java.security.cert.CRLException,
               org.bouncycastle.cert.ocsp.OCSPException,
               org.bouncycastle.operator.OperatorCreationException,
               deors.core.directory.DirectoryException {

        List<X509Certificate> certs = new ArrayList<X509Certificate>();
        certs.add(cert);
        return verifyX509Certificate(certs, caCert);
    }

    /**
     * Verifies the revocation status of the given certificates using the configured mode
     * (CRL/OCSP).
     *
     * @param certs the certificates to be verified
     * @param caCert the certificate of the CA that issued all the certificates that will be
     *        verified; this value is used only in OCSP verifications
     *
     * @return whether the certificates has not been revoked
     *
     * @throws java.io.IOException an I/O exception
     * @throws java.security.NoSuchProviderException the security provider is not supported
     * @throws java.security.cert.CertificateException there is a problem reading the certificate
     *                                                 file
     * @throws java.security.cert.CRLException an exception generating the CRL
     * @throws org.bouncycastle.cert.ocsp.OCSPException an exception preparing the OCSP request
     *                                                  or parsing the OCSP response
     * @throws org.bouncycastle.operator.OperatorCreationException error creating the operator
     * @throws deors.core.directory.DirectoryException a directory exception
     *
     * @see CertificateToolkit#DEFAULT_REVOCATION_VERIFICATION
     * @see CertificateToolkit#REVOCATION_VERIFICATION_CRL
     * @see CertificateToolkit#REVOCATION_VERIFICATION_OCSP
     */
    public static boolean verifyX509Certificate(List<X509Certificate> certs, X509Certificate caCert)
        throws java.io.IOException,
               java.security.NoSuchProviderException,
               java.security.cert.CertificateException,
               java.security.cert.CRLException,
               org.bouncycastle.cert.ocsp.OCSPException,
               org.bouncycastle.operator.OperatorCreationException,
               deors.core.directory.DirectoryException {

        if (DEFAULT_REVOCATION_VERIFICATION.equals(REVOCATION_VERIFICATION_CRL)) {
            return verifyX509CertificateUsingCRL(certs);
        } else if (DEFAULT_REVOCATION_VERIFICATION.equals(REVOCATION_VERIFICATION_OCSP)) {
            return verifyX509CertificateUsingOCSP(certs, caCert);
        } else {
            throw new IllegalArgumentException(
                SecurityContext.getMessage("CERTTK_ERR_REVOCATION_VER_MODE_INVALID")); //$NON-NLS-1$
        }
    }

    /**
     * Verifies the revocation status of the given certificate using the CRL distribution points it
     * contains and the configured LDAP host and port for X.500 verifications.
     *
     * @param cert the certificate to be verified
     *
     * @return whether the certificate has not been revoked
     *
     * @throws java.io.IOException an I/O exception
     * @throws java.security.cert.CertificateException there is a problem reading the certificate
     *                                                 file
     * @throws java.security.cert.CRLException an exception generating the CRL
     * @throws deors.core.directory.DirectoryException a directory exception
     */
    public static boolean verifyX509CertificateUsingCRL(X509Certificate cert)
        throws java.io.IOException,
               java.security.cert.CertificateException,
               java.security.cert.CRLException,
               deors.core.directory.DirectoryException {

        List<X509Certificate> certs = new ArrayList<X509Certificate>();
        certs.add(cert);
        return verifyX509CertificateUsingCRL(certs, DEFAULT_LDAP_HOST, DEFAULT_LDAP_PORT);
    }

    /**
     * Verifies the revocation status of the given certificates using the CRL distribution points
     * they contain and the configured LDAP host and port for X.500 verifications.
     *
     * @param certs the certificates to be verified
     *
     * @return whether the certificates has not been revoked
     *
     * @throws java.io.IOException an I/O exception
     * @throws java.security.cert.CertificateException there is a problem reading the certificate
     *                                                 file
     * @throws java.security.cert.CRLException an exception generating the CRL
     * @throws deors.core.directory.DirectoryException a directory exception
     */
    public static boolean verifyX509CertificateUsingCRL(List<X509Certificate> certs)
        throws java.io.IOException,
               java.security.cert.CertificateException,
               java.security.cert.CRLException,
               deors.core.directory.DirectoryException {

        return verifyX509CertificateUsingCRL(certs, DEFAULT_LDAP_HOST, DEFAULT_LDAP_PORT);
    }

    /**
     * Verifies the revocation status of the given certificate using the CRL distribution points it
     * contains and the given LDAP host and port for X.500 verifications.
     *
     * @param cert the certificate to be verified
     * @param dirHost the directory host name
     * @param dirPort the directory port
     *
     * @return whether the certificate has not been revoked
     *
     * @throws java.io.IOException an I/O exception
     * @throws java.security.cert.CertificateException there is a problem reading the certificate
     *                                                 file
     * @throws java.security.cert.CRLException an exception generating the CRL
     * @throws deors.core.directory.DirectoryException a directory exception
     */
    public static boolean verifyX509CertificateUsingCRL(X509Certificate cert, String dirHost,
                                                        int dirPort)
        throws java.io.IOException,
               java.security.cert.CertificateException,
               java.security.cert.CRLException,
               deors.core.directory.DirectoryException {

        List<X509Certificate> certs = new ArrayList<X509Certificate>();
        certs.add(cert);
        return verifyX509CertificateUsingCRL(certs, dirHost, dirPort);
    }

    /**
     * Verifies the revocation status of the given certificates using the CRL distribution points
     * they contain and the given LDAP host and port for X.500 verifications. If exists more than
     * one distribution point, the method uses the first one that is accessible. If there is a
     * exception downloading the CRL or accessing a directory, then the method tries with the next
     * distribution point until a CRL is obtained or there are no more distribution points
     * available.
     *
     * @param certs the certificates to be verified
     * @param dirHost the directory host name
     * @param dirPort the directory port
     *
     * @return whether the certificates has not been revoked
     *
     * @throws java.io.IOException an I/O exception
     * @throws java.security.cert.CertificateException there is a problem reading the certificate
     *                                                 file
     * @throws java.security.cert.CRLException an exception generating the CRL
     * @throws deors.core.directory.DirectoryException a directory exception
     */
    public static boolean verifyX509CertificateUsingCRL(List<X509Certificate> certs, String dirHost,
                                                        int dirPort)
        throws java.io.IOException,
               java.security.cert.CertificateException,
               java.security.cert.CRLException,
               deors.core.directory.DirectoryException {

        for (X509Certificate cert : certs) {

            // gets the CRL distribution points for cert
            List<CRLDistributionPoint> points = getCRLDistributionPoints(cert);

            int i = 0;
            for (CRLDistributionPoint point : points) {
                i++;
                try {
                    if (point.getType() == CRLDistributionPoint.CRL_IN_URL) {
                        X509CRL crl = CertificateToolkit.getCRLFromURL(point.getTarget());
                        X509CRLEntry crlEntry =
                            crl.getRevokedCertificate(cert.getSerialNumber());

                        if (crlEntry != null) {
                            return false;
                        }
                    } else {
                        X509CRL crl =
                            CertificateToolkit.getCRLFromX500Directory(point.getTarget(),
                                dirHost, dirPort);
                        X509CRLEntry crlEntry =
                            crl.getRevokedCertificate(cert.getSerialNumber());

                        if (crlEntry != null) {
                            return false;
                        }
                    }

                    // only the first accessible point is used
                    break;
                } catch (IOException ioe) {
                    if (i < points.size()) {
                        continue;
                    }

                    throw ioe;
                } catch (DirectoryException de) {
                    if (i < points.size()) {
                        continue;
                    }

                    throw de;
                }
            }
        }

        return true;
    }

    /**
     * Verifies the revocation status of the given certificate using an unsigned OCSP request to the
     * configured OCSP responder.
     *
     * @param cert the certificate to be verified
     * @param caCert the certificate of the CA that issued the certificate
     *
     * @return whether the certificate has not been revoked
     *
     * @throws java.io.IOException an I/O exception
     * @throws java.security.NoSuchProviderException the security provider is not supported
     * @throws java.security.cert.CertificateEncodingException error with certificate encoding
     * @throws org.bouncycastle.cert.ocsp.OCSPException an exception preparing the OCSP request
     *                                                  or parsing the OCSP response
     * @throws org.bouncycastle.operator.OperatorCreationException error creating the operator
     *
     * @see OCSPToolkit#verifyX509CertificateUsingOCSP(X509Certificate, X509Certificate)
     */
    public static boolean verifyX509CertificateUsingOCSP(X509Certificate cert,
                                                         X509Certificate caCert)
        throws java.io.IOException,
               java.security.NoSuchProviderException,
               java.security.cert.CertificateEncodingException,
               org.bouncycastle.cert.ocsp.OCSPException,
               org.bouncycastle.operator.OperatorCreationException {

        return OCSPToolkit.verifyX509CertificateUsingOCSP(cert, caCert);
    }

    /**
     * Verifies the revocation status of the given certificates using an unsigned OCSP request to
     * the configured OCSP responder.
     *
     * @param certs the certificates to be verified
     * @param caCert the certificate of the CA that issued all the certificates that will be
     *               verified
     *
     * @return whether the certificates has not been revoked
     *
     * @throws java.io.IOException an I/O exception
     * @throws java.security.NoSuchProviderException the security provider is not supported
     * @throws java.security.cert.CertificateEncodingException error with certificate encoding
     * @throws org.bouncycastle.cert.ocsp.OCSPException an exception preparing the OCSP request
     *                                                  or parsing the OCSP response
     * @throws org.bouncycastle.operator.OperatorCreationException error creating the operator
     *
     * @see OCSPToolkit#verifyX509CertificateUsingOCSP(List, X509Certificate)
     */
    public static boolean verifyX509CertificateUsingOCSP(List<X509Certificate> certs,
                                                         X509Certificate caCert)
        throws java.io.IOException,
               java.security.NoSuchProviderException,
               java.security.cert.CertificateEncodingException,
               org.bouncycastle.cert.ocsp.OCSPException,
               org.bouncycastle.operator.OperatorCreationException {

        return OCSPToolkit.verifyX509CertificateUsingOCSP(certs, caCert);
    }

    /**
     * Verifies the revocation status of the given certificate using an unsigned OCSP request to the
     * OCSP responder located in the given URL.
     *
     * @param cert the certificate to be verified
     * @param caCert the certificate of the CA that issued the certificate
     * @param ocspURL URL where the OCSP responder is located
     *
     * @return whether the certificate has not been revoked
     *
     * @throws java.io.IOException an I/O exception
     * @throws java.security.NoSuchProviderException the security provider is not supported
     * @throws java.security.cert.CertificateEncodingException error with certificate encoding
     * @throws org.bouncycastle.cert.ocsp.OCSPException an exception preparing the OCSP request
     *                                                  or parsing the OCSP response
     * @throws org.bouncycastle.operator.OperatorCreationException error creating the operator
     *
     * @see OCSPToolkit#verifyX509CertificateUsingOCSP(X509Certificate, X509Certificate, String)
     */
    public static boolean verifyX509CertificateUsingOCSP(X509Certificate cert,
                                                         X509Certificate caCert, String ocspURL)
        throws java.io.IOException,
               java.security.NoSuchProviderException,
               java.security.cert.CertificateEncodingException,
               org.bouncycastle.cert.ocsp.OCSPException,
               org.bouncycastle.operator.OperatorCreationException {

        return OCSPToolkit.verifyX509CertificateUsingOCSP(cert, caCert, ocspURL);
    }

    /**
     * Verifies the revocation status of the given certificates using an unsigned OCSP request to
     * the OCSP responder located in the given URL.
     *
     * @param certs the certificates to be verified
     * @param caCert the certificate of the CA that issued all the certificates that will be
     *               verified
     * @param ocspURL URL where the OCSP responder is located
     *
     * @return whether the certificates has not been revoked
     *
     * @throws java.io.IOException an I/O exception
     * @throws java.security.NoSuchProviderException the security provider is not supported
     * @throws java.security.cert.CertificateEncodingException error with certificate encoding
     * @throws org.bouncycastle.cert.ocsp.OCSPException an exception preparing the OCSP request
     *                                                  or parsing the OCSP response
     * @throws org.bouncycastle.operator.OperatorCreationException error creating the operator
     *
     * @see OCSPToolkit#verifyX509CertificateUsingOCSP(List, X509Certificate, String)
     */
    public static boolean verifyX509CertificateUsingOCSP(List<X509Certificate> certs,
                                                         X509Certificate caCert, String ocspURL)
        throws java.io.IOException,
               java.security.NoSuchProviderException,
               java.security.cert.CertificateEncodingException,
               org.bouncycastle.cert.ocsp.OCSPException,
               org.bouncycastle.operator.OperatorCreationException {

        return OCSPToolkit.verifyX509CertificateUsingOCSP(certs, caCert, ocspURL);
    }

    /**
     * Verifies the revocation status of the given certificate using a signed or unsigned OCSP
     * request to the OCSP responder located in the given URL. The request will be signed if both
     * the signing certificate and the signing private key are given.
     *
     * @param cert the certificate to be verified
     * @param caCert the certificate of the CA that issued the certificates
     * @param ocspURL URL where the OCSP responder is located
     * @param signingCert the X.509 certificate used to sign the OCSP request
     * @param signingKey the private key used to sign the OCSP private key
     *
     * @return whether the certificate has not been revoked
     *
     * @throws java.io.IOException an I/O exception
     * @throws java.security.NoSuchProviderException the security provider is not supported
     * @throws java.security.cert.CertificateEncodingException error with certificate encoding
     * @throws org.bouncycastle.cert.ocsp.OCSPException an exception preparing the OCSP request
     *                                                  or parsing the OCSP response
     * @throws org.bouncycastle.operator.OperatorCreationException error creating the operator
     *
     * @see OCSPToolkit#verifyX509CertificateUsingOCSP(X509Certificate, X509Certificate, String, X509Certificate, PrivateKey)
     */
    public static boolean verifyX509CertificateUsingOCSP(X509Certificate cert,
                                                         X509Certificate caCert, String ocspURL,
                                                         X509Certificate signingCert,
                                                         PrivateKey signingKey)
        throws java.io.IOException,
               java.security.NoSuchProviderException,
               java.security.cert.CertificateEncodingException,
               org.bouncycastle.cert.ocsp.OCSPException,
               org.bouncycastle.operator.OperatorCreationException {

        return OCSPToolkit.verifyX509CertificateUsingOCSP(
            cert, caCert, ocspURL, signingCert, signingKey);
    }

    /**
     * Verifies the revocation status of the given certificates using a signed or unsigned OCSP
     * request to the OCSP responder located in the given URL. The request will be signed if both
     * the signing certificate and the signing private key are given.
     *
     * @param certs the certificates to be verified
     * @param caCert the certificate of the CA that issued all the certificates that will be
     *               verified
     * @param ocspURL URL where the OCSP responder is located
     * @param signingCert the X.509 certificate used to sign the OCSP request
     * @param signingKey the private key used to sign the OCSP private key
     *
     * @return whether the certificates has not been revoked
     *
     * @throws java.io.IOException an I/O exception
     * @throws java.security.NoSuchProviderException the security provider is not supported
     * @throws java.security.cert.CertificateEncodingException error with certificate encoding
     * @throws org.bouncycastle.cert.ocsp.OCSPException an exception preparing the OCSP request
     *                                                  or parsing the OCSP response
     * @throws org.bouncycastle.operator.OperatorCreationException error creating the operator
     *
     * @see OCSPToolkit#verifyX509CertificateUsingOCSP(List, X509Certificate, String, X509Certificate, PrivateKey)
     */
    public static boolean verifyX509CertificateUsingOCSP(List<X509Certificate> certs,
                                                         X509Certificate caCert, String ocspURL,
                                                         X509Certificate signingCert,
                                                         PrivateKey signingKey)
        throws java.io.IOException,
               java.security.NoSuchProviderException,
               java.security.cert.CertificateEncodingException,
               org.bouncycastle.cert.ocsp.OCSPException,
               org.bouncycastle.operator.OperatorCreationException {

        return OCSPToolkit.verifyX509CertificateUsingOCSP(
            certs, caCert, ocspURL, signingCert, signingKey);
    }
}
