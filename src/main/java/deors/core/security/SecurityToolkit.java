package deors.core.security;

import java.net.URLConnection;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;

import javax.activation.CommandMap;
import javax.activation.MailcapCommandMap;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Toolkit methods for managing security providers and SSL connections.
 *
 * @author deors
 * @version 1.0
 */
public final class SecurityToolkit {

    /**
     * The Sun JSSE security provider.
     */
    static final String JSSE_SECURITY_PROVIDER = "SunJSSE"; //$NON-NLS-1$

    /**
     * The Bouncy Castle security provider.
     */
    static final String BC_SECURITY_PROVIDER = "BC"; //$NON-NLS-1$

    /**
     * The key store type.
     */
    static final String KEY_STORE_TYPE = "pkcs12"; //$NON-NLS-1$

    /**
     * The key manager type.
     */
    static final String KEY_MANAGER_TYPE = "SunX509"; //$NON-NLS-1$

    /**
     * The secure connection protocol.
     */
    static final String SSL_PROTOCOL = "SSL"; //$NON-NLS-1$

    /**
     * Metamail capabilities entry.
     */
    private static final String MAIL_CAP_PKCS7_SIG = "application/pkcs7-signature;;   x-java-content-handler=org.bouncycastle.mail.smime.handlers.pkcs7_signature"; //$NON-NLS-1$

    /**
     * Metamail capabilities entry.
     */
    private static final String MAIL_CAP_PKCS7_MIME = "application/pkcs7-mime;;        x-java-content-handler=org.bouncycastle.mail.smime.handlers.pkcs7_mime"; //$NON-NLS-1$

    /**
     * Metamail capabilities entry.
     */
    private static final String MAIL_CAP_XPKCS7_SIG = "application/x-pkcs7-signature;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.x_pkcs7_signature"; //$NON-NLS-1$

    /**
     * Metamail capabilities entry.
     */
    private static final String MAIL_CAP_XPKCS7_MIME = "application/x-pkcs7-mime;;      x-java-content-handler=org.bouncycastle.mail.smime.handlers.x_pkcs7_mime"; //$NON-NLS-1$

    /**
     * Metamail capabilities entry.
     */
    private static final String MAIL_CAP_MULTIPART = "multipart/signed;;              x-java-content-handler=org.bouncycastle.mail.smime.handlers.multipart_signed"; //$NON-NLS-1$

    /**
     * The server certificate entry key.
     */
    private static final String SERVER_CERT_ENTRY_KEY = "server"; //$NON-NLS-1$

    /**
     * The HTTPS Proxy Host system property name.
     */
    private static final String HTTPS_PROXY_HOST = "https.proxyHost"; //$NON-NLS-1$

    /**
     * The HTTPS Proxy Port system property name.
     */
    private static final String HTTPS_PROXY_PORT = "https.proxyPort"; //$NON-NLS-1$

    /**
     * Bouncy Castle security provider instance.
     */
    private static final Provider BOUNCY_CASTLE_PROVIDER = new BouncyCastleProvider();

    /**
     * Default constructor. This class is a toolkit and therefore it cannot be instantiated.
     */
    private SecurityToolkit() {
        super();
    }

    /**
     * Prepares the Bouncy Castle security provider.
     */
    public static void prepareProviderBC() {

        if (Security.getProvider(BOUNCY_CASTLE_PROVIDER.getName()) == null) {
            Security.addProvider(BOUNCY_CASTLE_PROVIDER);
        }
    }

    /**
     * Removes the Bouncy Castle security provider.
     */
    public static void removeProviderBC() {

        if (Security.getProvider(BOUNCY_CASTLE_PROVIDER.getName()) != null) {
            Security.removeProvider(BOUNCY_CASTLE_PROVIDER.getName());
        }
    }

    /**
     * Prepares the Bouncy Castle S/MIME handlers.
     */
    public static void prepareSMIMEHandlersBC() {

        MailcapCommandMap mailcap = (MailcapCommandMap) CommandMap.getDefaultCommandMap();

        mailcap.addMailcap(MAIL_CAP_PKCS7_SIG);
        mailcap.addMailcap(MAIL_CAP_PKCS7_MIME);
        mailcap.addMailcap(MAIL_CAP_XPKCS7_SIG);
        mailcap.addMailcap(MAIL_CAP_XPKCS7_MIME);
        mailcap.addMailcap(MAIL_CAP_MULTIPART);

        CommandMap.setDefaultCommandMap(mailcap);
    }

    /**
     * Prepares an SSL context using the given KeyStore to identify this computer and the given
     * X.509 certificate to identify the computer(s) in which to trust. If the X.509 certificate is
     * <code>null</code>, the default TrustManager value is used.
     *
     * @param clientKeyStore the KeyStore that identifies this computer
     * @param keyStorePassword the KeyStore password
     * @param serverCertificate the X.509 certificate that identifies the computer(s) in which to
     *        trust or null to use the default TrustManager value
     *
     * @return the SSL context
     *
     * @throws java.security.NoSuchProviderException the security provider is not supported
     * @throws java.security.NoSuchAlgorithmException the key or trust manager algorithm is not
     *                                                supported
     * @throws java.security.KeyStoreException the key or trust manager could not be initialized
     * @throws java.security.KeyManagementException the SSL context could not be initialized
     * @throws java.security.UnrecoverableKeyException the password is incorrect
     * @throws java.security.cert.CertificateException the client or server certificate could not be
     *                                                 loaded
     * @throws java.io.IOException an I/O exception
     */
    public static SSLContext prepareSSLContext(KeyStore clientKeyStore, char[] keyStorePassword,
                                               X509Certificate serverCertificate)
        throws java.security.NoSuchProviderException,
               java.security.NoSuchAlgorithmException,
               java.security.KeyStoreException,
               java.security.KeyManagementException,
               java.security.UnrecoverableKeyException,
               java.security.cert.CertificateException,
               java.io.IOException {

        KeyManagerFactory kmf =
            KeyManagerFactory.getInstance(KEY_MANAGER_TYPE, JSSE_SECURITY_PROVIDER);
        kmf.init(clientKeyStore, keyStorePassword);

        KeyManager[] km = kmf.getKeyManagers();

        TrustManager[] tm = null;

        if (serverCertificate != null) {
            KeyStore serverKeyStore = KeyStore.getInstance(KEY_STORE_TYPE, JSSE_SECURITY_PROVIDER);
            serverKeyStore.load(null, null);
            serverKeyStore.setCertificateEntry(SERVER_CERT_ENTRY_KEY, serverCertificate);

            TrustManagerFactory tmf =
                TrustManagerFactory.getInstance(KEY_MANAGER_TYPE, JSSE_SECURITY_PROVIDER);
            tmf.init(serverKeyStore);

            tm = tmf.getTrustManagers();
        }

        SSLContext context = SSLContext.getInstance(SSL_PROTOCOL, JSSE_SECURITY_PROVIDER);

        context.init(km, tm, null);

        return context;
    }

    /**
     * Changes the default SSL socket factory using the given SSL context.
     *
     * @param context the SSL context that defines the SSL socket factory
     */
    public static void changeDefaultSSLSocketFactory(SSLContext context) {

        HttpsURLConnection.setDefaultSSLSocketFactory(context.getSocketFactory());
    }

    /**
     * Checks an URL connection to see whether it uses an SSL connection and whether SSL tunneling
     * is required by using the system properties <code>https.proxyHost</code> and
     * <code>https.proxyPort</code>.
     *
     * @param urlconn the URL connection
     *
     * @return the URL connection
     */
    public static URLConnection checkURLConnectionForSSLTunneling(URLConnection urlconn) {

        // in JDK 1.2 and 1.3 with JSSE as an add-on
        // the class sun.net.www.protocol.https.HttpsURLConnectionImpl
        // is used instead of javax.net.ssl.HttpsURLConnection
        if (urlconn instanceof HttpsURLConnection) {

            String proxyHost = System.getProperty(HTTPS_PROXY_HOST);
            String proxyPort = System.getProperty(HTTPS_PROXY_PORT);

            if (proxyHost != null
                && proxyHost.length() != 0
                && proxyPort != null
                && proxyPort.length() != 0) {

                ((HttpsURLConnection) urlconn).setSSLSocketFactory(
                    new SSLTunnelSocketFactory(proxyHost, Integer.parseInt(proxyPort)));
            }
        }

        return urlconn;
    }
}
