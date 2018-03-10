package deors.core.security;

import static org.easymock.EasyMock.capture;
import static org.easymock.EasyMock.createMock;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.net.URLConnection;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.activation.CommandMap;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;

import org.easymock.Capture;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;

public class SecurityToolkitTestCase {

    private static String proxyHost = null;
    private static String proxyPort = null;

    public SecurityToolkitTestCase() {

        super();
    }

    @BeforeClass
    public static void saveProxy() {

        proxyHost = System.getProperty("https.proxyHost");
        proxyPort = System.getProperty("https.proxyPort");
    }

    @AfterClass
    public static void restoreProxy() {

        if (proxyHost != null) {
            System.setProperty("https.proxyHost", proxyHost);
        }
        if (proxyPort != null) {
            System.setProperty("https.proxyPort", proxyPort);
        }
    }

    @Test
    public void testSMIMEHandler() {

        SecurityToolkit.prepareSMIMEHandlersBC();

        String[] mimeTypes = CommandMap.getDefaultCommandMap().getMimeTypes();

        assertTrue(assertArrayContains("application/x-pkcs7-signature", mimeTypes));
        assertTrue(assertArrayContains("application/pkcs7-signature", mimeTypes));
        assertTrue(assertArrayContains("application/x-pkcs7-mime", mimeTypes));
        assertTrue(assertArrayContains("application/pkcs7-mime", mimeTypes));
        assertTrue(assertArrayContains("multipart/signed", mimeTypes));
    }

    private boolean assertArrayContains(String contains, String[] array) {

        for (String elem : array) {
            if (contains.equals(elem)) {
                return true;
            }
        }

        return false;
    }

    @Ignore
    @Test
    public void testSSLContext() throws NoSuchProviderException, NoSuchAlgorithmException, KeyStoreException, CertificateException, IOException, KeyManagementException, UnrecoverableKeyException {

        KeyStore ks = CertificateToolkit.readJKSKeyStore(
            this.getClass().getResourceAsStream("/ac13406900.jks"), "dotdesa".toCharArray());
        X509Certificate cert = CertificateToolkit.readX509Certificate(
            this.getClass().getResourceAsStream("/ac13406109.cer"));

        SSLContext ctx = SecurityToolkit.prepareSSLContext(ks, "dotdesa".toCharArray(), cert);

        assertEquals("SSL", ctx.getProtocol());
        assertTrue(ctx.getProvider().toString().contains("SunJSSE"));
    }

    @Test
    public void testSSLContextNoServer() throws NoSuchProviderException, NoSuchAlgorithmException, KeyStoreException, CertificateException, IOException, KeyManagementException, UnrecoverableKeyException {

        KeyStore ks = CertificateToolkit.readJKSKeyStore(
            this.getClass().getResourceAsStream("/ac13406900.jks"), "dotdesa".toCharArray());

        SSLContext ctx = SecurityToolkit.prepareSSLContext(ks, "dotdesa".toCharArray(), null);

        assertEquals("SSL", ctx.getProtocol());
        assertTrue(ctx.getProvider().toString().contains("SunJSSE"));
    }

    @Test
    public void testChangeDefaultSSLSocketFactory() throws NoSuchProviderException, NoSuchAlgorithmException, KeyStoreException, CertificateException, IOException, KeyManagementException, UnrecoverableKeyException {

        KeyStore ks = CertificateToolkit.readJKSKeyStore(
            this.getClass().getResourceAsStream("/ac13406900.jks"), "dotdesa".toCharArray());

        SSLContext ctx = SecurityToolkit.prepareSSLContext(ks, "dotdesa".toCharArray(), null);

        SecurityToolkit.changeDefaultSSLSocketFactory(ctx);
    }

    @Test
    public void testURLConnectionForTunnelingNotSecure() {

        URLConnection urlconn = createMock(URLConnection.class);

        replay(urlconn);

        assertEquals(urlconn, SecurityToolkit.checkURLConnectionForSSLTunneling(urlconn));

        verify(urlconn);
    }

    @Test
    public void testURLConnectionForTunnelingSecureNoProxy() {

        System.setProperty("https.proxyHost", "");
        System.setProperty("https.proxyPort", "");

        URLConnection urlconn = createMock(HttpsURLConnection.class);

        replay(urlconn);

        assertEquals(urlconn, SecurityToolkit.checkURLConnectionForSSLTunneling(urlconn));

        verify(urlconn);
    }

    @Test
    public void testURLConnectionForTunnelingSecureProxy() {

        System.setProperty("https.proxyHost", "secureproxy");
        System.setProperty("https.proxyPort", "8080");

        URLConnection urlconn = createMock(HttpsURLConnection.class);

        Capture<SSLTunnelSocketFactory> capturedValues = new Capture<>();
        ((HttpsURLConnection) urlconn).setSSLSocketFactory(capture(capturedValues));

        replay(urlconn);

        assertEquals(urlconn, SecurityToolkit.checkURLConnectionForSSLTunneling(urlconn));

        verify(urlconn);

        SSLTunnelSocketFactory actualValue = capturedValues.getValue();
        assertEquals("secureproxy", actualValue.getProxyHost());
        assertEquals(8080, actualValue.getProxyPort());
    }
}
