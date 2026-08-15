package deors.core.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.verify;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import jakarta.activation.CommandMap;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.mockito.MockedConstruction;

public class SecurityToolkitTestCase {

    private static String proxyHost = null;
    private static String proxyPort = null;

    public SecurityToolkitTestCase() {

        super();
    }

    @BeforeAll
    public static void saveProxy() {

        proxyHost = System.getProperty("https.proxyHost");
        proxyPort = System.getProperty("https.proxyPort");
    }

    @AfterAll
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

    @Test
    public void testSSLContext() throws NoSuchProviderException, NoSuchAlgorithmException, KeyStoreException, CertificateException, IOException, KeyManagementException, UnrecoverableKeyException {

        KeyStore ks = CertificateToolkit.readJKSKeyStore(
            this.getClass().getResourceAsStream("/certificate3.jks"), "changeit".toCharArray());
        X509Certificate cert = CertificateToolkit.readX509Certificate(
            this.getClass().getResourceAsStream("/certificate1.cer"));

        SSLContext ctx = SecurityToolkit.prepareSSLContext(ks, "changeit".toCharArray(), cert);

        assertEquals("SSL", ctx.getProtocol());
        assertTrue(ctx.getProvider().toString().contains("SunJSSE"));
    }

    @Test
    public void testSSLContextNoServer() throws NoSuchProviderException, NoSuchAlgorithmException, KeyStoreException, CertificateException, IOException, KeyManagementException, UnrecoverableKeyException {

        KeyStore ks = CertificateToolkit.readJKSKeyStore(
            this.getClass().getResourceAsStream("/certificate3.jks"), "changeit".toCharArray());

        SSLContext ctx = SecurityToolkit.prepareSSLContext(ks, "changeit".toCharArray(), null);

        assertEquals("SSL", ctx.getProtocol());
        assertTrue(ctx.getProvider().toString().contains("SunJSSE"));
    }

    @Test
    public void testChangeDefaultSSLSocketFactory() throws NoSuchProviderException, NoSuchAlgorithmException, KeyStoreException, CertificateException, IOException, KeyManagementException, UnrecoverableKeyException {

        KeyStore ks = CertificateToolkit.readJKSKeyStore(
            this.getClass().getResourceAsStream("/certificate3.jks"), "changeit".toCharArray());

        SSLContext ctx = SecurityToolkit.prepareSSLContext(ks, "changeit".toCharArray(), null);

        SecurityToolkit.changeDefaultSSLSocketFactory(ctx);
    }

    @Test
    public void testURLConnectionForTunnelingNotSecure() {

        HttpURLConnection urlconn = mock(HttpURLConnection.class);

        assertEquals(urlconn, SecurityToolkit.checkURLConnectionForSSLTunneling(urlconn));
    }

    @Test
    public void testURLConnectionForTunnelingSecureNoProxy() {

        HttpsURLConnection urlconn = mock(HttpsURLConnection.class);

        System.setProperty("https.proxyHost", "");
        System.setProperty("https.proxyPort", "");

        assertEquals(urlconn, SecurityToolkit.checkURLConnectionForSSLTunneling(urlconn));
    }

    @Test
    public void testURLConnectionForTunnelingSecureProxy() {

        HttpsURLConnection urlconn = mock(HttpsURLConnection.class);

        System.setProperty("https.proxyHost", "secureproxy");
        System.setProperty("https.proxyPort", "8080");

        try (MockedConstruction<SSLTunnelSocketFactory> mocked = mockConstruction(SSLTunnelSocketFactory.class)) {

            assertEquals(urlconn, SecurityToolkit.checkURLConnectionForSSLTunneling(urlconn));

            assertEquals(1, mocked.constructed().size());
            verify(urlconn).setSSLSocketFactory(mocked.constructed().get(0));
        }
    }
}
