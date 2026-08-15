package deors.core.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import org.junit.jupiter.api.Test;

public class KeyStoreEntryTestCase {

    public KeyStoreEntryTestCase() {

        super();
    }

    @Test
    public void testDefaultConstructorGettersAndSetters() {

        X509Certificate cert = mock(X509Certificate.class);
        PrivateKey key = mock(PrivateKey.class);
        KeyStoreEntry kse = new KeyStoreEntry();

        kse.setAlias("alias");
        kse.setCertificate(cert);
        kse.setPrivateKey(key);

        assertEquals("alias", kse.getAlias());
        assertEquals(cert, kse.getCertificate());
        assertEquals(key, kse.getPrivateKey());
    }

    @Test
    public void testConstructorAll() {

        X509Certificate cert = mock(X509Certificate.class);
        PrivateKey key = mock(PrivateKey.class);
        KeyStoreEntry kse = new KeyStoreEntry("alias", cert, key);

        assertEquals("alias", kse.getAlias());
        assertEquals(cert, kse.getCertificate());
        assertEquals(key, kse.getPrivateKey());
    }
}
