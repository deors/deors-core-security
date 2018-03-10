package deors.core.security;

import static org.easymock.EasyMock.createMock;
import static org.junit.Assert.assertEquals;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import org.junit.Test;

public class KeyStoreEntryTestCase {

    public KeyStoreEntryTestCase() {

        super();
    }

    @Test
    public void testDefaultConstructorGettersAndSetters() {

        X509Certificate cert = createMock(X509Certificate.class);
        PrivateKey key = createMock(PrivateKey.class);

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

        X509Certificate cert = createMock(X509Certificate.class);
        PrivateKey key = createMock(PrivateKey.class);

        KeyStoreEntry kse = new KeyStoreEntry("alias", cert, key);

        assertEquals("alias", kse.getAlias());
        assertEquals(cert, kse.getCertificate());
        assertEquals(key, kse.getPrivateKey());
    }
}
