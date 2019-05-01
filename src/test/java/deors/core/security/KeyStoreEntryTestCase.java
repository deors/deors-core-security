package deors.core.security;

import static org.junit.Assert.assertEquals;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import org.junit.Test;
import org.junit.runner.RunWith;

import mockit.Mocked;

public class KeyStoreEntryTestCase {

    public KeyStoreEntryTestCase() {

        super();
    }

    @Test
    public void testDefaultConstructorGettersAndSetters(@Mocked X509Certificate cert, @Mocked PrivateKey key) {

        KeyStoreEntry kse = new KeyStoreEntry();

        kse.setAlias("alias");
        kse.setCertificate(cert);
        kse.setPrivateKey(key);

        assertEquals("alias", kse.getAlias());
        assertEquals(cert, kse.getCertificate());
        assertEquals(key, kse.getPrivateKey());
    }

    @Test
    public void testConstructorAll(@Mocked X509Certificate cert, @Mocked PrivateKey key) {

        KeyStoreEntry kse = new KeyStoreEntry("alias", cert, key);

        assertEquals("alias", kse.getAlias());
        assertEquals(cert, kse.getCertificate());
        assertEquals(key, kse.getPrivateKey());
    }
}
