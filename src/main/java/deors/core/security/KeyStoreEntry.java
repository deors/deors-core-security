package deors.core.security;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/**
 * Bean that represents a key store entry (alias, X.509 certificate and private key).
 *
 * @author deors
 * @version 1.0
 */
public final class KeyStoreEntry {

    /**
     * The key store entry alias.
     */
    private String alias;

    /**
     * The key store entry X.509 certificate.
     */
    private X509Certificate certificate;

    /**
     * The key store entry private key.
     */
    private PrivateKey privateKey;

    /**
     * Default constructor.
     */
    public KeyStoreEntry() {
        super();
    }

    /**
     * Constructor that sets the alias, the X.509
     * certificate and the private key.
     *
     * @param alias the entry alias
     * @param certificate the entry X.509 certificate
     * @param privateKey the entry private key
     */
    public KeyStoreEntry(String alias, X509Certificate certificate, PrivateKey privateKey) {
        this();
        this.alias = alias;
        this.certificate = certificate;
        this.privateKey = privateKey;
    }

    /**
     * Returns the <code>alias</code> property value.
     *
     * @return the property value
     *
     * @see KeyStoreEntry#alias
     * @see KeyStoreEntry#setAlias(String)
     */
    public String getAlias() {
        return alias;
    }

    /**
     * Returns the <code>certificate</code> property value.
     *
     * @return the property value
     *
     * @see KeyStoreEntry#certificate
     * @see KeyStoreEntry#setCertificate(X509Certificate)
     */
    public X509Certificate getCertificate() {
        return certificate;
    }

    /**
     * Returns the <code>privateKey</code> property value.
     *
     * @return the property value
     *
     * @see KeyStoreEntry#privateKey
     * @see KeyStoreEntry#setPrivateKey(PrivateKey)
     */
    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    /**
     * Sets the <code>alias</code> property value.
     *
     * @param alias the property new value
     *
     * @see KeyStoreEntry#alias
     * @see KeyStoreEntry#getAlias()
     */
    public void setAlias(String alias) {
        this.alias = alias;
    }

    /**
     * Sets the <code>certificate</code> property value.
     *
     * @param certificate the property new value
     *
     * @see KeyStoreEntry#certificate
     * @see KeyStoreEntry#getCertificate()
     */
    public void setCertificate(X509Certificate certificate) {
        this.certificate = certificate;
    }

    /**
     * Sets the <code>privateKey</code> property value.
     *
     * @param privateKey the property new value
     *
     * @see KeyStoreEntry#privateKey
     * @see KeyStoreEntry#getPrivateKey()
     */
    public void setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }
}
