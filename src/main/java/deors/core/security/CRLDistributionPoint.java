package deors.core.security;

/**
 * Bean that represents a CRL distribution point.
 *
 * @author deors
 * @version 1.0
 */
public final class CRLDistributionPoint {

    /**
     * The distribution point type. Two constants are used to set the allowed values for the type:
     * <code>CRL_IN_URL</code> and <code>CRL_IN_X500</code>.
     */
    private int type;

    /**
     * The distribution point target. When the CRL is in an URL, the property value will be an URL,
     * and when the CRL is in an X.500 directory, the property will be the DN where the CRL is
     * stored in the directory.
     */
    private String target;

    /**
     * Constant that indicates that the CRL is stored in an URL.
     */
    public static final int CRL_IN_URL = 1;

    /**
     * Constant that indicates that the CRL is stored in an X.500 directory.
     */
    public static final int CRL_IN_X500 = 2;

    /**
     * Default constructor.
     */
    public CRLDistributionPoint() {
        super();
    }

    /**
     * Constructor that sets the type and target of the distribution point.
     *
     * @param type the distribution point type
     * @param target the distribution point target
     *
     * @see CRLDistributionPoint#CRL_IN_URL
     * @see CRLDistributionPoint#CRL_IN_X500
     */
    public CRLDistributionPoint(int type, String target) {
        this();
        setType(type);
        setTarget(target);
    }

    /**
     * Returns the <code>target</code> property value.
     *
     * @return the property value
     *
     * @see CRLDistributionPoint#target
     * @see CRLDistributionPoint#setTarget(String)
     */
    public String getTarget() {
        return target;
    }

    /**
     * Returns the <code>type</code> property value.
     *
     * @return the property value
     *
     * @see CRLDistributionPoint#type
     * @see CRLDistributionPoint#setType(int)
     */
    public int getType() {
        return type;
    }

    /**
     * Sets the <code>target</code> property value.
     *
     * @param target the property new value
     *
     * @see CRLDistributionPoint#target
     * @see CRLDistributionPoint#getTarget()
     */
    public void setTarget(String target) {
        this.target = target;
    }

    /**
     * Sets the <code>type</code> property value.<br>
     *
     * A <code>java.lang.IllegalArgumentException</code> exception is thrown if the distribution
     * point type is not one of the allowed types.
     *
     * @param type the property new value
     *
     * @see CRLDistributionPoint#type
     * @see CRLDistributionPoint#getType()
     * @see CRLDistributionPoint#CRL_IN_URL
     * @see CRLDistributionPoint#CRL_IN_X500
     */
    public void setType(int type) {

        if (type != CRL_IN_URL && type != CRL_IN_X500) {
            throw new IllegalArgumentException(SecurityContext.getMessage("CERT_ERR_CRLDIS_INVALID_TYPE")); //$NON-NLS-1$
        }
        this.type = type;
    }
}
