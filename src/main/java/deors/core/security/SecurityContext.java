package deors.core.security;

import deors.core.commons.AbstractContext;

/**
 * The Security Toolkit library context.<br>
 *
 * The context acts as a bridge between the library classes, the configuration properties
 * and the messages stored in the resource bundle created from
 * <code>deors.core.security.configuration.properties</code> properties file).<br>
 *
 * The system property <code>deors.core.security.configuration</code> can be used to inject
 * an alternate properties file.<br>
 *
 * The class is a singleton.
 *
 * @author deors
 * @version 1.0
 */
public final class SecurityContext extends AbstractContext {

    /**
     * The only class instance.
     */
    private static SecurityContext contextInstance = new SecurityContext();

    /**
     * The resource bundle name.
     */
    private static final String BUNDLE_NAME = "deors.core.security.configuration"; //$NON-NLS-1$

    /**
     * A blank string.
     */
    public static final String BLANK = ""; //$NON-NLS-1$

    /**
     * Key name in the properties file for <code>DEFAULT_BUFFER_SIZE</code> property.
     */
    private static final String KN_DEFAULT_BUFFER_SIZE = "security.defaultBufferSize"; //$NON-NLS-1$

    /**
     * Default value for <code>DEFAULT_BUFFER_SIZE</code> property.
     */
    private static final int DV_DEFAULT_BUFFER_SIZE = 4096;

    /**
     * Default buffer size. Configurable in the properties file using the key referenced by the
     * constant <code>KN_DEFAULT_BUFFER_SIZE</code> and <code>DV_DEFAULT_BUFFER_SIZE</code> as
     * the default value.
     *
     * @see SecurityContext#getConfigurationProperty(String, int)
     * @see SecurityContext#KN_DEFAULT_BUFFER_SIZE
     * @see SecurityContext#DV_DEFAULT_BUFFER_SIZE
     */
    public static final int DEFAULT_BUFFER_SIZE =
        getConfigurationProperty(KN_DEFAULT_BUFFER_SIZE, DV_DEFAULT_BUFFER_SIZE);

    /**
     * Default constructor.
     */
    private SecurityContext() {

        super(System.getProperty(BUNDLE_NAME, BUNDLE_NAME), SecurityContext.getContext());
    }

    /**
     * Static method that returns the only class instance.
     *
     * @return the only class instance
     */
    public static SecurityContext getContext() {
        return contextInstance;
    }

    /**
     * Returns a configuration property named by the given key or the default value if the resource
     * bundle could not be located or the key is missing.
     *
     * @param propertyName the property name
     * @param defaultValue the default value
     *
     * @return the property value or the default value if the resource bundle could not be located
     *         or the key is missing
     */
    public static String getConfigurationProperty(String propertyName, String defaultValue) {

        return contextInstance.getIConfigurationProperty(propertyName, defaultValue);
    }

    /**
     * Returns a configuration property named by the given key or the default value if the resource
     * bundle could not be located or the key is missing. The given array defines the property valid
     * values. If the configured value is not in the array the default value is returned.
     *
     * @param propertyName the property name
     * @param defaultValue the default value
     * @param validValues array with the valid values
     *
     * @return the property value or the default value if the resource bundle could not be located
     *         or the key is missing or the value is not a valid one
     */
    public static String getConfigurationProperty(String propertyName, String defaultValue,
                                                  String[] validValues) {

        return contextInstance.getIConfigurationProperty(
            propertyName, defaultValue, validValues);
    }

    /**
     * Returns a configuration property named by the given key converting the value to an integer
     * value or the default value if the resource bundle could not be located or the key is missing
     * or the value could not be converted to an integer value.
     *
     * @param propertyName the property name
     * @param defaultValue the default value
     *
     * @return the property value or the default value if the resource bundle could not be located
     *         or the key is missing or the value could not be converted to an integer value
     */
    public static int getConfigurationProperty(String propertyName, int defaultValue) {

        return contextInstance.getIConfigurationProperty(propertyName, defaultValue);
    }

    /**
     * Returns a configuration property named by the given key converting the first character to a
     * char value or the default value if the resource bundle could not be located or the key is
     * missing or the value could not be converted to a char value.
     *
     * @param propertyName the property name
     * @param defaultValue the default value
     *
     * @return the property value or the default value if the resource bundle could not be located
     *         or the key is missing or the value could not be converted to a char value
     */
    public static char getConfigurationProperty(String propertyName, char defaultValue) {

        return contextInstance.getIConfigurationProperty(propertyName, defaultValue);
    }

    /**
     * Returns a configuration property named by the given key converting the value to a boolean
     * value or the default value if the resource bundle could not be located or the key is missing.
     *
     * @param propertyName the property name
     * @param defaultValue the default value
     *
     * @return the property value or the default value if the resource bundle could not be located
     *         or the key is missing
     */
    public static boolean getConfigurationProperty(String propertyName, boolean defaultValue) {

        return contextInstance.getIConfigurationProperty(propertyName, defaultValue);
    }

    /**
     * Returns a message from the properties file or the message key if the resource bundle could
     * not be located or the key is missing.
     *
     * @param messageKey the message key in the properties file
     *
     * @return the message in the properties file or the message key if the resource bundle could
     *         not be located or the key is missing
     *
     * @see AbstractContext#getIMessage(String)
     */
    public static String getMessage(String messageKey) {

        return contextInstance.getIMessage(messageKey);
    }

    /**
     * Returns a message from the properties file replacing the default token with the given
     * replacement string or the message key if the resource bundle could not be located or the key
     * is missing.
     *
     * @param messageKey the message key in the properties file
     * @param replacementString string to replace the default token
     *
     * @return the message in the properties file with the replacement applied or the message key if
     *         the resource bundle could not be located or the key is missing
     *
     * @see AbstractContext#getIMessage(String, String)
     */
    public static String getMessage(String messageKey, String replacementString) {

        return contextInstance.getIMessage(messageKey, replacementString);
    }

    /**
     * Returns a message from the properties file replacing the first and second token with the given
     * replacement strings or the message key if the resource bundle could not be located or the key
     * is missing.
     *
     * @param messageKey the message key in the properties file
     * @param replacementString1 the first replacement string
     * @param replacementString2 the second replacement string
     *
     * @return the message in the properties file with the replacement applied or the message key if
     *         the resource bundle could not be located or the key is missing
     *
     * @see AbstractContext#getIMessage(String, String, String)
     */
    public static String getMessage(String messageKey, String replacementString1,
                                    String replacementString2) {

        return contextInstance.getIMessage(
            messageKey, replacementString1, replacementString2);
    }

    /**
     * Returns a message from the properties file replacing tokens in the form
     * <code>{<i>n</i>}</code> with the given replacements strings or the message key if the
     * resource bundle could not be located or the key is missing.
     *
     * @param messageKey the message key in the properties file
     * @param replacementStrings strings to replace the tokens
     *
     * @return the message in the properties file with the replacements applied or the message key
     *         if the resource bundle could not be located or the key is missing
     *
     * @see AbstractContext#getIMessage(String, String[])
     */
    public static String getMessage(String messageKey, String[] replacementStrings) {

        return contextInstance.getIMessage(messageKey, replacementStrings);
    }

    /**
     * Returns a message from the properties file replacing the given tokens with the given
     * replacements strings or the message key if the resource bundle could not be located or the
     * key is missing.
     *
     * @param messageKey the message key in the properties file
     * @param replacementTokens tokens that will be replaced from the message
     * @param replacementStrings strings to replace the tokens
     *
     * @return the message in the properties file with the replacements applied or the message key
     *         if the resource bundle could not be located or the key is missing
     *
     * @see AbstractContext#getIMessage(String, String[], String[])
     */
    public static String getMessage(String messageKey, String[] replacementTokens,
                                    String[] replacementStrings) {

        return contextInstance.getIMessage(
            messageKey, replacementTokens, replacementStrings);
    }
}
