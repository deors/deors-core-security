package deors.core.security;

import java.io.BufferedOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.ocsp.CertificateID;
import org.bouncycastle.ocsp.OCSPException;
import org.bouncycastle.ocsp.OCSPReq;
import org.bouncycastle.ocsp.OCSPReqGenerator;
import org.bouncycastle.ocsp.OCSPResp;
import org.bouncycastle.ocsp.OCSPRespStatus;
import org.bouncycastle.ocsp.SingleResp;

/**
 * Toolkit methods for verifying X.509 certificates using OCSP.
 *
 * @author deors
 * @version 1.0
 */
final class OCSPToolkit {

    /**
     * Application OCSP request MIME type.
     */
    private static final String APPLICATION_OCSP_REQUEST = "application/ocsp-request"; //$NON-NLS-1$

    /**
     * Application OCSP response MIME type.
     */
    private static final String APPLICATION_OCSP_RESPONSE = "application/ocsp-response"; //$NON-NLS-1$

    /**
     * Accept header name.
     */
    private static final String ACCEPT = "Accept"; //$NON-NLS-1$

    /**
     * Content type header name.
     */
    private static final String CONTENT_TYPE = "Content-Type"; //$NON-NLS-1$

    /**
     * Key name in the properties file for <code>DEFAULT_OCSP_RESPONDER_URL</code> property.
     */
    private static final String KN_DEFAULT_OCSP_RESPONDER_URL = "cert.defaultOCSPResponderURL"; //$NON-NLS-1$

    /**
     * Default value for <code>DEFAULT_OCSP_RESPONDER_URL</code> property.
     */
    private static final String DV_DEFAULT_OCSP_RESPONDER_URL =
        "http://apus.cert.fnmt.es/appsUsuario/ocsp/OcspResponder"; //$NON-NLS-1$

    /**
     * Default OCSP responder URL used to verify certificates. Configurable in the properties file
     * using the key referenced by the constant <code>KN_DEFAULT_OCSP_RESPONDER_URL</code> and
     * <code>DV_DEFAULT_OCSP_RESPONDER_URL</code> as the default value.
     *
     * @see SecurityContext#getConfigurationProperty(String, String)
     * @see OCSPToolkit#KN_DEFAULT_OCSP_RESPONDER_URL
     * @see OCSPToolkit#DV_DEFAULT_OCSP_RESPONDER_URL
     */
    private static final String DEFAULT_OCSP_RESPONDER_URL =
        SecurityContext.getConfigurationProperty(KN_DEFAULT_OCSP_RESPONDER_URL,
            DV_DEFAULT_OCSP_RESPONDER_URL);

    /**
     * Key name in the properties file for <code>DEFAULT_OCSP_SIGNATURE_ALGORITHM</code> property.
     */
    private static final String KN_OCSP_SIGNATURE_ALGORITHM = "cert.ocspSignatureAlgorithm"; //$NON-NLS-1$

    /**
     * Default value for <code>DEFAULT_OCSP_SIGNATURE_ALGORITHM</code> property.
     */
    private static final String DV_OCSP_SIGNATURE_ALGORITHM = "SHA1withRSA"; //$NON-NLS-1$

    /**
     * Signature algorithm used to sign OCSP requests. Configurable in the properties file using the
     * key referenced by the constant <code>KN_OCSP_SIGNATURE_ALGORITHM</code> and
     * <code>DV_OCSP_SIGNATURE_ALGORITHM</code> as the default value.
     *
     * @see SecurityContext#getConfigurationProperty(String, String)
     * @see OCSPToolkit#KN_OCSP_SIGNATURE_ALGORITHM
     * @see OCSPToolkit#DV_OCSP_SIGNATURE_ALGORITHM
     */
    private static final String OCSP_SIGNATURE_ALGORITHM =
        SecurityContext.getConfigurationProperty(KN_OCSP_SIGNATURE_ALGORITHM,
            DV_OCSP_SIGNATURE_ALGORITHM);

    /**
     * Default constructor. This class is a toolkit and therefore it cannot be instantiated.
     */
    private OCSPToolkit() {
        super();
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
     * @throws java.security.NoSuchProviderException the security provider is not supported
     * @throws java.io.IOException an I/O exception
     * @throws org.bouncycastle.ocsp.OCSPException an exception preparing the OCSP request or
     *                                             parsing the OCSP response
     */
    static boolean verifyX509CertificateUsingOCSP(X509Certificate cert,
                                                  X509Certificate caCert)
        throws java.security.NoSuchProviderException,
               java.io.IOException,
               org.bouncycastle.ocsp.OCSPException {

        List<X509Certificate> certs = new ArrayList<X509Certificate>();
        certs.add(cert);
        return verifyX509CertificateUsingOCSP(certs, caCert, DEFAULT_OCSP_RESPONDER_URL, null, null);
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
     * @throws java.security.NoSuchProviderException the security provider is not supported
     * @throws java.io.IOException an I/O exception
     * @throws org.bouncycastle.ocsp.OCSPException an exception preparing the OCSP request or
     *                                             parsing the OCSP response
     */
    static boolean verifyX509CertificateUsingOCSP(List<X509Certificate> certs,
                                                  X509Certificate caCert)
        throws java.security.NoSuchProviderException,
               java.io.IOException,
               org.bouncycastle.ocsp.OCSPException {

        return verifyX509CertificateUsingOCSP(certs, caCert, DEFAULT_OCSP_RESPONDER_URL, null, null);
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
     * @throws java.security.NoSuchProviderException the security provider is not supported
     * @throws java.io.IOException an I/O exception
     * @throws org.bouncycastle.ocsp.OCSPException an exception preparing the OCSP request or
     *                                             parsing the OCSP response
     */
    static boolean verifyX509CertificateUsingOCSP(X509Certificate cert,
                                                  X509Certificate caCert, String ocspURL)
        throws java.security.NoSuchProviderException,
               java.io.IOException,
               org.bouncycastle.ocsp.OCSPException {

        List<X509Certificate> certs = new ArrayList<X509Certificate>();
        certs.add(cert);
        return verifyX509CertificateUsingOCSP(certs, caCert, ocspURL, null, null);
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
     * @throws java.security.NoSuchProviderException the security provider is not supported
     * @throws java.io.IOException an I/O exception
     * @throws org.bouncycastle.ocsp.OCSPException an exception preparing the OCSP request or
     *                                             parsing the OCSP response
     */
    static boolean verifyX509CertificateUsingOCSP(List<X509Certificate> certs,
                                                  X509Certificate caCert, String ocspURL)
        throws java.security.NoSuchProviderException,
               java.io.IOException,
               org.bouncycastle.ocsp.OCSPException {

        return verifyX509CertificateUsingOCSP(certs, caCert, ocspURL, null, null);
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
     * @throws java.security.NoSuchProviderException the security provider is not supported
     * @throws java.io.IOException an I/O exception
     * @throws org.bouncycastle.ocsp.OCSPException an exception preparing the OCSP request or
     *                                             parsing the OCSP response
     */
    static boolean verifyX509CertificateUsingOCSP(X509Certificate cert,
                                                  X509Certificate caCert, String ocspURL,
                                                  X509Certificate signingCert,
                                                  PrivateKey signingKey)
        throws java.security.NoSuchProviderException,
               java.io.IOException,
               org.bouncycastle.ocsp.OCSPException {

        List<X509Certificate> certs = new ArrayList<X509Certificate>();
        certs.add(cert);
        return verifyX509CertificateUsingOCSP(certs, caCert, ocspURL, signingCert, signingKey);
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
     * @return whether the certificates have not been revoked
     *
     * @throws java.security.NoSuchProviderException the security provider is not supported
     * @throws java.io.IOException an I/O exception
     * @throws org.bouncycastle.ocsp.OCSPException an exception preparing the OCSP request or
     *                                             parsing the OCSP response
     */
    static boolean verifyX509CertificateUsingOCSP(List<X509Certificate> certs,
                                                  X509Certificate caCert, String ocspURL,
                                                  X509Certificate signingCert,
                                                  PrivateKey signingKey)
        throws java.security.NoSuchProviderException,
               java.io.IOException,
               org.bouncycastle.ocsp.OCSPException {

        final int hundred = 100;

        DataOutputStream dataOut = null;

        try {
            // the OCSP request is built
            OCSPReqGenerator ocspGenerator = new OCSPReqGenerator();

            // the certificates to be verified are added to the request
            for (X509Certificate cert : certs) {
                ocspGenerator.addRequest(
                    new CertificateID(CertificateID.HASH_SHA1, caCert, cert.getSerialNumber()));
            }

            // generates the OCSP request
            OCSPReq request = null;

            if (signingCert == null || signingKey == null) {
                request = ocspGenerator.generate();
            } else {
                // the request is digitally signed
                ocspGenerator.setRequestorName(signingCert.getSubjectX500Principal());

                request =
                    ocspGenerator.generate(OCSP_SIGNATURE_ALGORITHM, signingKey,
                        new X509Certificate[] {signingCert}, SecurityToolkit.BC_SECURITY_PROVIDER);
            }

            // the OCSP request is sent
            // embedded in an HTTP request
            URL url = new URL(ocspURL);

            URLConnection urlconn = url.openConnection();

            urlconn = SecurityToolkit.checkURLConnectionForSSLTunneling(urlconn);

            urlconn.setAllowUserInteraction(false);
            urlconn.setDoInput(true);
            urlconn.setDoOutput(true);
            urlconn.setUseCaches(false);

            urlconn.setRequestProperty(CONTENT_TYPE, APPLICATION_OCSP_REQUEST);
            urlconn.setRequestProperty(ACCEPT, APPLICATION_OCSP_RESPONSE);

            urlconn.connect();

            OutputStream out = urlconn.getOutputStream();
            dataOut = new DataOutputStream(new BufferedOutputStream(out));
            dataOut.write(request.getEncoded());
            dataOut.flush();
            dataOut.close();
            dataOut = null;

            HttpURLConnection httpconn = (HttpURLConnection) urlconn;

            // the HTTP response is read
            int httpStatus = httpconn.getResponseCode();
            if (httpStatus / hundred != 2) {
                throw new java.io.IOException(SecurityContext.getMessage(
                    "CERT_ERR_OCSP_HTTP_RESPONSE_NOT_200", String.valueOf(httpStatus))); //$NON-NLS-1$
            }

            // the HTTP response contents are read
            // and the OCSP response is parsed
            InputStream is = (InputStream) httpconn.getContent();
            OCSPResp response = new OCSPResp(is);

            int responseStatus = response.getStatus();

            if (responseStatus == OCSPRespStatus.SUCCESSFUL) {
                return processSuccessfulResponse(response);
            } else {
                throw processErrorResponse(responseStatus);
            }
        } finally {
            if (dataOut != null) {
                try {
                    dataOut.close();
                } catch (IOException ioe) {
                    ioe = null;
                }
            }
        }
    }

    /**
     * Process a successful response.
     *
     * @param response the OCSP response
     *
     * @return whether the certificates have not been revoked
     *
     * @throws java.security.NoSuchProviderException the security provider is not supported
     * @throws org.bouncycastle.ocsp.OCSPException an exception preparing the OCSP request or
     *                                             parsing the OCSP response
     */
    private static boolean processSuccessfulResponse(OCSPResp response)
        throws OCSPException,
               NoSuchProviderException {

        BasicOCSPResp basicResponse = (BasicOCSPResp) response.getResponseObject();

        // validates the OCSP response signature
        X509Certificate[] responseCertChain =
            basicResponse.getCerts(SecurityToolkit.BC_SECURITY_PROVIDER);
        if (responseCertChain.length != 0) {
            X509Certificate responseSignerCert = responseCertChain[0];
            java.security.PublicKey responseSignerKey = responseSignerCert.getPublicKey();
            boolean responseSignatureValid =
                basicResponse.verify(responseSignerKey, SecurityToolkit.BC_SECURITY_PROVIDER);

            if (!responseSignatureValid) {
                throw new OCSPException(
                    SecurityContext.getMessage("CERT_ERR_OCSP_RESPONSE_SIGNATURE_NOT_VALID")); //$NON-NLS-1$
            }
        }

        SingleResp[] singleResponses = basicResponse.getResponses();

        if (singleResponses.length != 0) {
            for (int i = 0; i < singleResponses.length; i++) {
                SingleResp singleResponse = singleResponses[i];

                Object certStatus = singleResponse.getCertStatus();
                if (certStatus instanceof org.bouncycastle.ocsp.RevokedStatus) {
                    // response status REVOKED (1)
                    return false;
                }
            }
        }

        return true;
    }

    /**
     * Process an error response.
     *
     * @param responseStatus the response error status
     *
     * @return the error object to be thrown
     */
    private static OCSPException processErrorResponse(int responseStatus) {

        OCSPException error = null;

        if (responseStatus == OCSPRespStatus.MALFORMED_REQUEST) {
            error = new OCSPException(SecurityContext.getMessage("CERT_ERR_OCSP_RESPONSE_STATUS_1")); //$NON-NLS-1$
        } else if (responseStatus == OCSPRespStatus.INTERNAL_ERROR) {
            error = new OCSPException(SecurityContext.getMessage("CERT_ERR_OCSP_RESPONSE_STATUS_2")); //$NON-NLS-1$
        } else if (responseStatus == OCSPRespStatus.TRY_LATER) {
            error = new OCSPException(SecurityContext.getMessage("CERT_ERR_OCSP_RESPONSE_STATUS_3")); //$NON-NLS-1$
        } else if (responseStatus == OCSPRespStatus.SIGREQUIRED) {
            error = new OCSPException(SecurityContext.getMessage("CERT_ERR_OCSP_RESPONSE_STATUS_5")); //$NON-NLS-1$
        } else if (responseStatus == OCSPRespStatus.UNAUTHORIZED) {
            error = new OCSPException(SecurityContext.getMessage("CERT_ERR_OCSP_RESPONSE_STATUS_6")); //$NON-NLS-1$
        }

        return error;
    }
}
