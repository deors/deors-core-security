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

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

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
     * @throws java.io.IOException an I/O exception
     * @throws java.security.NoSuchProviderException the security provider is not supported
     * @throws java.security.cert.CertificateEncodingException error with certificate encoding
     * @throws org.bouncycastle.cert.ocsp.OCSPException an exception preparing the OCSP request
     *                                                  or parsing the OCSP response
     * @throws org.bouncycastle.operator.OperatorCreationException error creating the operator
     */
    static boolean verifyX509CertificateUsingOCSP(X509Certificate cert,
                                                  X509Certificate caCert)
        throws java.io.IOException,
               java.security.NoSuchProviderException,
               java.security.cert.CertificateEncodingException,
               org.bouncycastle.cert.ocsp.OCSPException,
               org.bouncycastle.operator.OperatorCreationException {

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
     * @throws java.io.IOException an I/O exception
     * @throws java.security.NoSuchProviderException the security provider is not supported
     * @throws java.security.cert.CertificateEncodingException error with certificate encoding
     * @throws org.bouncycastle.cert.ocsp.OCSPException an exception preparing the OCSP request
     *                                                  or parsing the OCSP response
     * @throws org.bouncycastle.operator.OperatorCreationException error creating the operator
     */
    static boolean verifyX509CertificateUsingOCSP(List<X509Certificate> certs,
                                                  X509Certificate caCert)
        throws java.io.IOException,
               java.security.NoSuchProviderException,
               java.security.cert.CertificateEncodingException,
               org.bouncycastle.cert.ocsp.OCSPException,
               org.bouncycastle.operator.OperatorCreationException {

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
     * @throws java.io.IOException an I/O exception
     * @throws java.security.NoSuchProviderException the security provider is not supported
     * @throws java.security.cert.CertificateEncodingException error with certificate encoding
     * @throws org.bouncycastle.cert.ocsp.OCSPException an exception preparing the OCSP request
     *                                                  or parsing the OCSP response
     * @throws org.bouncycastle.operator.OperatorCreationException error creating the operator
     */
    static boolean verifyX509CertificateUsingOCSP(X509Certificate cert,
                                                  X509Certificate caCert, String ocspURL)
        throws java.io.IOException,
               java.security.NoSuchProviderException,
               java.security.cert.CertificateEncodingException,
               org.bouncycastle.cert.ocsp.OCSPException,
               org.bouncycastle.operator.OperatorCreationException {

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
     * @throws java.io.IOException an I/O exception
     * @throws java.security.NoSuchProviderException the security provider is not supported
     * @throws java.security.cert.CertificateEncodingException error with certificate encoding
     * @throws org.bouncycastle.cert.ocsp.OCSPException an exception preparing the OCSP request
     *                                                  or parsing the OCSP response
     * @throws org.bouncycastle.operator.OperatorCreationException error creating the operator
     */
    static boolean verifyX509CertificateUsingOCSP(List<X509Certificate> certs,
                                                  X509Certificate caCert, String ocspURL)
        throws java.io.IOException,
               java.security.NoSuchProviderException,
               java.security.cert.CertificateEncodingException,
               org.bouncycastle.cert.ocsp.OCSPException,
               org.bouncycastle.operator.OperatorCreationException {

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
     * @throws java.io.IOException an I/O exception
     * @throws java.security.NoSuchProviderException the security provider is not supported
     * @throws java.security.cert.CertificateEncodingException error with certificate encoding
     * @throws org.bouncycastle.cert.ocsp.OCSPException an exception preparing the OCSP request
     *                                                  or parsing the OCSP response
     * @throws org.bouncycastle.operator.OperatorCreationException error creating the operator
     */
    static boolean verifyX509CertificateUsingOCSP(X509Certificate cert,
                                                  X509Certificate caCert, String ocspURL,
                                                  X509Certificate signingCert,
                                                  PrivateKey signingKey)
        throws java.io.IOException,
               java.security.NoSuchProviderException,
               java.security.cert.CertificateEncodingException,
               org.bouncycastle.cert.ocsp.OCSPException,
               org.bouncycastle.operator.OperatorCreationException {

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
     * @throws java.io.IOException an I/O exception
     * @throws java.security.NoSuchProviderException the security provider is not supported
     * @throws java.security.cert.CertificateEncodingException error with certificate encoding
     * @throws org.bouncycastle.cert.ocsp.OCSPException an exception preparing the OCSP request
     *                                                  or parsing the OCSP response
     * @throws org.bouncycastle.operator.OperatorCreationException error creating the operator
     */
    static boolean verifyX509CertificateUsingOCSP(List<X509Certificate> certs,
                                                  X509Certificate caCert, String ocspURL,
                                                  X509Certificate signingCert,
                                                  PrivateKey signingKey)
        throws java.io.IOException,
               java.security.NoSuchProviderException,
               java.security.cert.CertificateEncodingException,
               org.bouncycastle.cert.ocsp.OCSPException,
               org.bouncycastle.operator.OperatorCreationException {

        final int httpOk = 200;

        DataOutputStream dataOut = null;

        try {
            // the OCSP request is built
            OCSPReqBuilder ocspBuilder = new OCSPReqBuilder();

            // provide the digest calculator
            JcaDigestCalculatorProviderBuilder digestBuilder =
                new JcaDigestCalculatorProviderBuilder();
            DigestCalculatorProvider digestProvider =
                digestBuilder.build();
            DigestCalculator digestCalculator =
                digestProvider.get(CertificateID.HASH_SHA1);

            // the certificates to be verified are added to the request
            for (X509Certificate cert : certs) {
                ocspBuilder.addRequest(
                    new CertificateID(
                        digestCalculator,
                        new JcaX509CertificateHolder(caCert),
                        cert.getSerialNumber()));
            }

            // generates the OCSP request
            OCSPReq request = null;

            if (signingCert == null || signingKey == null) {
                request = ocspBuilder.build();
            } else {
                // the request is digitally signed
                ocspBuilder.setRequestorName(
                    new JcaX509CertificateHolder(signingCert).getSubject());

                ContentSigner signer = new JcaContentSignerBuilder(OCSP_SIGNATURE_ALGORITHM)
                    .build(signingKey);

                request =
                    ocspBuilder.build(signer,
                        new X509CertificateHolder[] {new JcaX509CertificateHolder(signingCert)});
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
            if (httpStatus != httpOk) {
                throw new java.io.IOException(SecurityContext.getMessage(
                    "CERT_ERR_OCSP_HTTP_RESPONSE_NOT_200", String.valueOf(httpStatus))); //$NON-NLS-1$
            }

            // the HTTP response contents are read
            // and the OCSP response is parsed
            InputStream is = (InputStream) httpconn.getContent();
            OCSPResp response = new OCSPResp(is);

            int responseStatus = response.getStatus();
            if (responseStatus == OCSPResp.SUCCESSFUL) {
                return processSuccessfulResponse(response, caCert);
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
     * @param caCert the certificate of the CA that issued all the certificates that will be
     *               verified
     *
     * @return whether the certificates have not been revoked
     *
     * @throws java.security.NoSuchProviderException the security provider is not supported
     * @throws org.bouncycastle.cert.ocsp.OCSPException an exception preparing the OCSP request
     *                                                  or parsing the OCSP response
     * @throws org.bouncycastle.operator.OperatorCreationException error creating the operator
     */
    private static boolean processSuccessfulResponse(OCSPResp response,
                                                     X509Certificate caCert)
        throws java.security.NoSuchProviderException,
               org.bouncycastle.cert.ocsp.OCSPException,
               org.bouncycastle.operator.OperatorCreationException {

        BasicOCSPResp basicResponse = (BasicOCSPResp) response.getResponseObject();

        // validates the OCSP response signature
        boolean responseSignatureValid =
            basicResponse.isSignatureValid(
                new JcaContentVerifierProviderBuilder().build(caCert));

        if (!responseSignatureValid) {
            throw new OCSPException(
                SecurityContext.getMessage("CERT_ERR_OCSP_RESPONSE_SIGNATURE_NOT_VALID")); //$NON-NLS-1$
        }

        SingleResp[] singleResponses = basicResponse.getResponses();

        if (singleResponses.length != 0) {
            for (int i = 0; i < singleResponses.length; i++) {
                SingleResp singleResponse = singleResponses[i];

                Object certStatus = singleResponse.getCertStatus();
                if (certStatus instanceof org.bouncycastle.cert.ocsp.RevokedStatus) {
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

        if (responseStatus == OCSPResp.MALFORMED_REQUEST) {
            error = new OCSPException(SecurityContext.getMessage("CERT_ERR_OCSP_RESPONSE_STATUS_1")); //$NON-NLS-1$
        } else if (responseStatus == OCSPResp.INTERNAL_ERROR) {
            error = new OCSPException(SecurityContext.getMessage("CERT_ERR_OCSP_RESPONSE_STATUS_2")); //$NON-NLS-1$
        } else if (responseStatus == OCSPResp.TRY_LATER) {
            error = new OCSPException(SecurityContext.getMessage("CERT_ERR_OCSP_RESPONSE_STATUS_3")); //$NON-NLS-1$
        } else if (responseStatus == OCSPResp.SIG_REQUIRED) {
            error = new OCSPException(SecurityContext.getMessage("CERT_ERR_OCSP_RESPONSE_STATUS_5")); //$NON-NLS-1$
        } else if (responseStatus == OCSPResp.UNAUTHORIZED) {
            error = new OCSPException(SecurityContext.getMessage("CERT_ERR_OCSP_RESPONSE_STATUS_6")); //$NON-NLS-1$
        }

        return error;
    }
}
