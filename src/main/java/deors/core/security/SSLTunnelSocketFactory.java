package deors.core.security;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.net.Socket;
import java.util.Locale;

import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import deors.core.commons.base64.Base64Toolkit;

/**
 * Class used to perform HTTPS tunneling.
 *
 * @author deors
 * @version 1.0
 */
public final class SSLTunnelSocketFactory
    extends SSLSocketFactory
    implements HandshakeCompletedListener {

    /**
     * The socket factory.
     */
    private final SSLSocketFactory factory;

    /**
     * The proxy host name.
     */
    private final String proxyHost;

    /**
     * The proxy port.
     */
    private final int proxyPort;

    /**
     * The proxy user name.
     */
    private String proxyUserName;

    /**
     * The proxy user password.
     */
    private String proxyUserPassword;

    /**
     * US-ASCII encoding identifier.
     */
    private static final String ID_US_ASCII = "US-ASCII"; //$NON-NLS-1$

    /**
     * Handshake connect string.
     */
    private static final String HANDSHAKE_CONNECT = "CONNECT "; //$NON-NLS-1$

    /**
     * Handshake colon string.
     */
    private static final String HANDSHAKE_COLON = ":"; //$NON-NLS-1$

    /**
     * Handshake HTTP header string.
     */
    private static final String HANDSHAKE_HTTP_HEADER = " HTTP/1.0\r\nUser-Agent: "; //$NON-NLS-1$

    /**
     * Handshake HTTP user agent.
     */
    private static final String HANDSHAKE_USER_AGENT = "Java/1.6.0_05"; //$NON-NLS-1$

    /**
     * Handshake end of line string.
     */
    private static final String HANDSHAKE_END_OF_LINE = "\r\n"; //$NON-NLS-1$

    /**
     * Handshake proxy header string.
     */
    private static final String HANDSHAKE_PROXY_HEADER = "Proxy-Authorization: Basic "; //$NON-NLS-1$

    /**
     * Handshake code 200 string.
     */
    private static final String HANDSHAKE_CODE_200 = "200 connection established"; //$NON-NLS-1$

    /**
     * Constructor that sets the proxy host and port.
     *
     * @param proxyHost the proxy host name
     * @param proxyPort the proxy port
     */
    public SSLTunnelSocketFactory(String proxyHost, int proxyPort) {

        super();
        this.factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
        this.proxyHost = proxyHost;
        this.proxyPort = proxyPort;
    }

    /**
     * Constructor that sets the proxy host and port, and the
     * user name and password to access the proxy.
     *
     * @param proxyHost the proxy host name
     * @param proxyPort the proxy port
     * @param proxyUserName the proxy user name
     * @param proxyUserPassword the proxy user password
     */
    public SSLTunnelSocketFactory(String proxyHost, int proxyPort,
                                  String proxyUserName, String proxyUserPassword) {
        super();
        this.factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
        this.proxyHost = proxyHost;
        this.proxyPort = proxyPort;
        this.proxyUserName = proxyUserName;
        this.proxyUserPassword = proxyUserPassword;
    }

    /**
     * Creates and returns a socket.
     *
     * @param host the target host
     * @param port the target port
     *
     * @return the socket
     *
     * @throws java.io.IOException an I/O exception
     */
    public Socket createSocket(String host, int port)
        throws java.io.IOException {

        return createSocket(null, host, port, true);
    }

    /**
     * Creates and returns a socket.
     *
     * @param host the target host
     * @param port the target port
     *
     * @return the socket
     *
     * @throws java.io.IOException an I/O exception
     */
    public Socket createSocket(InetAddress host, int port)
        throws java.io.IOException {

        return createSocket(null, host.getHostName(), port, true);
    }

    /**
     * Creates and returns a socket.
     *
     * @param host the target host
     * @param port the target port
     * @param clientHost the client host (ignored)
     * @param clientPort the client port (ignored)
     *
     * @return the socket
     *
     * @throws java.io.IOException an I/O exception
     */
    public Socket createSocket(String host, int port, String clientHost, int clientPort)
        throws java.io.IOException {

        return createSocket(null, host, port, true);
    }

    /**
     * Creates and returns a socket.
     *
     * @param host the target host
     * @param port the target port
     * @param clientHost the client host (ignored)
     * @param clientPort the client host (ignored)
     *
     * @return the socket
     *
     * @throws java.io.IOException an I/O exception
     */
    public Socket createSocket(String host, int port, InetAddress clientHost, int clientPort)
        throws java.io.IOException {

        return createSocket(null, host, port, true);
    }

    /**
     * Creates and returns a socket.
     *
     * @param host the target host
     * @param port the target port
     * @param clientHost the client host (ignored)
     * @param clientPort the client host (ignored)
     *
     * @return the socket
     *
     * @throws java.io.IOException an I/O exception
     */
    public Socket createSocket(InetAddress host, int port,
                               InetAddress clientHost, int clientPort)
        throws java.io.IOException {

        return createSocket(null, host.getHostName(), port, true);
    }

    /**
     * Returns a socket layered over an existing socket connected
     * to the named host, at the given port.
     *
     * @param socket the existing socket
     * @param host the target host
     * @param port the target port
     * @param autoClose whether the underlying socket will be closed when this socket is closed
     *
     * @return the socket
     *
     * @throws java.io.IOException an I/O exception
     */
    public Socket createSocket(Socket socket, String host, int port, boolean autoClose)
        throws java.io.IOException {

        Socket tunnel = new Socket(proxyHost, proxyPort);

        doTunnelHandshake(tunnel, host, port);

        SSLSocket result = (SSLSocket) factory.createSocket(tunnel, host, port, autoClose);

        result.addHandshakeCompletedListener(this);

        //result.startHandshake();

        return result;
    }

    /**
     * Method executed when the <code>HandshakeCompleted</code> event is raised.
     *
     * @param event the <code>HandshakeCompleted</code> event
     */
    public void handshakeCompleted(HandshakeCompletedEvent event) {

        // the cipher suite is: event.getCipherSuite()
        // the session id is: event.getSession()
        // the peer host is: event.getSession().getPeerHost()
    }

    /**
     * Method that performs the tunnel handshake.
     *
     * @param tunnel the socket connected to the proxy
     * @param host the target host
     * @param port the target port
     *
     * @throws java.io.IOException an I/O exception
     */
    private void doTunnelHandshake(Socket tunnel, String host, int port)
        throws java.io.IOException {

        final int replyBufferSize = 200;

        OutputStream out = tunnel.getOutputStream();

        StringBuilder sb = new StringBuilder();
        sb.append(HANDSHAKE_CONNECT);
        sb.append(host);
        sb.append(HANDSHAKE_COLON);
        sb.append(port);
        sb.append(HANDSHAKE_HTTP_HEADER);
        sb.append(HANDSHAKE_USER_AGENT);
        sb.append(HANDSHAKE_END_OF_LINE);

        if (proxyUserName != null && proxyUserPassword != null) {
            sb.append(HANDSHAKE_PROXY_HEADER);

            StringBuilder sbAuth = new StringBuilder(proxyUserName);
            sbAuth.append(HANDSHAKE_COLON);
            sbAuth.append(proxyUserPassword);

            sb.append(Base64Toolkit.encode(sbAuth.toString()));
            sb.append(HANDSHAKE_END_OF_LINE);
        }

        sb.append(HANDSHAKE_END_OF_LINE);

        String httpMessage = sb.toString();
        byte[] b;

        try {
            // ASCII7 is mandatory for HTTP communications
            b = httpMessage.getBytes(ID_US_ASCII);
        } catch (UnsupportedEncodingException ignored) {
            b = httpMessage.getBytes();
        }

        out.write(b);
        out.flush();

        byte[] reply = new byte[replyBufferSize];
        int replyLen = 0;
        int newLinesSeen = 0;
        boolean headerDone = false;

        InputStream in = tunnel.getInputStream();

        while (newLinesSeen < 2) {
            int i = in.read();
            if (i < 0) {
                throw new IOException(SecurityContext.getMessage("SSLTUN_ERR_EOF_FROM_PROXY")); //$NON-NLS-1$
            }

            if (i == '\n') {
                headerDone = true;
                ++newLinesSeen;
            } else if (i != '\r') {
                newLinesSeen = 0;
                if (!headerDone && replyLen < reply.length) {
                    reply[replyLen++] = (byte) i;
                }
            }
        }

        String replyStr = null;
        try {
            // ASCII7 is mandatory for HTTP communications
            replyStr = new String(reply, 0, replyLen, ID_US_ASCII);
        } catch (UnsupportedEncodingException ignored) {
            replyStr = new String(reply, 0, replyLen);
        }

        if (replyStr.toLowerCase(Locale.getDefault()).indexOf(HANDSHAKE_CODE_200) == -1) {
            throw new IOException(SecurityContext.getMessage(
                "SSLTUN_ERR_UNABLE_TO_TUNNEL", //$NON-NLS-1$
                new String[] {proxyHost, Integer.toString(proxyPort), replyStr}));
        }
    }

    /**
     * Returns the default cipher suites.
     *
     * @return the default cipher suites
     */
    public String[] getDefaultCipherSuites() {

        return factory.getDefaultCipherSuites();
    }

    /**
     * Returns the supported cipher suites.
     *
     * @return the supported cipher suites
     */
    public String[] getSupportedCipherSuites() {

        return factory.getSupportedCipherSuites();
    }

    /**
     * Returns the <code>factory</code> property value.
     *
     * @return the property value
     *
     * @see SSLTunnelSocketFactory#factory
     */
    public SSLSocketFactory getFactory() {

        return factory;
    }

    /**
     * Returns the <code>proxyHost</code> property value.
     *
     * @return the property value
     *
     * @see SSLTunnelSocketFactory#proxyHost
     */
    public String getProxyHost() {

        return proxyHost;
    }

    /**
     * Returns the <code>proxyPort</code> property value.
     *
     * @return the property value
     *
     * @see SSLTunnelSocketFactory#proxyPort
     */
    public int getProxyPort() {

        return proxyPort;
    }

    /**
     * Returns the <code>proxyUserName</code> property value.
     *
     * @return the property value
     *
     * @see SSLTunnelSocketFactory#proxyUserName
     */
    public String getProxyUserName() {

        return proxyUserName;
    }

    /**
     * Returns the <code>proxyUserPassword</code> property value.
     *
     * @return the property value
     *
     * @see SSLTunnelSocketFactory#proxyUserPassword
     */
    public String getProxyUserPassword() {

        return proxyUserPassword;
    }
}
