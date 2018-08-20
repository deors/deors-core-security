# deors-core-security

collection of high-level APIs to simplify common cryptographic operations

## bill of materials (main components)

* CertificateToolkit: toolkit with common functions to work with digital certificates

* CryptoToolkit: toolkit with common functions to work with cryptographic operations

* CryptoSession: a cryptographic session with given configuration to perform cryptographic operations during durable operations (i.e. no need to initialize classes on every call, consistency of used algorithms and key lengths)

* OCSPToolkit: toolkit with common functions to validate certificates using OCSP

* SecurityToolkit: toolkit with common functions to work with security providers in the JVM

* SSLTunnelSocketFactory: a simple socket factory that do SSL tunneling through a proxy server
