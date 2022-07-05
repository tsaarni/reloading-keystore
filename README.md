
# Java KeyStore SPI tutorial

![](https://github.com/tsaarni/java-keystore-tutorial/workflows/unit-tests/badge.svg)

## Overview

This project is a tutorial on how to implement custom `KeyStoreSpi` with following features:

* Load certificates and private keys directly from `.pem` files, in addition to `.p12` and `.jks` keystore files.
* Automatically reload credentials from disk when the underlying files change.
* Allow user to set fallback certificate which will be used by server when a client does not send SNI extension or sends unknown servername.

These features can be implemented with relatively little code (under 600 lines), without external dependencies and without background threads.

### Shortcomings of Java KeyStores

#### Constructing KeyStore at runtime from PEM files

One shortcoming in Java and JSSE (Java Secure Socket Extension) is that it does not support PEM files, even though it is the most likely format for TLS credentials.
User has to go through conversion process to construct PKCS#12 or JKS keystore from the original PEMs.

#### Hot-reload credentials from disk without application restart

Another shortcoming is that JSSE requires application to be restarted to reload keystore after it has been updated on disk.

Let's Encrypt recommends renewing certificates [every 60 days](https://letsencrypt.org/docs/faq/#what-is-the-lifetime-for-let-s-encrypt-certificates-for-how-long-are-they-valid).
Lot shorter renewal period may be used in certain deployments internally, even down to hours or minutes.
It becomes inconvenient to restart the application every time the certificate is rotated.
The ability to reload certificates and keys at runtime is often referred to as _certificate hot-reload_ or _hitless certificate rotation_.

#### Fallback certificate

Last shortcoming is related to certificate selection when more than one certificate is included in a `KeyStore`.
`NewSunX509` implementation of `X509KeyManager` supports server certificate selection according to TLS SNI (Server Name Indication) sent by the client.
However, JSSE `KeyStores` do not return certificates in order that would allow user to know which certificate will be selected by when the client _does not_ send TLS SNI servername, or sends unknown servername.
Deterministic behavior would be required to implement a feature which is often referred to as _fallback certificate_ or _default certificate_.

The same applies to mutual TLS authentication, where server may not send the distinguished names of accepted authorities.
In this case the client sends given fallback certificate to authenticate itself to the server.


## Show me the code

Let us see from the application developer viewpoint how to use the classes implemented in this tutorial.
Following example shows how to create a TLS server that reads its server credentials from PEM files.
We construct a custom `KeyStore` which will have the special capabilities mentioned previously.
We then pass it to `KeyManager` just like the standard `KeyStores`.

```java
// Create KeyManagerFactory with our KeyStore,
// constructed from two PEM files: server.pem and server-key.pem.
KeyManagerFactory kmf = KeyManagerFactory.getInstance("NewSunX509");
kmf.init(new KeyStoreBuilderParameters(ReloadingKeyStore.Builder.fromPem(
    Paths.get("server.pem"), Paths.get("server-key.pem"))));

// Otherwise continue as with any KeyStore implementation:

// Initialize SSLContext with our KeyManager.
SSLContext ctx = SSLContext.getInstance("TLS");
ctx.init(kmf.getKeyManagers(), null, null);

// Create server socket and start accepting connections.
// Server will query our KeyManager for server credentials
// every time it gets a new connection from the clients.
SSLServerSocketFactory ssf = ctx.getServerSocketFactory();
SSLServerSocket socket = (SSLServerSocket) ssf.createServerSocket(
    8443, 1, InetAddress.getByName("localhost"));

try (SSLSocket client = (SSLSocket) socket.accept()) {
    // ...
}
```

Check [here](https://tsaarni.github.io/java-keystore-tutorial) to see the full API documentation.


### How the reloading KeyStore is implemented

#### What is KeyStoreSpi

> TODO short description with a figure.

#### Overview of the implementation

> TODO: description about the to be written.
