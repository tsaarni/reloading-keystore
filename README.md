# Reloading KeyStore for Java

![](https://github.com/tsaarni/reloading-keystore/workflows/unit-tests/badge.svg)

## Description

This project is a library that implements custom `KeyStore` with following features:

* Automatically reload credentials from disk when the underlying files change.
* Load certificates and private keys directly from `.pem` files, in addition to `.p12` and `.jks` keystore files.
* Allow user to set fallback certificate which will be used by server when a client does not send TLS SNI extension (Server Name Indication) or sends unknown servername.

These features can be implemented in relatively few lines of code, without external dependencies and without background threads.

Use this project either as a tutorial on how to implement custom `KeyStoreSpi` or import the library directly into your application.

## Documentation

The code is compatible with JDK 8 and above.

See the [implementation description](docs/implementation-description.md)
for details and related background discussion about JSSE (Java Secure Socket Extension).

Read the latest API documentation [here](https://tsaarni.github.io/reloading-keystore).


## Example

Following example shows how to create a TLS server that reads its server credentials from PEM files.
It constructs an instance of custom `KeyStore` which will have the special capabilities mentioned previously.
It is then passed to `KeyManager` just like the standard `KeyStores`.

```java
// Create KeyManagerFactory with our KeyStoreSpi constructed from:
// server.pem and server-key.pem.
KeyManagerFactory kmf = KeyManagerFactory.getInstance("NewSunX509");
kmf.init(new KeyStoreBuilderParameters(ReloadingKeyStore.Builder.fromPem(
    Paths.get("server.pem"), Paths.get("server-key.pem"))));

// Otherwise continue as with any KeyStore implementation:

// Initialize SSLContext with our KeyManager.
SSLContext ctx = SSLContext.getInstance("TLS");
ctx.init(kmf.getKeyManagers(), null, null);

// Create server socket and start accepting connections.
// Server will query our KeyManager for server credentials every time it
// gets a new connection from the clients. Credentials will be reloaded
// automatically when they are updated on disk.
SSLServerSocketFactory ssf = ctx.getServerSocketFactory();
SSLServerSocket socket = (SSLServerSocket) ssf.createServerSocket(
    8443, 1, InetAddress.getByName("localhost"));

try (SSLSocket client = (SSLSocket) socket.accept()) {
    // ...
}
```

For more code examples, see the test suite [here](lib/src/test/java/fi/protonode/reloadingkeystore/).
