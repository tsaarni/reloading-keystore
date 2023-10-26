# Reloading KeyStore

_Implementation Description_

## Rationale

Reloading-keystore addresses following shortcomings of JSSE (Java Secure Socket Extension):

`KeyStore` does not automatically reload its content when underlying file changes.
Why is this a problem?
Let's Encrypt recommends renewing certificates [every 60 days](https://letsencrypt.org/docs/faq/#what-is-the-lifetime-for-let-s-encrypt-certificates-for-how-long-are-they-valid).
Lot shorter renewal period may be used in certain deployments as internal "private" PKI certificates, even down to hours or minutes.
It becomes inconvenient to restart the application every time certificate is rotated.
The ability to reload certificates and private keys at runtime is often referred to as _certificate hot-reload_ or _hitless certificate rotation_.

JSSE does not support loading certificates and private keys in PEM format, even though it is the most likely format for TLS credentials.
User has to go through conversion process to construct PKCS#12 or JKS keystore from the original PEMs.

Multiple server certificates per `KeyStore` are used when server supports virtual hosting for multiple domain names.
There is no way for user to reliably configure which certificate is returned as fallback certificate (default certificate) for clients that do not send [TLS SNI servername](https://en.wikipedia.org/wiki/Server_Name_Indication) or if client sends unknown servername.
For further discussion see [here](https://stackoverflow.com/questions/72446019/how-does-java-pick-default-certificate-when-keystore-has-multiple-server-certifi).

## Implementation

Reloading-keystore is split into following classes

![](reloading-keystore.png)

### PEM Support

[`PemReader`](../lib/src/main/java/fi/protonode/reloadingkeystore/PemReader.java) implements support for reading PEM encoded files consisting of one or more PEM blocks.
When there are more than one block, the file is sometimes referred to as PEM bundle.
For example, PEM bundle may contain several trusted CA certificates.

[`PemCredentialFactory`](../lib/src/main/java/fi/protonode/reloadingkeystore/PemCredentialFactory.java) uses `PemReader` to construct [`Certificate`](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/security/Certificate.html) and [`PrivateKey`](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/security/PrivateKey.html) objects from PEM files.
Private key PEM files are expected to be encoded as unencrypted [PKCS#8](https://en.wikipedia.org/wiki/PKCS_8).
This can be recognized from `-----BEGIN PRIVATE KEY-----` header in the beginning of the file.
RSA and EC key types are supported.

### Implementation(s) of KeyStoreSpi

[`DelegatingKeyStoreSpi`](../lib/src/main/java/fi/protonode/reloadingkeystore/DelegatingKeyStoreSpi.java) is an abstract base class for implementations of [`KeyStoreSpi`](https://github.com/openjdk/jdk17u/blob/master/src/java.base/share/classes/java/security/KeyStoreSpi.java) in this project.
It simply delegates the calls to another instance of [`KeyStore`](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/security/KeyStore.html).
The benefit in this is that the delegate `KeyStore` can be replaced with a new instance when the underlying files have changed.
Application or `KeyManager` does not need to be aware that the delegate instance was replaced.

Since it does not make sense to check the files every time the credentials are used, at least on a busy server, there is a refresh period that sets the cap on how frequently the check happens.
Default cache TTL is one second.
Once that period has expired, the modification timestamp of the files are checked by the `refresh()` method defined in the concrete subclasses.

`DelegatingKeyStoreSpi` sorts the aliases returned by the delegate, allowing user to leverage the predictable ordering to select default certificate.
The alias that comes first alphabetically is the default certificate when using `NewSunX509` algorithm (see "Why use `NewSunX509` key manager?"),

[`ReloadingKeyStoreFileSpi`](../lib/src/main/java/fi/protonode/reloadingkeystore/ReloadingKeyStoreFileSpi.java) is a subclass that reads its input from underlying `PKCS#12` or `JKS` key store file.
It monitors the modification timestamp of the KeyStore file.
When the timestamp is newer than last loaded timestamp, it reads the file again and constructs a new delegate `KeyStore`.

[`ReloadingPemFileKeyStoreSpi`](../lib/src/main/java/fi/protonode/reloadingkeystore/ReloadingPemFileKeyStoreSpi.java) is a subclass that reads its input from underlying certificate and private key PEM files by using `PemCredentialFactory`.
It monitors the modification timestamp of the files.
When the timestamp is newer than the last loaded timestamp, it reads the files again and constructs in-memory `KeyStore` from the PEM files and sets it as delegate.
The KeyStore type used as delegate is PKCS#12.
Since two individual files constitute PEM credentials, user should take care when updating the files on disk so that KeyStore will always serve certificate and private key that belong together.
See topic "Why not use `WatchService`?" below.

### Builder for Reloading KeyStore(s)

[`ReloadingKeyStore`](../lib/src/main/java/fi/protonode/reloadingkeystore/ReloadingKeyStore.java) contains static factory methods to construct [`KeyStores`](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/security/KeyStore.html) of type `ReloadingKeyStore` via the [`KeyStore.Builder`](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/security/KeyStore.html) builder class.
Internally it constructs instances of `ReloadingKeyStoreFileSpi` or `ReloadingPemFileKeyStoreSpi` depending on the use case.

## Background Information

### Why not use `WatchService`?

Java supports monitoring files with [`WatchService`](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/nio/file/WatchService.html).
On Linux it is [implemented](https://github.com/openjdk/jdk17u/blob/master/src/java.base/linux/classes/sun/nio/fs/LinuxWatchService.java) using [inotify](https://en.wikipedia.org/wiki/Inotify).
Instead of using that, the implementation in this project polls file modification timestamp.
While it would be possible to use `WatchService`, there are two major complications in that.

The first complication is that `WatchService` needs a background thread to block on receiving the watch events.
Managing the thread from `KeyStoreSpi` can be challenging.
None of the related classes implement `Closeable`.
There is no explicit call when `KeyStore` is destroyed, that would allow stopping the thread and to free the watch to `close(fd)` the inotify file descriptors.
The `KeyStoreSpi` implementation is several layers deep, buried under `KeyStore` and `KeyManager` interfaces so it is not feasible to add such capability either.
That results in these native resources not being freed in timely manner.
The application can even run out of file descriptors e.g. during unit test execution where a lot of short-lived keystores might be instantiated, or worse, in production.

The second complication is related to the way how the underlying credential files are updated.
Different events will be emitted by the watch depending on the update scheme.
Reloading will quietly fail to happen if the user chose a scheme that the implementation did not support.

Example update schemes include:
1. User may overwrite the existing credential files in place with new content.
2. User may create temporary credential file(s) and then rename them to replace original file(s).
3. User may swap the credential files by manipulating symbolic links, either on the individual file level or directory level.
4. User may swap the credential files by renaming the parent directory.

The update must be done atomically to avoid loading corrupted files or loading a pair of PEM credentials where the certificate does not match the private key since the files were read in the middle of the update.
Not all the above update schemes guarantee atomic file swap.
This may need to be compensated by the implementation if a non-atomic file swap scheme needs to be supported.

In case of Kubernetes `Secret` volume mount, symbolic links are set up pointing to a directory that will be swapped.
The content of all the files change atomically at the time of the directory swap.
As a consequence of the atomic swap, the credential files cannot be monitored directly.
The watch would fail to trigger since it follows the old file(s) that are never updated.
The watch must monitor move operations in a directory where the swap happens.
It needs to consider any move as a possible trigger and check if the content of credential files actually changed.
Single directory move might have caused the symlinks to point to a completely new set of credential files.
See [here](https://github.com/envoyproxy/envoy/issues/9359#issuecomment-579314094) for further description.

There is no single approach to watch files that would work for all schemes.
Users would need to be able to configure watched base directory and the list of watched events.
Simpler approach taken by this project bypasses the above complications with (hopefully) acceptable compromise.

### Why use `KeyStoreSpi`?

There are two alternative approaches to change how TLS credentials are handled:

* Create custom `KeyManager` by extending `X509ExtendedKeyManager`.
* Create custom `KeyStoreSpi` and use it with the default `KeyManager(s)`.

While the first alternative may be used more often, it might not be the best alternative.
Even if the interface seems very similar to `KeyStore` in the first sight, the scope of implementation can be very different.
One may end up implementing TLS features, such as processing the TLS SNI extension.
See `KeyManager` implementations from the JDK for [`NewSunX509`](https://github.com/openjdk/jdk17u/blob/master/src/java.base/share/classes/sun/security/ssl/X509KeyManagerImpl.java) to get an idea about the scope.

The `KeyStoreSpi` is a service provider interface (an extension point) for implementing KeyStores - nothing more.
It has a major benefit of working together with the existing KeyManagers, such as `NewSunX509`, making it possible to benefit from all of the features that existing KeyManagers provide out-of-the-box.

### Why use `NewSunX509` key manager?

While the default KeyManager in JDK 17 is still `SunX509`, there is more advanced `NewSunX509` KeyManager, introduced already in JDK 5.
It has following features ([source](https://github.com/openjdk/jdk17u/blob/master/src/java.base/share/classes/sun/security/ssl/X509KeyManagerImpl.java)):

* It supports KeyStores with multiple certificates and private keys, selecting the most suitable one to return to the peer according to various criteria.
* It is designed for use with KeyStores that change over their lifetime.
* It supports different passwords for each key entry.

The new KeyManager is instantiated by specifying `NewSunX509` as an algorithm name in property `ssl.KeyManagerFactory.algorithm` or by explicitly requesting an instance:

```java
KeyManagerFactory factory = KeyManagerFactory.getInstance("NewSunX509");
```

The different criteria considered by `NewSunX509` when selecting the most suitable certificate are:

* When KeyManager is used by TLS server: pick key entry that matches the TLS SNI servername sent by the client. It also supports wildcard certificate matching. If match is not found the first certificate entry from `KeyStore` is returned as default certificate (see `DelegatingKeyStoreSpi` which sorts entries by alias).
* When KeyManager is used by TLS client: pick key entry that matches the Distinguished Names of supported certificate authorities sent by the server.
* Pick key entry that matches key usage and extended key usage for TLS server or TLS client.
* Pick key entry that matches key type suitable for enabled cipher suites.
* Pick key entry that is valid according to certificate valid from / valid to dates.

One neglected aspect when implementing custom `KeyManager(s)` is the lack of synchronization between two methods called during the TLS handshake: `getCertificateChain(String alias)` and `getPrivateKey(String alias)`.
KeyManager API was not designed for KeyStores that change their content at runtime: what if certificate and private key are updated during the handshake?
The resulting mix of old and new credentials would be invalid.
It could result in infrequent authentication error that might be hard to troubleshoot.
`NewSunX509` [caches](https://github.com/openjdk/jdk17u/blob/84ac0f0de4556472c61a775abd812302765a3395/src/java.base/share/classes/sun/security/ssl/X509KeyManagerImpl.java#L77-L78) the [`PrivateKeyEntry`](https://github.com/openjdk/jdk17u/blob/20f3576cd1bbe516360b0d9f7deaacdad94df4d7/src/java.base/share/classes/java/security/KeyStore.java#L462-L472) instances (a combination of certificate chain and private key) internally to make it more likely it has loaded a consistent set of credentials.
It uses its own [prefixed alias naming scheme](https://github.com/openjdk/jdk17u/blob/84ac0f0de4556472c61a775abd812302765a3395/src/java.base/share/classes/sun/security/ssl/X509KeyManagerImpl.java#L237-L244) to refer to the cached entries.
Calls to get the certificate chain or private key with given alias sticks to the cached key entries.
The calls do not proceed all the way to the `KeyStoreSpi` instance, risking that it would hit credentials that have been updated between calls.
The next round-trip to SPI happens when next server or client alias selection is requested.
The updated credentials will be picked up at that point.

The last improvement in `NewSunX509` might not be something that gets used very often.
Previously only single password for all key entries was possible.
`NewSunX509` uses new [KeyStore.Builder](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/security/KeyStore.Builder.html) API which allows more flexibility: the KeyStore will call `getProtectionParameter(String alias)` which may return different password for each alias.

### Why hot-reloading of truststores does not work?

Java itself does not support truststores that change content during runtime, unlike it does in case of keystores.
[`TrustManagerFactory`](https://github.com/openjdk/jdk17u/blob/9c16e89d275654cee98f5374434bea2097dda91e/src/java.base/share/classes/sun/security/ssl/TrustManagerFactoryImpl.java#L77) fetches the trusted certificates from `KeyStore` at instantiation time, and therefore [`TrustManager`](https://github.com/openjdk/jdk17u/blob/9c16e89d275654cee98f5374434bea2097dda91e/src/java.base/share/classes/sun/security/ssl/X509TrustManagerImpl.java#L79) holds a copy of the trusted certificates in memory.
There is no way to update the certificates cached by `TrustManager` without creating a new instance.

See the test case [`TestReloadingKeyStoreWithTls.testTrustStoreHotReload()`](../lib/src/test/java/fi/protonode/reloadingkeystore/TestReloadingKeyStoreWithTls.java#:~:text=testTrustStoreHotReload) for an example how to implement hot-reloading for truststores.
The example will replace the `TrustManager` instance in `SSLContext` when the underlying truststore file changes.
The same approach can be used to replace the `KeyManager` instance as well.
The difference between keystore with built-in reload support and re-initializing `SSLContext` is that in the latter case each application must monitor the file changes, reload, and update the `SSLContext`, while in the former case, the logic is hidden inside `KeyStore` implementation.
