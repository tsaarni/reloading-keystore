# Reloading KeyStore

Implementation Description

## Rationale

Reloading-keystore addresses following shortcomings of Java and JSSE (Java Secure Socket Extension):

`KeyStore` does not automatically reload its content when underlying file changes.
Why is this a problem?
Let's Encrypt recommends renewing certificates [every 60 days](https://letsencrypt.org/docs/faq/#what-is-the-lifetime-for-let-s-encrypt-certificates-for-how-long-are-they-valid).
Lot shorter renewal period may be used in certain deployments internally, even down to hours or minutes.
It becomes inconvenient to restart the application every time the certificate is rotated.
The ability to reload certificates and keys at runtime is often referred to as _certificate hot-reload_ or _hitless certificate rotation_.

JSSE does not support certificates and private keys in PEM format, even though it is the most likely format for TLS credentials.
User has to go through conversion process to construct PKCS#12 or JKS keystore from the original PEMs.


Multiple server certificates per `KeyStore` are used when server supports virtual hosting for multiple domain names.
There is no way for user to reliably configure which certificate is returned as fallback certificate (default certificate) for clients that do not send TLS SNI servername. See [StackOverflow discussion](https://stackoverflow.com/questions/72446019/how-does-java-pick-default-certificate-when-keystore-has-multiple-server-certifi).

## Implementation

Reloading-keystore is split into following areas and classes

### PEM Support

[`PemReader`](../lib/src/main/java/fi/protonode/reloadingkeystore/PemReader.java) implements support for reading PEM encoded files.
A file consists of one or more PEM blocks.
When there is more than one block, the file is sometimes referred to as PEM bundle.
For example, PEM bundle may contain several trusted CA certificates.

[`PemCredentialFactory`](../lib/src/main/java/fi/protonode/reloadingkeystore/PemCredentialFactory.java) uses `PemReader` to construct [`Certificate`](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/security/Certificate.html) and [`PrivateKey`](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/security/PrivateKey.html) objects from PEM files.
Private keys are expected to be encoded as unencrypted [PKCS#8](https://en.wikipedia.org/wiki/PKCS_8).

### Implementation(s) of KeyStoreSpi

[`DelegatingKeyStoreSpi`](../lib/src/main/java/fi/protonode/reloadingkeystore/DelegatingKeyStoreSpi.java) is an abstract base class for implementations of [`KeyStoreSpi`](https://github.com/openjdk/jdk17u/blob/master/src/java.base/share/classes/java/security/KeyStoreSpi.java).
It simply delegates the calls to an instance of existing [`KeyStore`](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/security/KeyStore.html).
The delegate `KeyStore` can be replaced with a new instance when the underlying files have changed.

It does not make sense to check the files every time the credentials are used, at least in a busy server.
Therefore a refresh period is defined (default `CACHE_TTL` is one second).
Once that period has expired, the modification timestamp of the files are are checked.
The check is implemented by the `refresh()` method in the concrete subclasses.

`DelegatingKeyStoreSpi` sorts the aliases returned by the delegate, allowing user to leverage the predictable ordering to select default certificate.
The alias that comes first alphabetically is the default certificate.

[`ReloadingKeyStoreFileSpi`](../lib/src/main/java/fi/protonode/reloadingkeystore/ReloadingKeyStoreFileSpi.java) is a subclass that reads its input from underlying `PKCS#12` or `JKS` key store file.
It monitors the modification timestamp of the file.
When the timestamp is newer it reads the file again and constructs a new delegate `KeyStore`.

[`ReloadingPemFileKeyStoreSpi`](../lib/src/main/java/fi/protonode/reloadingkeystore/ReloadingPemFileKeyStoreSpi.java) is a subclass that reads its input from underlying certificate and private key PEM files by using `PemCredentialFactory`.
It monitors the modification timestamp of the files.
When the timestamp is newer it reads the files again, constructs  in-memory `PKCS#12` `KeyStore` from the PEM files and sets it as delegate.

### Builder for Reloading KeyStore(s)

[`ReloadingKeyStore`](../lib/src/main/java/fi/protonode/reloadingkeystore/ReloadingKeyStore.java) contains factory methods to construct [`KeyStores`](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/security/KeyStore.html) with hot-reload capability from key store and PEM files.
It constructs instances of `ReloadingKeyStoreFileSpi` or `ReloadingPemFileKeyStoreSpi` depending on the use case.

## Background Information

### Why not use `WatchService`?

Java supports monitoring files with [`WatchService`](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/nio/file/WatchService.html).
On Linux it is [implemented](https://github.com/openjdk/jdk17u/blob/master/src/java.base/linux/classes/sun/nio/fs/LinuxWatchService.java) using [inotify](https://en.wikipedia.org/wiki/Inotify).
Instead of using that, the implementation polls file modification timestamp at the time when credentials are requested but still at most with a frequency of `CACHE_TTL`.
While it would be possible to use `WatchService`, there are two major complications in that.

First complication is that `WatchService` needs a background thread to block on receiving the watch events.
Managing the thread from `KeyStoreSpi` implementation can be challenging.
None of the related classes implement `Closeable` and there is no explicit call when `KeyStore` is destroyed, to stop the thread and free the watch i.e. `close(fd)` the inotify file descriptor.
The `KeyStoreSpi` implementation is several layers deep, buried under `KeyStore` and `KeyManager` interfaces so it is not feasible to add such capability either.
This can result in these native resources not being freed in timely manner.
The application can even run out of file descriptors e.g. during unit test execution, or worse, in production use.

Second complication is related to the way how the files are updated.
The files cannot be monitored directly since the content is replaced by an atomic operation - the monitored file is replaced by another file.
Watch on direct file would become invalid at each update.
In case of PEM files, there are two files (certificate and private key) that must be replaced by single atomic operation.
There are different schemes for achieving that.
In case of Kubernetes `Secret` volume mount, symbolic links are set up pointing to a directory that will be swapped.
The content of all files changes atomically at the time the directory is swapped.
There is no single approach to watch files with inotify that would work for all schemes.
User would need to be able to configure watched base directory to work with their scheme.
The implementation needs to consider inotify just as indicative and check if the content of files really changed.
See [here](https://github.com/envoyproxy/envoy/issues/9359#issuecomment-579314094) for further description of the problem.

The simpler file modification time poll-based approach of this implementation bypasses the above complications with (hopefully) acceptable compromise.

### What is  `KeyStoreSpi`?

There are two alternative approaches to change how TLS credentials are handled:

* Create custom `KeyManager` by extending `X509ExtendedKeyManager`.
* Create custom `KeyStoreSpi` and use it with the default `KeyManager(s)`.

While the first alternative may be used more often, it might not be the best alternative.
Even if the interface seems similar to `KeyStore`, the scope of implementation can be very different.
One may end up also implementing TLS features, such as processing the TLS SNI extension.

The `KeyStoreSpi` is a service provider interface (an extension point) for implementing KeyStores.
It has a major benefit of working together with the existing KeyManagers, such as `NewSunX509`, making it possible to benefit from all of its features that it provides out-of-the-box.

### What is `NewSunX509` key manager?

While the default KeyManager JDK 17 is `SunX509`, more advanced `NewSunX509` KeyManager was introduced already in JDK 5.
It has following features ([source code link](https://github.com/openjdk/jdk17u/blob/master/src/java.base/share/classes/sun/security/ssl/X509KeyManagerImpl.java)):

* Supports KeyStore with multiple certificates and keys, selects the most suitable one to return to the peer according to various criteria.
* It is designed to use with KeyStores that change over their lifetime.
* Supports different passwords for each key entry.

It can be instantiated by specifying `NewSunX509` as algorithm name in property `ssl.KeyManagerFactory.algorithm` or by explicitly getting an instance in code:

```java
KeyManagerFactory factory = KeyManagerFactory.getInstance("NewSunX509");
```

The criteria used to select the most suitable certificate:

* When used by TLS server: picks entry from KeyStore that matches the TLS SNI servername sent by the client. It also supports wildcard certificate matching.
* When used by TLS client: picks entry from KeyStore that matches the Distinguished Names of supported certificate authorities sent by the server.
* Picks entry that matches key usage and extended key usage for TLS server or TLS client.
* Picks entry that matches key type suitable for enabled cipher suites.
* Picks entry that is valid according to certificate valid from / valid to dates.

One often neglected aspect of implementing `KeyManager(s)` is the lack of synchronization between two methods called during the TLS handshake: `getCertificateChain(String alias)` and `getPrivateKey(String alias)`.
In theory, it may be that the certificate and private key gets updated in the middle of the call sequence.
If this would happen and e.g. old certificate and new private key used together, it would result in infrequent authentication error that can be hard to troubleshoot.

`NewSunX509` [caches](https://github.com/openjdk/jdk17u/blob/84ac0f0de4556472c61a775abd812302765a3395/src/java.base/share/classes/sun/security/ssl/X509KeyManagerImpl.java#L77-L78) the [`PrivateKeyEntry`](https://github.com/openjdk/jdk17u/blob/20f3576cd1bbe516360b0d9f7deaacdad94df4d7/src/java.base/share/classes/java/security/KeyStore.java#L462-L472) instances (a combination of certificate chain and private key) internally to make it more likely it has a consistent set of credentials.
It uses its own [prefixed alias naming scheme](https://github.com/openjdk/jdk17u/blob/84ac0f0de4556472c61a775abd812302765a3395/src/java.base/share/classes/sun/security/ssl/X509KeyManagerImpl.java#L237-L244) to refer to the cached entries.
Calls to get the certificate chain or private key with given alias sticks to the cache and does not proceed to the `KeyStoreSpi` instance, risking that it would hit credentials that have been updated between calls.
The next round-trip to SPI happens when next server or client alias selection is requested.

Previously only single password for all key entries was possible.
`NewSunX509` uses new [KeyStore.Builder](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/security/KeyStore.Builder.html) API which allows each entry to have different password: the KeyStore will call `getProtectionParameter(String alias)` which may return different password for each alias.
