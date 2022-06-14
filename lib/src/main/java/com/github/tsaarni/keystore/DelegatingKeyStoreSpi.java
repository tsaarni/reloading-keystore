package com.github.tsaarni.keystore;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class DelegatingKeyStoreSpi extends KeyStoreSpi {

    private static final Logger log = LoggerFactory.getLogger(DelegatingKeyStoreSpi.class);

    // Defines how often the delegate keystore should be checked for updates.
    private static final Duration CACHE_TTL = Duration.of(1, ChronoUnit.SECONDS);

    private AtomicReference<Delegate> delegate = new AtomicReference<>();

    // Defines the next time when to check updates.
    private Instant cacheExpiredTime = Instant.MIN;

    /**
     * Reloads the delegate KeyStore if the underlying files have changed on disk.
     */
    abstract void refresh() throws Exception;

    /**
     * Calls {@link #refresh()} to refresh the cached KeyStore and if more than
     * {@link #cacheTtl} has passed since last
     * refresh.
     */
    private void refreshCachedKeyStore() {
        // Return if not enough time has passed for the delegate KeyStore to be refreshed.
        if (Instant.now().isBefore(cacheExpiredTime)) {
            return;
        }

        // Set the time when refresh should be checked next.
        cacheExpiredTime = Instant.now().plus(CACHE_TTL);

        try {
            refresh();
        } catch (Exception e) {
            log.debug("Failed to refresh: ", e);
        }
    }

    void setKeyStoreDelegate(KeyStore delegate) {
        this.delegate.set(new Delegate(delegate));
    }

    @Override
    public Key engineGetKey(String alias, char[] password) throws NoSuchAlgorithmException, UnrecoverableKeyException {
        refreshCachedKeyStore();
        try {
            return delegate.get().keyStore.getKey(alias, password);
        } catch (KeyStoreException e) {
            log.error("getKey() failed", e);
            return null;
        }
    }

    @Override
    public Certificate[] engineGetCertificateChain(String alias) {
        refreshCachedKeyStore();
        try {
            return delegate.get().keyStore.getCertificateChain(alias);
        } catch (KeyStoreException e) {
            log.error("getCertificateChain() failed ", e);
            return new Certificate[0];
        }
    }

    @Override
    public Certificate engineGetCertificate(String alias) {
        refreshCachedKeyStore();
        try {
            return delegate.get().keyStore.getCertificate(alias);
        } catch (KeyStoreException e) {
            log.error("getCertificate() failed ", e);
            return null;
        }
    }

    @Override
    public Date engineGetCreationDate(String alias) {
        refreshCachedKeyStore();
        try {
            return delegate.get().keyStore.getCreationDate(alias);
        } catch (KeyStoreException e) {
            log.error("getCreationDate() failed ", e);
            return null;
        }
    }

    @Override
    public Enumeration<String> engineAliases() {
        refreshCachedKeyStore();
        // Return aliases in sorted order instead of the order that underlying KeyStore would return them.
        // This allows user to have expected fallback behavior when KeyManager selects server certificate in cases
        // when SNI is not set or unknown SNI servername is requested
        return Collections.enumeration(new ArrayList<>(delegate.get().sortedAliases));
    }

    @Override
    public boolean engineContainsAlias(String alias) {
        refreshCachedKeyStore();
        try {
            return delegate.get().keyStore.containsAlias(alias);
        } catch (KeyStoreException e) {
            log.error("containsAlias() failed) ", e);
            return false;
        }
    }

    @Override
    public int engineSize() {
        refreshCachedKeyStore();
        try {
            return delegate.get().keyStore.size();
        } catch (KeyStoreException e) {
            log.error("size() failed ", e);
            return 0;
        }
    }

    @Override
    public boolean engineIsKeyEntry(String alias) {
        refreshCachedKeyStore();
        try {
            return delegate.get().keyStore.isKeyEntry(alias);
        } catch (KeyStoreException e) {
            log.error("isKeyEntry() failed", e);
            return false;
        }
    }

    @Override
    public boolean engineIsCertificateEntry(String alias) {
        refreshCachedKeyStore();
        try {
            return delegate.get().keyStore.isCertificateEntry(alias);
        } catch (KeyStoreException e) {
            log.error("isCertificateEntry() failed ", e);
            return false;
        }
    }

    @Override
    public String engineGetCertificateAlias(Certificate cert) {
        refreshCachedKeyStore();
        try {
            return delegate.get().keyStore.getCertificateAlias(cert);
        } catch (KeyStoreException e) {
            log.error("getCertificateAlias() failed", e);
            return null;
        }
    }

    @Override
    public void engineLoad(InputStream stream, char[] password)
            throws IOException, NoSuchAlgorithmException, CertificateException {
        // Nothing to do here since implementations of this class have their own means to load certificates and keys.
    }

    private static final String IMMUTABLE_KEYSTORE_ERR = "Modifying keystore is not supported";

    @Override
    public void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain)
            throws KeyStoreException {
        throw new UnsupportedOperationException(IMMUTABLE_KEYSTORE_ERR);
    }

    @Override
    public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain) throws KeyStoreException {
        throw new UnsupportedOperationException(IMMUTABLE_KEYSTORE_ERR);
    }

    @Override
    public void engineSetCertificateEntry(String alias, Certificate cert) throws KeyStoreException {
        throw new UnsupportedOperationException(IMMUTABLE_KEYSTORE_ERR);
    }

    @Override
    public void engineDeleteEntry(String alias) throws KeyStoreException {
        throw new UnsupportedOperationException(IMMUTABLE_KEYSTORE_ERR);
    }

    @Override
    public void engineStore(OutputStream stream, char[] password)
            throws IOException, NoSuchAlgorithmException, CertificateException {
        throw new UnsupportedOperationException(IMMUTABLE_KEYSTORE_ERR);
    }

    class Delegate {
        KeyStore keyStore;
        List<String> sortedAliases;

        Delegate(KeyStore ks) {
            this.keyStore = ks;

            try {
                // Keep aliases sorted to entries returned.
                sortedAliases = Collections.list(ks.aliases());
                Collections.sort(sortedAliases);
            } catch (KeyStoreException e) {
                // Ignore exception.
                log.error("Failed getting aliases: ", e);
            }
        }
    }
}
