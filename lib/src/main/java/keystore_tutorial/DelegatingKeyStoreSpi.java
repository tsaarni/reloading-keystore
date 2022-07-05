/*
 * Copyright Tero Saarni
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package keystore_tutorial;

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

/**
 * Implements {@code KeyStoreSpi} by delegating SPI calls to an instance of {@code KeyStore}.
 * The delegate keystore can be replaced on demand when the underlying certificate(s) and key(s) require that.
 *
 * The class returns aliases in sorted order instead of the order that underlying KeyStore would return them.
 * This allows user to have expected fallback behavior when KeyManager selects server certificate in cases
 * when SNI is not set or unknown SNI servername is requested
 */
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

    /**
     * Replace the {@code KeyStore} delegate,
     *
     * @param delegate KeyStore instance that becomes the delegate.
     */
    void setKeyStoreDelegate(KeyStore delegate) {
        log.debug("New KeyStore delegate set");
        this.delegate.set(new Delegate(delegate));
    }

    @Override
    public Key engineGetKey(String alias, char[] password) throws NoSuchAlgorithmException, UnrecoverableKeyException {
        log.debug("engineGetKey()");
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
        log.debug("engineGetCertificateChain()");
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
        log.debug("engineGetCertificate()");
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
        log.debug("engineGetCreationDate()");
        refreshCachedKeyStore();
        try {
            return delegate.get().keyStore.getCreationDate(alias);
        } catch (KeyStoreException e) {
            log.error("getCreationDate() failed ", e);
            return null;
        }
    }

    /**
     * Return aliases in sorted order instead of the order that underlying KeyStore would return them.
     * This allows user to have expected fallback behavior when KeyManager selects server certificate in cases
     * when SNI is not set or unknown SNI servername is requested
     */
    @Override
    public Enumeration<String> engineAliases() {
        log.debug("engineAliases()");
        refreshCachedKeyStore();
        return Collections.enumeration(new ArrayList<>(delegate.get().sortedAliases));
    }

    @Override
    public boolean engineContainsAlias(String alias) {
        log.debug("engineContainsAlias({})", alias);
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
        log.debug("engineSize()");
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
        log.debug("engineIsKeyEntry()");
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
        log.debug("engineIsCertificateEntry({})", alias);
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
        log.debug("engineGetCertificateAlias()");
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
        log.debug("engineLoad()");
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
