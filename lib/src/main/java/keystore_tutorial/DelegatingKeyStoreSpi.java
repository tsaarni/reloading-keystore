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
import java.security.spec.InvalidKeySpecException;
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
 * Implementation of {@code KeyStoreSpi} that delegates calls to an instance of {@code KeyStore}.
 * The delegate keystore can be replaced on demand when the underlying certificate(s) and key(s) change.
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
    abstract void refresh() throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException,
            InvalidKeySpecException;

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
            log.debug("Failed to refresh:", e);
            e.printStackTrace();
        }
    }

    /**
     * Replace the {@code KeyStore} delegate,
     *
     * @param delegate KeyStore instance that becomes the delegate.
     */
    void setKeyStoreDelegate(KeyStore delegate) {
        log.debug("Setting new KeyStore delegate");
        this.delegate.set(new Delegate(delegate));
    }

    @Override
    public Key engineGetKey(String alias, char[] password) throws NoSuchAlgorithmException, UnrecoverableKeyException {
        refreshCachedKeyStore();

        try {
            log.debug("engineGetKey(alias={}, password={})", alias, password != null ? "<masked>" : "<null>");
            return delegate.get().keyStore.getKey(alias, password);
        } catch (KeyStoreException e) {
            log.error("getKey() failed", e);
            return null;
        } catch (UnrecoverableKeyException e) {
            // The exception is thrown when given keystore entry password was incorrect.
            // X509KeyManager.getEntry() hides the error by catching and ignoring the exception.
            // To help troubleshooting, we catch the exception here and print loud error.
            log.error("getKey() failed", e);
            e.printStackTrace();
            throw e;
        }
    }

    @Override
    public Certificate[] engineGetCertificateChain(String alias) {
        refreshCachedKeyStore();

        try {
            log.debug("engineGetCertificateChain(alias={})", alias);
            return delegate.get().keyStore.getCertificateChain(alias);
        } catch (KeyStoreException e) {
            log.error("getCertificateChain() failed:", e);
            return new Certificate[0];
        }
    }

    @Override
    public Certificate engineGetCertificate(String alias) {
        refreshCachedKeyStore();

        try {
            log.debug("engineGetCertificate(alias={})", alias);
            return delegate.get().keyStore.getCertificate(alias);
        } catch (KeyStoreException e) {
            log.error("getCertificate() failed:", e);
            return null;
        }
    }

    @Override
    public Date engineGetCreationDate(String alias) {
        refreshCachedKeyStore();

        try {
            Date result = delegate.get().keyStore.getCreationDate(alias);
            log.debug("engineGetCreationDate(alias={}) -> {}", alias, result);
            return result;
        } catch (KeyStoreException e) {
            log.error("getCreationDate() failed:", e);
            return null;
        }
    }

    /**
     * Return aliases in sorted order.
     * This is different than the order used by underlying KeyStore.
     * Sorting aliases enables user to have expected fallback behavior when KeyManager selects server certificate.
     * This can be useful in cases when client does not set TLS SNI or unknown SNI servername is requested.
     */
    @Override
    public Enumeration<String> engineAliases() {
        refreshCachedKeyStore();

        log.debug("engineAliases() -> {}", delegate.get().sortedAliases);
        return Collections.enumeration(new ArrayList<>(delegate.get().sortedAliases));
    }

    @Override
    public boolean engineContainsAlias(String alias) {
        refreshCachedKeyStore();

        try {
            boolean result = delegate.get().keyStore.containsAlias(alias);
            log.debug("engineContainsAlias(alias={}) -> {}", alias, result);
            return result;
        } catch (KeyStoreException e) {
            log.error("containsAlias() failed:", e);
            return false;
        }
    }

    @Override
    public int engineSize() {
        refreshCachedKeyStore();

        try {
            int result = delegate.get().keyStore.size();
            log.debug("engineSize() -> {}", result);
            return result;
        } catch (KeyStoreException e) {
            log.error("size() failed:", e);
            return 0;
        }
    }

    @Override
    public boolean engineIsKeyEntry(String alias) {
        refreshCachedKeyStore();

        try {
            boolean result = delegate.get().keyStore.isKeyEntry(alias);
            log.debug("engineIsKeyEntry(alias={}) -> {}", alias, result);
            return result;
        } catch (KeyStoreException e) {
            log.error("isKeyEntry() failed:", e);
            return false;
        }
    }

    @Override
    public boolean engineIsCertificateEntry(String alias) {
        refreshCachedKeyStore();

        try {
            boolean result = delegate.get().keyStore.isCertificateEntry(alias);
            log.debug("engineIsCertificateEntry(alias={}) -> {}", alias, result);
            return result;
        } catch (KeyStoreException e) {
            log.error("isCertificateEntry() failed;", e);
            return false;
        }
    }

    @Override
    public String engineGetCertificateAlias(Certificate cert) {
        refreshCachedKeyStore();

        try {
            String result = delegate.get().keyStore.getCertificateAlias(cert);
            log.debug("engineGetCertificateAlias() -> {}", result);
            return result;
        } catch (KeyStoreException e) {
            log.error("getCertificateAlias() failed:", e);
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
                log.error("Failed getting aliases:", e);
            }
        }
    }

}
