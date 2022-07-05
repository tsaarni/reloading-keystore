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
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * KeyStore that can reload itself when the backing files are modified.
 */
public class ReloadingKeyStore extends KeyStore {

    private static final Logger log = LoggerFactory.getLogger(ReloadingKeyStore.class);

    protected ReloadingKeyStore(KeyStoreSpi keyStoreSpi, Provider provider, String type)
            throws NoSuchAlgorithmException, CertificateException, IOException {
        super(keyStoreSpi, provider, type);

        // Calling load(), even with null arguments, will initialize the KeyStore to
        // expected state.
        load(null, null);
    }

    /**
     * Builder implementation for reloading keystore.
     */
    public static class Builder extends KeyStore.Builder {

        private final KeyStore keyStore;
        private final ProtectionParameter protection;

        // Map<alias, protection>
        private Map<String, ProtectionParameter> aliasProtection;

        private Builder(KeyStore keyStore, char[] password) {
            this.keyStore = keyStore;
            this.protection = new PasswordProtection(password);
        }

        private Builder(KeyStore keyStore, char[] password, Map<String, char[]> aliasPasswords) {
            this.keyStore = keyStore;
            this.protection = new PasswordProtection(password);
            this.aliasProtection = new HashMap<>();
            for (Map.Entry<String, char[]> entry : aliasPasswords.entrySet()) {
                aliasProtection.put(entry.getKey(), new PasswordProtection(entry.getValue()));
            }
        }

        @Override
        public KeyStore getKeyStore() {
            return keyStore;
        }

        @Override
        public ProtectionParameter getProtectionParameter(String newSunAlias) {
            log.debug("getProtectionParameter({})", newSunAlias);

            // Use keystore password, if individual alias passwords are not defined.
            if (aliasProtection == null) {
                return protection;
            }

            // Parse plain alias from NewSunS509 KeyManager prefixed alias.
            // https://github.com/openjdk/jdk/blob/6e55a72f25f7273e3a8a19e0b9a97669b84808e9/src/java.base/share/classes/sun/security/ssl/X509KeyManagerImpl.java#L237-L265
            Objects.requireNonNull(newSunAlias);
            int firstDot = newSunAlias.indexOf('.');
            int secondDot = newSunAlias.indexOf('.', firstDot + 1);
            if ((firstDot == -1) || (secondDot == firstDot)) {
                // TODO: JDK17 does not use prefix anymore.
                return aliasProtection.getOrDefault(newSunAlias, protection);
            }
            String requestedAlias = newSunAlias.substring(secondDot + 1);
            return aliasProtection.getOrDefault(requestedAlias, protection);
        }

        /**
         * Creates KeyStore builder from PKCS#12 or JKS file.
         *
         * @param type KeyStore type such PKCS12 or JKS.
         * @param provider KeyStore provider.
         * @param path Path to the keystore file.
         * @param password Password used to decrypt the KeyStore.
         * @return The KeyStore builder.
         */
        public static KeyStore.Builder fromKeyStoreFile(String type, String provider, Path path, String password)
                throws NoSuchAlgorithmException, CertificateException, KeyStoreException,
                NoSuchProviderException, IOException {
            return new Builder(new ReloadingKeyStore(new ReloadingKeyStoreFileSpi(type, provider, path, password), null,
                    "ReloadingKeyStore"), password.toCharArray());
        }

        /**
         * Creates KeyStore builder from PKCS#12 or JKS file.
         *
         * @param type KeyStore type such PKCS12 or JKS.
         * @param provider KeyStore provider.
         * @param path Path to the keystore file.
         * @param password Password used to decrypt the KeyStore.
         * @param aliasPasswords Passwords used to decrypt keystore entries (map of alias -> password).
         * @return The KeyStore builder.
         */
        public static KeyStore.Builder fromKeyStoreFile(String type, String provider, Path path, String password,
                Map<String, char[]> aliasPasswords)
                throws NoSuchAlgorithmException, CertificateException, KeyStoreException,
                NoSuchProviderException, IOException {
            return new Builder(new ReloadingKeyStore(new ReloadingKeyStoreFileSpi(type, provider, path, password), null,
                    "ReloadingKeyStore"), password.toCharArray(), aliasPasswords);
        }

        /**
         * Creates KeyStore builder from list of certificate and key paths.
         * Certificate in position {@code certs[n]} must match the private key in position {@code keys[n]}.
         *
         * @param certs List of paths to certificates.
         * @param keys List of keys to private keys.
         * @return The KeyStore builder.
         */
        public static KeyStore.Builder fromPem(List<Path> certs, List<Path> keys)
                throws NoSuchAlgorithmException, CertificateException, IllegalArgumentException, KeyStoreException,
                InvalidKeySpecException, IOException {

            if (keys.size() < certs.size()) {
                throw new IllegalArgumentException("Missing private key");
            } else if (keys.size() > certs.size()) {
                throw new IllegalArgumentException("Missing X.509 certificate");
            } else if (keys.isEmpty()) {
                throw new IllegalArgumentException("No credentials configured");
            }

            ReloadingPemFileKeyStoreSpi spi = new ReloadingPemFileKeyStoreSpi();

            Iterator<Path> cpi = certs.iterator();
            Iterator<Path> kpi = keys.iterator();
            while (cpi.hasNext() && kpi.hasNext()) {
                spi.addKeyEntry(cpi.next(), kpi.next());
            }

            return new Builder(new ReloadingKeyStore(spi, null, "ReloadingKeyStore"),
                    ReloadingPemFileKeyStoreSpi.IN_MEMORY_KEYSTORE_PASSWORD);
        }

        /**
         * Creates KeyStore builder from certificate and key path.
         *
         * @param cert Path to certificate.
         * @param key Path to private key.
         * @return The KeyStore builder.
         */
        public static KeyStore.Builder fromPem(Path cert, Path key)
                throws NoSuchAlgorithmException, CertificateException, IllegalArgumentException, KeyStoreException,
                InvalidKeySpecException, IOException {

            ReloadingPemFileKeyStoreSpi spi = new ReloadingPemFileKeyStoreSpi();
            spi.addKeyEntry(cert, key);
            return new Builder(new ReloadingKeyStore(spi, null, "ReloadingKeyStore"),
                    ReloadingPemFileKeyStoreSpi.IN_MEMORY_KEYSTORE_PASSWORD);
        }

        /**
         * Creates KeyStore builder from certificate path(s).
         *
         * @param cert Path to certificate.
         * @return The KeyStore builder.
         */
        public static KeyStore.Builder fromPem(Path... cert) throws KeyStoreException, InvalidKeySpecException,
                NoSuchAlgorithmException, CertificateException, IOException {

            ReloadingPemFileKeyStoreSpi spi = new ReloadingPemFileKeyStoreSpi();
            for (Path c : cert) {
                spi.addCertificateEntry(c);
            }
            return new Builder(new ReloadingKeyStore(spi, null, "ReloadingKeyStore"),
                    ReloadingPemFileKeyStoreSpi.IN_MEMORY_KEYSTORE_PASSWORD);
        }
    }

}
