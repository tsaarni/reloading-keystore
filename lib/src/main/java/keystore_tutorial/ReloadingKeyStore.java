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
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * KeyStore that can reload itself when the backing files are modified.
 */
public class ReloadingKeyStore extends KeyStore {

    protected ReloadingKeyStore(KeyStoreSpi keyStoreSpi, Provider provider, String type)
            throws NoSuchAlgorithmException, CertificateException, IOException {
        super(keyStoreSpi, provider, type);

        // Calling load(), even with null arguments, will initialize the KeyStore to expected state.
        load(null, null);
    }

    /**
     * Builder implementation for reloading keystores.
     */
    public static class Builder extends KeyStore.Builder {

        private final KeyStore keyStore;
        private final ProtectionParameter protection;

        private final String alias;
        private final ProtectionParameter aliasProtection;

        private Builder(KeyStore keyStore, String password, String alias, String aliasPassword) {
            this.keyStore = keyStore;
            this.protection = password != null ? new PasswordProtection(password.toCharArray()) : null;
            this.alias = alias;
            this.aliasProtection = aliasPassword != null ? new PasswordProtection(aliasPassword.toCharArray()) : null;
        }

        @Override
        public KeyStore getKeyStore() {
            return keyStore;
        }

        @Override
        public ProtectionParameter getProtectionParameter(String newSunAlias) {
            Objects.requireNonNull(newSunAlias);

            // Parse plain alias from NewSunS509 KeyManager prefixed alias.
            // https://github.com/openjdk/jdk/blob/6e55a72f25f7273e3a8a19e0b9a97669b84808e9/src/java.base/share/classes/sun/security/ssl/X509KeyManagerImpl.java#L237-L265
            int firstDot = newSunAlias.indexOf('.');
            int secondDot = newSunAlias.indexOf('.', firstDot + 1);
            if ((firstDot == -1) || (secondDot == firstDot)) {
                // Invalid alias.
                return protection;
            }
            String requestedAlias = newSunAlias.substring(secondDot + 1);
            if (requestedAlias.equals(alias) && aliasProtection != null) {
                return aliasProtection;
            }
            return protection;
        }

        public static KeyStore.Builder fromKeyStoreFile(String type, String provider, Path path, String password, String alias,
                String aliasPassword) throws NoSuchAlgorithmException, CertificateException, KeyStoreException, NoSuchProviderException, IOException  {
            return new Builder(new ReloadingKeyStore(new ReloadingKeyStoreFileSpi(type, provider, path, password), null,
                    "ReloadingKeyStore"), password, alias, aliasPassword);
        }

        public static KeyStore.Builder fromPem(List<Path> certs, List<Path> keys)
                throws NoSuchAlgorithmException, CertificateException, IllegalArgumentException, KeyStoreException,
                InvalidKeySpecException, IOException {
            return new Builder(
                    new ReloadingKeyStore(new ReloadingPemFileKeyStoreSpi(certs, keys), null, "ReloadingKeyStore"),
                    null,
                    null, null);
        }

        public static KeyStore.Builder fromPem(Path cert, Path key) throws NoSuchAlgorithmException, CertificateException, IllegalArgumentException, KeyStoreException, InvalidKeySpecException, IOException {
            return new Builder(
                    new ReloadingKeyStore(new ReloadingPemFileKeyStoreSpi(Arrays.asList(cert), Arrays.asList(key)),
                            null, "ReloadingKeyStore"),
                    null, null, null);
        }

    }

}
