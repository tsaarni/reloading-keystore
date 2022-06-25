package keystore_tutorial;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ReloadingPemFileKeyStoreSpi extends DelegatingKeyStoreSpi {

    public static final char[] IN_MEMORY_KEYSTORE_PASSWORD = "".toCharArray();

    private static final Logger log = LoggerFactory.getLogger(ReloadingPemFileKeyStoreSpi.class);
    private final List<KeyFileEntry> keyFileEntries = new ArrayList<>();
    private final List<CertificateFileEntry> certificateFileEntries = new ArrayList<>();

    /**
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws KeyStoreException
     */
    public ReloadingPemFileKeyStoreSpi() {
    }

    public void setKeyEntry(Path cert, Path key) throws KeyStoreException, InvalidKeySpecException,
            NoSuchAlgorithmException, CertificateException, IOException {
        keyFileEntries.add(new KeyFileEntry(cert, key));
        setKeyStoreDelegate(createKeyStore());
    }

    public void setCertificateEntry(Path cert) throws KeyStoreException, InvalidKeySpecException,
            NoSuchAlgorithmException, CertificateException, IOException {
        certificateFileEntries.add(new CertificateFileEntry(cert));
        setKeyStoreDelegate(createKeyStore());
    }

    /**
     * Reload certificate and key PEM files if they were modified on disk since they
     * were last loaded.
     * @throws IOException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws KeyStoreException
     */
    void refresh() throws KeyStoreException, InvalidKeySpecException, NoSuchAlgorithmException, CertificateException,
            IOException {
        // Check if any of the files has been updated.
        // If yes, update the last modification timestamp for the file(s) and recreate delegate KeyStore with new content.
        boolean wasReloaded = false;
        int i = 0;
        for (KeyFileEntry e : keyFileEntries) {
            if (e.needsReload()) {
                keyFileEntries.set(i, new KeyFileEntry(e.certPath, e.keyPath));
                wasReloaded = true;
            }
            i++;
        }
        i = 0;
        for (CertificateFileEntry e : certificateFileEntries) {
            if (e.needsReload()) {
                certificateFileEntries.set(i, new CertificateFileEntry(e.certPath));
                wasReloaded = true;
            }
            i++;
        }
        // Re-generate KeyStore.
        if (wasReloaded) {
            log.debug("Refreshing KeyStore");
            setKeyStoreDelegate(createKeyStore());
        }
    }

    /**
     * Create KeyStore that contains the certificates and keys that were passed by paths.
     * @throws KeyStoreException
     * @throws IOException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    private KeyStore createKeyStore() throws KeyStoreException, InvalidKeySpecException, NoSuchAlgorithmException,
            CertificateException, IOException {
        log.debug("Creating new in-memory PKCS12 KeyStore.");
        KeyStore ks = KeyStore.getInstance("PKCS12");

        // Calling load(), even with null arguments, will initialize the KeyStore to expected state.
        ks.load(null, null);

        int i = 0;

        // Load certificates + private keys.
        for (KeyFileEntry e : keyFileEntries) {
            String alias = String.format("%04d", i++);
            log.debug("Adding key entry with alias {}: {}, {}", alias, e.keyPath, e.certPath);
            ks.setKeyEntry(alias, PemCredentialFactory.generatePrivateKey(e.keyPath), IN_MEMORY_KEYSTORE_PASSWORD,
                    PemCredentialFactory.generateCertificates(e.certPath));
        }
        // Load trusted certificates.
        for (CertificateFileEntry e : certificateFileEntries) {
            String alias = String.format("%04d", i++);
            log.debug("Adding certificate entry with alias {}: {}", alias, e.certPath);
            for (Certificate c : PemCredentialFactory.generateCertificates(e.certPath)) {
                ks.setCertificateEntry(alias, c);
            }
        }

        return ks;
    }

    /**
     * Holds the path of the certificate and key files and the modification timestamps when last loaded.
     */
    class KeyFileEntry {
        private final Path certPath;
        private final Path keyPath;
        private final FileTime certLastModified;
        private final FileTime keyLastModified;

        KeyFileEntry(Path certPath, Path keyPath) throws IOException {
            this.certPath = certPath;
            this.keyPath = keyPath;
            this.certLastModified = Files.getLastModifiedTime(certPath);
            this.keyLastModified = Files.getLastModifiedTime(keyPath);
        }

        boolean needsReload() throws IOException {
            return (certLastModified.compareTo(Files.getLastModifiedTime(certPath)) < 0) ||
                    (keyLastModified.compareTo(Files.getLastModifiedTime(keyPath)) < 0);
        }
    }

    /**
     * Holds the path of the certificate file and the modification timestamps when last loaded.
     */
    class CertificateFileEntry {
        private final Path certPath;
        private final FileTime certLastModified;

        CertificateFileEntry(Path certPath) throws IOException {
            this.certPath = certPath;
            this.certLastModified = Files.getLastModifiedTime(certPath);
        }

        boolean needsReload() throws IOException {
            return certLastModified.compareTo(Files.getLastModifiedTime(certPath)) < 0;
        }
    }
}
