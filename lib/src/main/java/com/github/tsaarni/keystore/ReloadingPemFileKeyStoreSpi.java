package com.github.tsaarni.keystore;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.FileTime;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ReloadingPemFileKeyStoreSpi extends DelegatingKeyStoreSpi {

    private static final Logger log = LoggerFactory.getLogger(ReloadingPemFileKeyStoreSpi.class);
    private final List<FileCredentialInfo> fileCredentials = new ArrayList<>();

    /**
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws KeyStoreException
     */
    public ReloadingPemFileKeyStoreSpi(List<Path> certs, List<Path> keys) throws IllegalArgumentException, IOException, KeyStoreException, InvalidKeySpecException, NoSuchAlgorithmException, CertificateException {

        if (keys.size() < certs.size()) {
            throw new IllegalArgumentException("Missing private key");
        } else if (keys.size() > certs.size()) {
            throw new IllegalArgumentException("Missing X.509 certificate");
        } else if (keys.isEmpty()) {
            throw new IllegalArgumentException("No credentials configured");
        }

        // Load credentials that were passed as file paths.
        Iterator<Path> cpi = certs.iterator();
        Iterator<Path> kpi = keys.iterator();
        while (cpi.hasNext() && kpi.hasNext()) {
            fileCredentials.add(new FileCredentialInfo(cpi.next(), kpi.next()));
        }

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
    void refresh() throws KeyStoreException, InvalidKeySpecException, NoSuchAlgorithmException, CertificateException, IOException {
        boolean wasReloaded = false;
        int i = 0;
        for (FileCredentialInfo fc : fileCredentials) {
            try {
                if (fc.needsReload()) {
                    fileCredentials.set(i, new FileCredentialInfo(fc.certPath, fc.keyPath));
                    wasReloaded = true;
                }
            } catch (Exception e) {
                log.error("Failed to load: ", e);
            }
            i++;
        }

        // Re-generate KeyStore.
        if (wasReloaded) {
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
    private KeyStore createKeyStore() throws KeyStoreException, InvalidKeySpecException, NoSuchAlgorithmException, CertificateException, IOException {
        log.debug("Creating new KeyStore.");
        KeyStore ks = KeyStore.getInstance("PKCS12");

        // Calling load(), even with null arguments, will initialize the KeyStore to expected state.
        ks.load(null, null);

        int i = 0;
        for (FileCredentialInfo fc : fileCredentials) {
            String alias = String.format("%04d", i++);
            log.debug("Storing files {} and {} with alias {}", fc.keyPath, fc.certPath, alias);
            ks.setKeyEntry(alias, PemCredentialFactory.generatePrivateKey(fc.keyPath), null,
                    PemCredentialFactory.generateCertificates(fc.certPath));

        }
        return ks;
    }

    /**
     * Holds the path of the certificate and key files and the modification
     * timestamps for the latest reload.
     */
    class FileCredentialInfo {
        private final Path certPath;
        private final Path keyPath;
        private final FileTime certLastModified;
        private final FileTime keyLastModified;

        FileCredentialInfo(Path certPath, Path keyPath) throws IOException {
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
}
