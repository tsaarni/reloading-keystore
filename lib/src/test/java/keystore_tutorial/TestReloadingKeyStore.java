package keystore_tutorial;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import fi.protonode.certy.Credential;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mockStatic;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public class TestReloadingKeyStore {

    @Test
    void testCreateKeyStoreFromPems(@TempDir Path tempDir) throws Exception {
        Path certPath1 = tempDir.resolve("server1.pem");
        Path keyPath1 = tempDir.resolve("server1-key.pem");
        Path certPath2 = tempDir.resolve("server2.pem");
        Path keyPath2 = tempDir.resolve("server2-key.pem");

        new Credential().subject("CN=server1").writeCertificateAsPem(certPath1).writePrivateKeyAsPem(keyPath1);
        new Credential().subject("CN=server2").writeCertificateAsPem(certPath2).writePrivateKeyAsPem(keyPath2);

        List<Path> certs = Arrays.asList(certPath1, certPath2);
        List<Path> keys = Arrays.asList(keyPath2, keyPath2);
        KeyStore.Builder builder = ReloadingKeyStore.Builder.fromPem(certs, keys);
        assertNotNull(builder);

        KeyStore ks = builder.getKeyStore();
        assertNotNull(ks);

        assertEquals(Arrays.asList("0000", "0001"), Collections.list(ks.aliases()));
        assertArrayEquals(PemCredentialFactory.generateCertificates(certs.get(0)), ks.getCertificateChain("0000"));
        assertArrayEquals(PemCredentialFactory.generateCertificates(certs.get(1)), ks.getCertificateChain("0001"));
        assertEquals(PemCredentialFactory.generatePrivateKey(keys.get(0)), ks.getKey("0000", null));
        assertEquals(PemCredentialFactory.generatePrivateKey(keys.get(1)), ks.getKey("0001", null));
    }

    @Test
    void testCreateKeyStoreFromJks(@TempDir Path tempDir) throws Exception {
        Credential server1 = new Credential().subject("CN=server1");
        Credential server2 = new Credential().subject("CN=server2");

        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(null, null);
        ks.setKeyEntry("server1", server1.getPrivateKey(), "".toCharArray(), server1.getCertificates());
        ks.setKeyEntry("server2", server2.getPrivateKey(), "".toCharArray(), server2.getCertificates());

        Path ksPath = tempDir.resolve("keystore.p12");
        ks.store(Files.newOutputStream(ksPath), "secret".toCharArray());

        KeyStore.Builder builder = ReloadingKeyStore.Builder.fromKeyStoreFile("JKS", "SUN", ksPath,
                "secret", null, null);

        KeyStore reloadingKs = builder.getKeyStore();
        assertNotNull(reloadingKs);

        assertEquals(Arrays.asList("server1", "server2"), Collections.list(reloadingKs.aliases()));
        assertArrayEquals(server1.getCertificates(), reloadingKs.getCertificateChain("server1"));
        assertArrayEquals(server2.getCertificates(), reloadingKs.getCertificateChain("server2"));
        assertEquals(server1.getPrivateKey(), reloadingKs.getKey("server1", "".toCharArray()));
        assertEquals(server2.getPrivateKey(), reloadingKs.getKey("server2", "".toCharArray()));
    }

    @Test
    void testCreateKeyStoreFromPkcs12(@TempDir Path tempDir) throws Exception {
        Credential server1 = new Credential().subject("CN=server1");
        Credential server2 = new Credential().subject("CN=server2");

        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry("server1", server1.getPrivateKey(), null, server1.getCertificates());
        ks.setKeyEntry("server2", server2.getPrivateKey(), null, server2.getCertificates());

        Path ksPath = tempDir.resolve("keystore.p12");
        ks.store(Files.newOutputStream(ksPath), "secret".toCharArray());

        KeyStore.Builder builder = ReloadingKeyStore.Builder.fromKeyStoreFile("PKCS12", "SUN", ksPath,
                "secret", null, null);

        KeyStore reloadingKs = builder.getKeyStore();
        assertNotNull(reloadingKs);

        assertEquals(Arrays.asList("server1", "server2"), Collections.list(reloadingKs.aliases()));
        assertArrayEquals(server1.getCertificates(), reloadingKs.getCertificateChain("server1"));
        assertArrayEquals(server2.getCertificates(), reloadingKs.getCertificateChain("server2"));
        assertEquals(server1.getPrivateKey(), reloadingKs.getKey("server1", null));
        assertEquals(server2.getPrivateKey(), reloadingKs.getKey("server2", null));
    }

    @Test
    void testPemHotReload(@TempDir Path tempDir) throws Exception {
        Path certPath = tempDir.resolve("server.pem");
        Path keyPath = tempDir.resolve("server-key.pem");

        Instant before = Instant.parse("2022-01-01T13:00:00Z");
        Instant after = Instant.parse("2022-01-01T13:00:01Z"); // Cache TTL expires 1 second later.

        try (MockedStatic<Instant> mockedStatic = mockStatic(Instant.class, Mockito.CALLS_REAL_METHODS)) {
            mockedStatic.when(() -> Instant.now()).thenReturn(before);

            // Write initial versions of the PEMs to the disk.
            Credential credBeforeUpdate = new Credential().subject("CN=server").writeCertificateAsPem(certPath)
                    .writePrivateKeyAsPem(keyPath);

            // Load PEMs into keystore and check that we got them back.
            KeyStore.Builder builder = ReloadingKeyStore.Builder.fromPem(certPath, keyPath);
            assertNotNull(builder);
            KeyStore ks = builder.getKeyStore();
            assertNotNull(ks);
            assertArrayEquals(credBeforeUpdate.getCertificates(), ks.getCertificateChain("0000"));
            assertEquals(credBeforeUpdate.getPrivateKey(), ks.getKey("0000", null));

            // Write updated PEM files to the disk.
            Credential credAfterUpdate = new Credential().subject("CN=server").writeCertificateAsPem(certPath)
                    .writePrivateKeyAsPem(keyPath);

            // Check that old PEM files are returned before cache TTL expires.
            assertArrayEquals(credBeforeUpdate.getCertificates(), ks.getCertificateChain("0000"));
            assertEquals(credBeforeUpdate.getPrivateKey(), ks.getKey("0000", null));

            // Advance time to expire cache TTL.
            mockedStatic.when(() -> Instant.now()).thenReturn(after);

            // Check that PEM files are reloaded from disk after cache TTL expired.
            assertArrayEquals(credAfterUpdate.getCertificates(), ks.getCertificateChain("0000"));
            assertEquals(credAfterUpdate.getPrivateKey(), ks.getKey("0000", null));
        }
    }

    @Test
    void testKeyStoreHotReload(@TempDir Path tempDir) throws Exception {
        Path ksPath = tempDir.resolve("keystore.p12");
        Instant before = Instant.parse("2022-01-01T13:00:00Z");
        Instant after = Instant.parse("2022-01-01T13:00:01Z"); // Cache TTL expires 1 second later.

        try (MockedStatic<Instant> mockedStatic = mockStatic(Instant.class, Mockito.CALLS_REAL_METHODS)) {
            mockedStatic.when(() -> Instant.now()).thenReturn(before);

            // Write initial versions of the keystore to the disk.
            Credential credBeforeUpdate = new Credential().subject("CN=joe");

            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(null, null);
            ks.setKeyEntry("cred", credBeforeUpdate.getPrivateKey(), null, credBeforeUpdate.getCertificates());
            ks.store(Files.newOutputStream(ksPath), "secret".toCharArray());

            // Load initial keystore from the disk.
            KeyStore.Builder builder = ReloadingKeyStore.Builder.fromKeyStoreFile("PKCS12", "SUN", ksPath,
                    "secret", null, null);
            KeyStore reloadingKs = builder.getKeyStore();
            assertNotNull(reloadingKs);

            // Check that we got the initial certificate and key back.
            assertArrayEquals(credBeforeUpdate.getCertificates(), reloadingKs.getCertificateChain("cred"));
            assertEquals(credBeforeUpdate.getPrivateKey(), reloadingKs.getKey("cred", null));

            // Write updated keystore to the disk.
            Credential credAfterUpdate = new Credential().subject("CN=joe");
            ks = KeyStore.getInstance("PKCS12");
            ks.load(null, null);
            ks.setKeyEntry("cred", credAfterUpdate.getPrivateKey(), null, credAfterUpdate.getCertificates());
            ks.store(Files.newOutputStream(ksPath), "secret".toCharArray());

            // Check that we still get old credentials back, before cache TTL expires.
            assertArrayEquals(credBeforeUpdate.getCertificates(), reloadingKs.getCertificateChain("cred"));
            assertEquals(credBeforeUpdate.getPrivateKey(), reloadingKs.getKey("cred", null));

            // Advance time to expire cache TTL.
            mockedStatic.when(() -> Instant.now()).thenReturn(after);

            // Check that keystore was reloaded from disk after cache TTL expired.
            assertArrayEquals(credAfterUpdate.getCertificates(), reloadingKs.getCertificateChain("cred"));
            assertEquals(credAfterUpdate.getPrivateKey(), reloadingKs.getKey("cred", null));
        }
    }

    @Test
    void testKeyStoreSortedAliases(@TempDir Path tempDir) throws Exception {
        Credential cred = new Credential().subject("CN=joe");

        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry("03-certs-added", cred.getPrivateKey(), null, cred.getCertificates());
        ks.setKeyEntry("01-in-random", cred.getPrivateKey(), null, cred.getCertificates());
        ks.setKeyEntry("02-order", cred.getPrivateKey(), null, cred.getCertificates());
        ks.setKeyEntry("04-to-the-store", cred.getPrivateKey(), null, cred.getCertificates());
        Path ksPath = tempDir.resolve("keystore.p12");
        ks.store(Files.newOutputStream(ksPath), "secret".toCharArray());

        KeyStore.Builder builder = ReloadingKeyStore.Builder.fromKeyStoreFile("PKCS12", "SUN", ksPath,
                "secret", null, null);

        KeyStore reloadingKs = builder.getKeyStore();
        assertNotNull(ks);

        assertEquals(Arrays.asList("01-in-random", "02-order", "03-certs-added", "04-to-the-store"),
                Collections.list(reloadingKs.aliases()));
    }

    @Test
    void testKeyStoreWithEncryptedEntry() {
        // TODO
    }
}
