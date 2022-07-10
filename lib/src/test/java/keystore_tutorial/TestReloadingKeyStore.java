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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mockStatic;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.time.Clock;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import fi.protonode.certy.Credential;

/**
 * Use ReloadingKeyStore as KeyStore with following extra capabilities:
 * - Construct KeyStore directly from PEM files.
 * - Update KeyStore when underlying files on disk are updated.
 * - Return entries in deterministic order, sorted by aliases.
 */
public class TestReloadingKeyStore {

    @Test
    void testCreateReloadingKeyStoreFromPemFiles(@TempDir Path tempDir) throws Exception {
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
    void testCreateReloadingKeyStoreFromJks(@TempDir Path tempDir) throws Exception {
        Credential server1 = new Credential().subject("CN=server1");
        Credential server2 = new Credential().subject("CN=server2");

        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(null, null);
        ks.setKeyEntry("server1", server1.getPrivateKey(), "".toCharArray(), server1.getCertificates());
        ks.setKeyEntry("server2", server2.getPrivateKey(), "".toCharArray(), server2.getCertificates());

        Path ksPath = tempDir.resolve("keystore.p12");
        ks.store(Files.newOutputStream(ksPath), "secret".toCharArray());

        KeyStore gotKs = ReloadingKeyStore.Builder.fromKeyStoreFile("JKS", ksPath, "secret").getKeyStore();
        assertNotNull(gotKs);

        assertEquals(Arrays.asList("server1", "server2"), Collections.list(gotKs.aliases()));
        assertArrayEquals(server1.getCertificates(), gotKs.getCertificateChain("server1"));
        assertArrayEquals(server2.getCertificates(), gotKs.getCertificateChain("server2"));
        assertEquals(server1.getPrivateKey(), gotKs.getKey("server1", "".toCharArray()));
        assertEquals(server2.getPrivateKey(), gotKs.getKey("server2", "".toCharArray()));
    }

    @Test
    void testCreateReloadingKeyStoreFromPkcs12(@TempDir Path tempDir) throws Exception {
        Credential server1 = new Credential().subject("CN=server1");
        Credential server2 = new Credential().subject("CN=server2");

        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry("server1", server1.getPrivateKey(), null, server1.getCertificates());
        ks.setKeyEntry("server2", server2.getPrivateKey(), null, server2.getCertificates());

        Path ksPath = tempDir.resolve("keystore.p12");
        ks.store(Files.newOutputStream(ksPath), "secret".toCharArray());

        KeyStore gotKs = ReloadingKeyStore.Builder.fromKeyStoreFile("PKCS12", ksPath, "secret").getKeyStore();
        assertNotNull(gotKs);

        assertEquals(Arrays.asList("server1", "server2"), Collections.list(gotKs.aliases()));
        assertArrayEquals(server1.getCertificates(), gotKs.getCertificateChain("server1"));
        assertArrayEquals(server2.getCertificates(), gotKs.getCertificateChain("server2"));
        assertEquals(server1.getPrivateKey(), gotKs.getKey("server1", null));
        assertEquals(server2.getPrivateKey(), gotKs.getKey("server2", null));
    }

    @Test
    void testPemHotReload(@TempDir Path tempDir) throws Exception {
        Path certPath = tempDir.resolve("server.pem");
        Path keyPath = tempDir.resolve("server-key.pem");

        // Time instants
        // - before: PEM files were created.
        // - after: cache TTL has expired and PEM files will be checked for modification.
        Instant before = Instant.now();
        Instant after = before.plus(DelegatingKeyStoreSpi.CACHE_TTL);

        // Inject mocked clock to control time.
        Clock originalClock = DelegatingKeyStoreSpi.now;
        DelegatingKeyStoreSpi.now = Mockito.mock(Clock.class);

        try (MockedStatic<Instant> mockedInstant = mockStatic(Instant.class, Mockito.CALLS_REAL_METHODS)) {
            // Configure clock to return the initial time instant.
            Mockito.when(DelegatingKeyStoreSpi.now.instant()).thenReturn(before);

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

            // Configure clock to return different time to expire cache TTL.
            Mockito.when(DelegatingKeyStoreSpi.now.instant()).thenReturn(after);

            // Check that PEM files are reloaded from disk after cache TTL expired.
            assertArrayEquals(credAfterUpdate.getCertificates(), ks.getCertificateChain("0000"));
            assertEquals(credAfterUpdate.getPrivateKey(), ks.getKey("0000", null));
        } finally {
            // Restore original clock back.
            DelegatingKeyStoreSpi.now = originalClock;
        }
    }

    @Test
    void testKeyStoreHotReload(@TempDir Path tempDir) throws Exception {
        Path ksPath = tempDir.resolve("keystore.p12");

        // Time instants
        // - before: keystore file was created.
        // - after: cache TTL has expired and keystore file will be checked for modification.
        Instant before = Instant.now();
        Instant after = before.plus(DelegatingKeyStoreSpi.CACHE_TTL);

        // Inject mocked clock to control time.
        Clock originalClock = DelegatingKeyStoreSpi.now;
        DelegatingKeyStoreSpi.now = Mockito.mock(Clock.class);

        try (MockedStatic<Instant> mockedInstant = mockStatic(Instant.class, Mockito.CALLS_REAL_METHODS)) {
            // Configure clock to return the initial time instant.
            Mockito.when(DelegatingKeyStoreSpi.now.instant()).thenReturn(before);

            // Write initial versions of the keystore to the disk.
            Credential credBeforeUpdate = new Credential().subject("CN=joe");

            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(null, null);
            ks.setKeyEntry("cred", credBeforeUpdate.getPrivateKey(), null, credBeforeUpdate.getCertificates());
            ks.store(Files.newOutputStream(ksPath), "secret".toCharArray());

            // Load initial keystore from the disk.
            KeyStore gotKs = ReloadingKeyStore.Builder.fromKeyStoreFile("PKCS12", ksPath, "secret").getKeyStore();
            assertNotNull(gotKs);

            // Check that we got the initial certificate and key back.
            assertArrayEquals(credBeforeUpdate.getCertificates(), gotKs.getCertificateChain("cred"));
            assertEquals(credBeforeUpdate.getPrivateKey(), gotKs.getKey("cred", null));

            // Write updated keystore to the disk.
            Credential credAfterUpdate = new Credential().subject("CN=joe");
            ks = KeyStore.getInstance("PKCS12");
            ks.load(null, null);
            ks.setKeyEntry("cred", credAfterUpdate.getPrivateKey(), null, credAfterUpdate.getCertificates());
            ks.store(Files.newOutputStream(ksPath), "secret".toCharArray());

            // Check that we still get old credentials back, before cache TTL expires.
            assertArrayEquals(credBeforeUpdate.getCertificates(), gotKs.getCertificateChain("cred"));
            assertEquals(credBeforeUpdate.getPrivateKey(), gotKs.getKey("cred", null));

            // Configure clock to return different time to expire cache TTL.
            Mockito.when(DelegatingKeyStoreSpi.now.instant()).thenReturn(after);

            // Check that keystore was reloaded from disk after cache TTL expired.
            assertArrayEquals(credAfterUpdate.getCertificates(), gotKs.getCertificateChain("cred"));
            assertEquals(credAfterUpdate.getPrivateKey(), gotKs.getKey("cred", null));
        } finally {
            // Restore original clock back.
            DelegatingKeyStoreSpi.now = originalClock;
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

        KeyStore gotKs = ReloadingKeyStore.Builder.fromKeyStoreFile("PKCS12", ksPath, "secret").getKeyStore();
        assertNotNull(gotKs);

        assertEquals(Arrays.asList("01-in-random", "02-order", "03-certs-added", "04-to-the-store"),
                Collections.list(gotKs.aliases()));
    }

    @Test
    void testFailWhenInvalidPemFile(@TempDir Path tempDir) throws IOException, KeyStoreException,
            InvalidKeySpecException, NoSuchAlgorithmException, CertificateException {
        // Try to load file that is not PEM at all.
        Path p = tempDir.resolve("invalid.pem");
        Files.write(p, "this\nis\nnot\nPEM\n".getBytes());
        assertThrows(CertificateException.class, () -> ReloadingKeyStore.Builder.fromPem(p));

        // Try reading certificate from key and key from certificate PEM.
        Path certPath = tempDir.resolve("cert.pem");
        Path keyPath = tempDir.resolve("key.pem");
        new Credential().subject("CN=joe").writeCertificateAsPem(certPath).writePrivateKeyAsPem(keyPath);
        assertThrows(IllegalArgumentException.class, () -> ReloadingKeyStore.Builder.fromPem(keyPath, certPath));
    }

    @Test
    void testInvalidKeyEntryPassword(@TempDir Path tempDir) throws Exception {
        Path ksPath = tempDir.resolve("keystore.p12");

        Credential cred = new Credential().subject("CN=joe");

        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry("cred", cred.getPrivateKey(), "correct-password".toCharArray(), cred.getCertificates());
        ks.store(Files.newOutputStream(ksPath), "secret".toCharArray());

        KeyStore gotKs = ReloadingKeyStore.Builder.fromKeyStoreFile("PKCS12", ksPath, "secret").getKeyStore();
        assertNotNull(gotKs);

        // Note:
        // When accessing the key directly via KeyStore (instead of KeyManager),
        // exception is received with descriptive error when given key entry password is wrong:
        //     java.security.UnrecoverableKeyException:
        //        Get Key failed: Given final block not properly padded.
        //        Such issues can arise if a bad key is used during decryption.
        assertThrows(UnrecoverableEntryException.class, () -> gotKs.getKey("cred", "invalid-password".toCharArray()));
    }
}
