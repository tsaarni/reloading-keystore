package keystore_tutorial;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.KeyStoreBuilderParameters;
import javax.net.ssl.TrustManagerFactory;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import fi.protonode.certy.Credential;

public class TestReloadingKeyStoreWithTls {

    @Test
    void testServerAuthenticationWithKeyStore(@TempDir Path tempDir) throws Exception {
        Path ksPath = tempDir.resolve("server.p12");
        Path tsPath = tempDir.resolve("trusted.p12");

        // Enable Java KeyManager debug printouts.
        System.setProperty("javax.net.debug", "keymanager:trustmanager");

        // Create CA and server certificate.
        Credential caCreds = new Credential().subject("CN=ca");
        Credential serverCreds = new Credential().subject("CN=server").issuer(caCreds);

        // Create keystore files.
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry("server", serverCreds.getPrivateKey(), "secret".toCharArray(), serverCreds.getCertificates());
        // ks.setKeyEntry("server", serverCreds.getPrivateKey(), null,
        // serverCreds.getCertificates());
        ks.store(Files.newOutputStream(ksPath), "secret".toCharArray());

        KeyStore ts = KeyStore.getInstance("PKCS12");
        ts.load(null, null);
        ts.setCertificateEntry("trusted", caCreds.getCertificate());
        ts.store(Files.newOutputStream(tsPath), "secret".toCharArray());

        // Create KeyManager for server.
        KeyManagerFactory kmfServer = KeyManagerFactory.getInstance("NewSunX509");
        kmfServer.init(new KeyStoreBuilderParameters(ReloadingKeyStore.Builder.fromKeyStoreFile("PKCS12", "SUN", ksPath,
                "secret", null, null)));

        // Create TrustManager for client.
        TrustManagerFactory tmfClient = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()); // algorithm=PKIX
        tmfClient.init(ReloadingKeyStore.Builder.fromKeyStoreFile("PKCS12", "SUN", tsPath,
                "secret", null, null).getKeyStore());

        // Create TLS connection.
        try (TlsTester.Server server = TlsTester.serverWithServerAuth(kmfServer.getKeyManagers())) {
            Certificate[] serverCerts = TlsTester.connect(tmfClient.getTrustManagers(), server).getServerCertificate();
            assertArrayEquals(serverCreds.getCertificates(), serverCerts);
        }
    }

    @Test
    void testServerAuthenticationWithPem(@TempDir Path tempDir) throws Exception {
        // Enable Java KeyManager debug printouts.
        // System.setProperty("javax.net.debug", "keymanager:trustmanager");
        System.setProperty("javax.net.debug", "keymanager");

        Path serverCaCertPem = tempDir.resolve("server-ca.pem");
        Path serverCertPem = tempDir.resolve("server.pem");
        Path serverKeyPem = tempDir.resolve("server-key.pem");

        // Create CAs and server certificate.
        Credential serverCaCreds = new Credential().subject("CN=server-ca").writeCertificateAsPem(serverCaCertPem);
        Credential serverCreds = new Credential().subject("CN=server").issuer(serverCaCreds)
                .writeCertificateAsPem(serverCertPem).writePrivateKeyAsPem(serverKeyPem);

        // Create KeyManager for server.
        KeyManagerFactory kmfServer = KeyManagerFactory.getInstance("NewSunX509");
        kmfServer.init(new KeyStoreBuilderParameters(ReloadingKeyStore.Builder.fromPem(serverCertPem, serverKeyPem)));

        // Create TrustManager for client.
        TrustManagerFactory tmfClient = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()); // algorithm=PKIX
        tmfClient.init(ReloadingKeyStore.Builder.fromPem(serverCaCertPem).getKeyStore());

        // Create TLS connection.
        try (TlsTester.Server server = TlsTester.serverWithServerAuth(kmfServer.getKeyManagers())) {
            Certificate[] serverCerts = TlsTester.connect(tmfClient.getTrustManagers(), server).getServerCertificate();
            assertArrayEquals(serverCreds.getCertificates(), serverCerts);
        }
    }

    @Test
    void testMutualAuthenticationWithPem(@TempDir Path tempDir) throws Exception {
        // Enable Java KeyManager debug printouts.
        System.setProperty("javax.net.debug", "keymanager:trustmanager");

        Path serverCaCertPem = tempDir.resolve("server-ca.pem");
        Path clientCaCertPem = tempDir.resolve("client-ca.pem");
        Path serverCertPem = tempDir.resolve("server.pem");
        Path serverKeyPem = tempDir.resolve("server-key.pem");
        Path clientCertPem = tempDir.resolve("client.pem");
        Path clientKeyPem = tempDir.resolve("client-key.pem");

        // Create CAs, server and client certificate.
        Credential serverCaCreds = new Credential().subject("CN=server-ca").writeCertificateAsPem(serverCaCertPem);
        Credential clientCaCreds = new Credential().subject("CN=client-ca").writeCertificateAsPem(clientCaCertPem);
        Credential serverCreds = new Credential().subject("CN=server").issuer(serverCaCreds)
                .writeCertificateAsPem(serverCertPem).writePrivateKeyAsPem(serverKeyPem);
        Credential clientCreds = new Credential().subject("CN=client").issuer(clientCaCreds)
                .writeCertificateAsPem(clientCertPem).writePrivateKeyAsPem(clientKeyPem);

        // Create KeyManager for server.
        KeyManagerFactory kmfServer = KeyManagerFactory.getInstance("NewSunX509");
        kmfServer.init(new KeyStoreBuilderParameters(ReloadingKeyStore.Builder.fromPem(serverCertPem, serverKeyPem)));

        // Create TrustManager for server.
        TrustManagerFactory tmfServer = TrustManagerFactory.getInstance("PKIX");
        // tmfServer.init(new CertPathTrustManagerParameters(new PKIXBuilderParameters(
        // ReloadingKeyStore.Builder.fromPem(clientCaCertPem).getKeyStore(), new
        // X509CertSelector())));
        tmfServer.init(ReloadingKeyStore.Builder.fromPem(clientCaCertPem).getKeyStore());

        // Create KeyManager for client.
        KeyManagerFactory kmfClient = KeyManagerFactory.getInstance("NewSunX509");
        kmfClient.init(new KeyStoreBuilderParameters(ReloadingKeyStore.Builder.fromPem(clientCertPem, clientKeyPem)));

        // Create TrustManager for client.
        TrustManagerFactory tmfClient = TrustManagerFactory.getInstance("PKIX");
        tmfClient.init(ReloadingKeyStore.Builder.fromPem(serverCaCertPem).getKeyStore());
        // tmfClient.init(new CertPathTrustManagerParameters(new PKIXBuilderParameters(
        // ReloadingKeyStore.Builder.fromPem(serverCaCertPem).getKeyStore(), new
        // X509CertSelector())));

        // Create TLS connection.
        try (TlsTester.Server server = TlsTester.serverWithMutualAuth(kmfServer.getKeyManagers(),
                tmfServer.getTrustManagers())) {
            Certificate[] serverCerts = TlsTester
                    .connect(kmfClient.getKeyManagers(), tmfClient.getTrustManagers(), server)
                    .getServerCertificate();
            Certificate[] clientCerts = server.getClientCertificates();
            assertArrayEquals(serverCreds.getCertificates(), serverCerts);
            assertArrayEquals(clientCreds.getCertificates(), clientCerts);
        }
    }

    @Test
    void testMultipleServerCertificateWithSniSelection(@TempDir Path tempDir)
            throws CertificateException, NoSuchAlgorithmException, IOException, UnrecoverableKeyException,
            KeyStoreException, KeyManagementException, InvalidAlgorithmParameterException, NoSuchProviderException {

        // Create CA and server certificates for a server that supports several servernames / virtualhosts.
        Credential serverCaCreds = new Credential().subject("CN=server-ca");
        KeyManagerFactory kmfServer = createKeyManagerFactory(tempDir,
                new Credential().subject("CN=foo").issuer(serverCaCreds).subjectAltName("DNS:foo.com"),
                new Credential().subject("CN=bar").issuer(serverCaCreds).subjectAltName("DNS:bar.com"),
                new Credential().subject("CN=00-fallback-credentials").issuer(serverCaCreds));
        TrustManagerFactory tmfClient = createTrustManagerFactory(tempDir, serverCaCreds);

        // Create TLS connection with SNI servername: foo.com.
        try (TlsTester.Server server = TlsTester.serverWithServerAuth(kmfServer.getKeyManagers())) {
            Certificate[] serverCerts = TlsTester.connectWithSni(tmfClient.getTrustManagers(), "foo.com", server)
                    .getServerCertificate();
            assertEquals("CN=foo", ((X509Certificate) serverCerts[0]).getSubjectX500Principal().toString());
        }

        // Create TLS connection with SNI servername: bar.com.
        try (TlsTester.Server server = TlsTester.serverWithServerAuth(kmfServer.getKeyManagers())) {
            Certificate[] serverCerts = TlsTester.connectWithSni(tmfClient.getTrustManagers(), "bar.com", server)
                    .getServerCertificate();
            assertEquals("CN=bar", ((X509Certificate) serverCerts[0]).getSubjectX500Principal().toString());
        }

        // Create TLS connection with SNI servername that does not match: unknown.com.
        try (TlsTester.Server server = TlsTester.serverWithServerAuth(kmfServer.getKeyManagers())) {
            Certificate[] serverCerts = TlsTester.connectWithSni(tmfClient.getTrustManagers(), "unknown.com", server)
                    .getServerCertificate();
            assertEquals("CN=00-fallback-credentials",
                    ((X509Certificate) serverCerts[0]).getSubjectX500Principal().toString());
        }

        // Create TLS connection without SNI.
        try (TlsTester.Server server = TlsTester.serverWithServerAuth(kmfServer.getKeyManagers())) {
            Certificate[] serverCerts = TlsTester.connect(tmfClient.getTrustManagers(), server)
                    .getServerCertificate();
            assertEquals("CN=00-fallback-credentials",
                    ((X509Certificate) serverCerts[0]).getSubjectX500Principal().toString());
        }
    }

    private KeyManagerFactory createKeyManagerFactory(Path tempDir, Credential... credentials)
            throws KeyStoreException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException,
            IOException, InvalidAlgorithmParameterException, NoSuchProviderException {

        // Create empty KeyStore.
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);

        // Add given certificates and private keys as KeyEntries.
        for (Credential c : credentials) {
            ks.setKeyEntry(c.getX509Certificate().getSubjectX500Principal().toString(),
                    c.getPrivateKey(), "".toCharArray(), c.getCertificates());
        }

        // Store keystore to disk.
        Path ksPath = tempDir.resolve(ks.toString());
        ks.store(Files.newOutputStream(ksPath), "".toCharArray());

        // Create KeyManagerFactory and ReloadingKeyStore for the stored keystore.
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("NewSunX509");
        kmf.init(new KeyStoreBuilderParameters(ReloadingKeyStore.Builder.fromKeyStoreFile("PKCS12", "SUN", ksPath,
                "", null, null)));

        return kmf;
    }

    private TrustManagerFactory createTrustManagerFactory(Path tempDir, Credential... credentials)
            throws KeyStoreException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException,
            IOException {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        for (Credential c : credentials) {
            ks.setKeyEntry(c.getX509Certificate().getSubjectX500Principal().toString(),
                    c.getPrivateKey(), "".toCharArray(), c.getCertificates());
        }
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()); // algorithm=PKIX
        tmf.init(ks);
        return tmf;
    }

    @Test
    void testFallbackCertificateSelection() {
        // TODO
    }

    @Test
    void testMultipleServerCertificateWithKeyTypeSelection() {
        // TODO
    }

    @Test
    void testMultipleClientCertificatesWithAuthoritySelection() {
        // TODO
    }

    @Test
    void testMultipleClientCertificatesWithKeyTypeSelection() {
        // TODO
    }

    @Test
    void testServerCertificateHotReload() {
        // TODO
    }

    @Test
    void testClientCertificateHotReload() {
        // TODO
    }

    @Test
    void testInvalidEntryPassword() {
        // TODO: error is not propagated for some reason.
    }

    @Test
    void testFailedServerAuthentication() {
        // TODO
    }

    @Test
    void testFailedClientAuthentication() {
        // TODO
    }
}
