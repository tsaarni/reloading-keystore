package com.github.tsaarni.keystore;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.Certificate;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.KeyStoreBuilderParameters;
import javax.net.ssl.TrustManagerFactory;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import fi.protonode.certy.Credential;

public class TestReloadingKeyStoreWithTls {

    @Test
    void testServerAuthentication(@TempDir Path tempDir) throws Exception {
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

        // Create KeyManager with ReloadingKeyStore.
        KeyStore.Builder ksBuilder = ReloadingKeyStore.Builder.fromKeyStoreFile("PKCS12", "SUN", ksPath,
                "secret", null, null);
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("NewSunX509");
        kmf.init(new KeyStoreBuilderParameters(ksBuilder));

        // Create TrustManager with ReloadingKeyStore.
        KeyStore.Builder tsBuilder = ReloadingKeyStore.Builder.fromKeyStoreFile("PKCS12", "SUN", tsPath,
                "secret", null, null);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()); // algorithm=PKIX
        tmf.init(tsBuilder.getKeyStore());

        // Test TLS connection.
        try (TlsTester.Server server = TlsTester.withServerAuth(kmf.getKeyManagers())) {
            Certificate[] serverCerts = TlsTester.connectTo(tmf.getTrustManagers(), server).getServerCertificate();
            assertArrayEquals(serverCreds.getCertificates(), serverCerts);
        }
    }

    @Test
    void testMutualAuthentication(@TempDir Path tempDir) throws Exception {
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
        KeyStore.Builder ksBuilder = ReloadingKeyStore.Builder.fromPem(serverCertPem, serverKeyPem);
        KeyManagerFactory kmfServer = KeyManagerFactory.getInstance("NewSunX509");
        kmfServer.init(new KeyStoreBuilderParameters(ksBuilder));

        // Create TrustManager for server.
        // KeyStore.Builder ksBuilder = ReloadingKeyStore.Builder.fromPem(serverCertPem, serverKeyPem);
        // KeyManagerFactory kmfServer = KeyManagerFactory.getInstance("NewSunX509");
        // kmfServer.init(new KeyStoreBuilderParameters(ksBuilder));


    }

    @Test
    void testMultipleServerCertificateWithSniSelection() {
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
    void testServerCertificateRotation() {
        // TODO
    }

    @Test
    void testClientCertificateRotation() {
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
