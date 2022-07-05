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

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.HashMap;
import java.util.Map;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.KeyStoreBuilderParameters;
import javax.net.ssl.TrustManagerFactory;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import fi.protonode.certy.Credential;
import fi.protonode.certy.Credential.KeyType;

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
        ks.store(Files.newOutputStream(ksPath), "secret".toCharArray());

        KeyStore ts = KeyStore.getInstance("PKCS12");
        ts.load(null, null);
        ts.setCertificateEntry("trusted", caCreds.getCertificate());
        ts.store(Files.newOutputStream(tsPath), "secret".toCharArray());

        // Create KeyManager for server.
        KeyManagerFactory kmfServer = KeyManagerFactory.getInstance("NewSunX509");
        kmfServer.init(new KeyStoreBuilderParameters(ReloadingKeyStore.Builder.fromKeyStoreFile("PKCS12", "SunJSSE", ksPath,
                "secret")));

        // Create TrustManager for client.
        TrustManagerFactory tmfClient = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()); // algorithm=PKIX
        tmfClient.init(ReloadingKeyStore.Builder.fromKeyStoreFile("PKCS12", "SunJSSE", tsPath,
                "secret").getKeyStore());

        // Create TLS connection.
        try (TlsTester.Server server = TlsTester.serverWithServerAuth(kmfServer.getKeyManagers())) {
            Certificate[] gotServerCerts = TlsTester.connect(server, tmfClient.getTrustManagers())
                    .getServerCertificate();
            assertArrayEquals(serverCreds.getCertificates(), gotServerCerts);
        }
    }

    @Test
    void testServerAuthenticationWithPem(@TempDir Path tempDir) throws Exception {
        // Enable Java KeyManager debug printouts.
        // System.setProperty("javax.net.debug", "keymanager:trustmanager");

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
            Certificate[] gotServerCerts = TlsTester.connect(server, tmfClient.getTrustManagers())
                    .getServerCertificate();
            assertArrayEquals(serverCreds.getCertificates(), gotServerCerts);
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
        tmfServer.init(ReloadingKeyStore.Builder.fromPem(clientCaCertPem).getKeyStore());

        // Create KeyManager for client.
        KeyManagerFactory kmfClient = KeyManagerFactory.getInstance("NewSunX509");
        kmfClient.init(new KeyStoreBuilderParameters(ReloadingKeyStore.Builder.fromPem(clientCertPem, clientKeyPem)));

        // Create TrustManager for client.
        TrustManagerFactory tmfClient = TrustManagerFactory.getInstance("PKIX");
        tmfClient.init(ReloadingKeyStore.Builder.fromPem(serverCaCertPem).getKeyStore());

        // Create TLS connection.
        try (TlsTester.Server server = TlsTester.serverWithMutualAuth(kmfServer.getKeyManagers(),
                tmfServer.getTrustManagers())) {
            Certificate[] gotServerCerts = TlsTester
                    .connect(server, kmfClient.getKeyManagers(), tmfClient.getTrustManagers())
                    .getServerCertificate();
            Certificate[] gotClientCerts = server.getClientCertificates();
            assertArrayEquals(serverCreds.getCertificates(), gotServerCerts);
            assertArrayEquals(clientCreds.getCertificates(), gotClientCerts);
        }
    }

    @Test
    void testMultipleServerCertificateWithSniSelection(@TempDir Path tempDir) throws Exception {

        // Create CA and server certificates for a server that supports several virtualhosts.
        Credential serverCaCreds = new Credential().subject("CN=server-ca");
        Credential serverFooCreds = new Credential().subject("CN=foo").issuer(serverCaCreds)
                .subjectAltName("DNS:foo.com");
        Credential serverBarCreds = new Credential().subject("CN=bar").issuer(serverCaCreds)
                .subjectAltName("DNS:bar.com");

        KeyManagerFactory kmfServer = TlsTester.createKeyManagerFactory(tempDir, serverFooCreds, serverBarCreds);
        TrustManagerFactory tmfClient = TlsTester.createTrustManagerFactory(tempDir, serverCaCreds);

        // Create TLS connection with SNI servername: foo.com.
        try (TlsTester.Server server = TlsTester.serverWithServerAuth(kmfServer.getKeyManagers())) {
            Certificate[] gotServerCerts = TlsTester.connectWithSni(server, "foo.com", tmfClient.getTrustManagers())
                    .getServerCertificate();
            assertArrayEquals(serverFooCreds.getCertificates(), gotServerCerts);
        }

        // Create TLS connection with SNI servername: bar.com.
        try (TlsTester.Server server = TlsTester.serverWithServerAuth(kmfServer.getKeyManagers())) {
            Certificate[] gotServerCerts = TlsTester.connectWithSni(server, "bar.com", tmfClient.getTrustManagers())
                    .getServerCertificate();
            assertArrayEquals(serverBarCreds.getCertificates(), gotServerCerts);
        }
    }

    @Test
    void testFallbackCertificateSelection(@TempDir Path tempDir) throws Exception {

        // Create CA.
        Credential serverCaCreds = new Credential().subject("CN=server-ca");

        // Helper method createKeyManagerFactory() uses subject as KeyStore alias.
        // ReloadingKeyStore sorts aliases, so that we will have stable fallback / default certificate:
        // the key entry with alias that becomes first in sorting order.
        Credential serverFooCreds = new Credential().subject("CN=01-foo-com-credentials").issuer(serverCaCreds)
                .subjectAltName("DNS:foo.com");
        Credential serverFallbackCreds = new Credential().subject("CN=00-fallback-credentials").issuer(serverCaCreds);

        KeyManagerFactory kmfServer = TlsTester.createKeyManagerFactory(tempDir, serverFooCreds, serverFallbackCreds);
        TrustManagerFactory tmfClient = TlsTester.createTrustManagerFactory(tempDir, serverCaCreds);

        // Create TLS connection with SNI servername: foo.com.
        try (TlsTester.Server server = TlsTester.serverWithServerAuth(kmfServer.getKeyManagers())) {
            Certificate[] gotServerCerts = TlsTester.connectWithSni(server, "foo.com", tmfClient.getTrustManagers())
                    .getServerCertificate();
            assertArrayEquals(serverFooCreds.getCertificates(), gotServerCerts);
        }

        // Create TLS connection with SNI servername that does not match: unknown.com.
        try (TlsTester.Server server = TlsTester.serverWithServerAuth(kmfServer.getKeyManagers())) {
            Certificate[] gotServerCerts = TlsTester.connectWithSni(server, "unknown.com", tmfClient.getTrustManagers())
                    .getServerCertificate();
            assertArrayEquals(serverFallbackCreds.getCertificates(), gotServerCerts);
        }

        // Create TLS connection without SNI.
        try (TlsTester.Server server = TlsTester.serverWithServerAuth(kmfServer.getKeyManagers())) {
            Certificate[] gotServerCerts = TlsTester.connect(server, tmfClient.getTrustManagers())
                    .getServerCertificate();
            assertArrayEquals(serverFallbackCreds.getCertificates(), gotServerCerts);
        }
    }

    @Test
    void testMultipleServerCertificateWithKeyTypeSelection(@TempDir Path tempDir) throws Exception {

        // Create CA and server certificates: one with RSA and one with EC key types.
        Credential serverCaCreds = new Credential().subject("CN=server-ca");
        Credential serverRsaCreds = new Credential().subject("CN=rsa").issuer(serverCaCreds).keyType(KeyType.RSA);
        Credential serverEcCreds = new Credential().subject("CN=ec").issuer(serverCaCreds).keyType(KeyType.EC);

        KeyManagerFactory kmfServer = TlsTester.createKeyManagerFactory(tempDir, serverRsaCreds, serverEcCreds);
        TrustManagerFactory tmfClient = TlsTester.createTrustManagerFactory(tempDir, serverCaCreds);

        // Create TLS connection by only offering cipher that forces server to select RSA certificate.
        try (TlsTester.Server server = TlsTester.serverWithServerAuth(kmfServer.getKeyManagers())) {
            Certificate[] gotServerCerts = new TlsTester.Client(null, tmfClient.getTrustManagers())
                    .protocols(new String[] { "TLSv1.2" })
                    .ciphers(new String[] { "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" })
                    .connect(server)
                    .getServerCertificate();
            assertArrayEquals(serverRsaCreds.getCertificates(), gotServerCerts);
        }

        // Create TLS connection by only offering cipher that forces server to select EC certificate.
        try (TlsTester.Server server = TlsTester.serverWithServerAuth(kmfServer.getKeyManagers())) {
            Certificate[] gotServerCerts = new TlsTester.Client(null, tmfClient.getTrustManagers())
                    .protocols(new String[] { "TLSv1.2" })
                    .ciphers(new String[] { "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" })
                    .connect(server)
                    .getServerCertificate();
            assertArrayEquals(serverEcCreds.getCertificates(), gotServerCerts);
        }
    }

    @Test
    void testMultipleClientCertificatesWithKeyTypeSelection(@TempDir Path tempDir) throws Exception {

        // Create CA and server certificates: one with RSA and one with EC key types.
        Credential serverCaCreds = new Credential().subject("CN=server-ca");
        Credential serverRsaCreds = new Credential().subject("CN=rsa").issuer(serverCaCreds).keyType(KeyType.RSA);
        Credential serverEcCreds = new Credential().subject("CN=ec").issuer(serverCaCreds).keyType(KeyType.EC);

        // Create CA and client certificates: one with RSA and one with EC key types.
        Credential clientCaCreds = new Credential().subject("CN=client-ca");
        Credential clientRsaCreds = new Credential().subject("CN=rsa").issuer(clientCaCreds).keyType(KeyType.RSA);
        Credential clientEcCreds = new Credential().subject("CN=ec").issuer(clientCaCreds).keyType(KeyType.EC);

        KeyManagerFactory kmfServer = TlsTester.createKeyManagerFactory(tempDir, serverRsaCreds, serverEcCreds);
        TrustManagerFactory tmfServer = TlsTester.createTrustManagerFactory(tempDir, clientCaCreds);
        KeyManagerFactory kmfClient = TlsTester.createKeyManagerFactory(tempDir, clientRsaCreds, clientEcCreds);
        TrustManagerFactory tmfClient = TlsTester.createTrustManagerFactory(tempDir, serverCaCreds);

        // Create server that only offers RSA cipher and forces client to select RSA certificate.
        try (TlsTester.Server server = new TlsTester.Server(kmfServer.getKeyManagers(), tmfServer.getTrustManagers())) {
            server.ciphers(new String[] { "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" })
                    .protocols(new String[] { "TLSv1.2" });
            Certificate[] gotServerCerts = TlsTester
                    .connect(server, kmfClient.getKeyManagers(), tmfClient.getTrustManagers())
                    .getServerCertificate();
            assertArrayEquals(serverRsaCreds.getCertificates(), gotServerCerts);
            // TODO: EC key gets selected
            //       assertArrayEquals(clientRsaCreds.getCertificates(), server.getClientCertificates());
        }

        // Create server that only offers EC cipher and forces client to select EC certificate.
        try (TlsTester.Server server = new TlsTester.Server(kmfServer.getKeyManagers(), tmfServer.getTrustManagers())) {
            server.ciphers(new String[] { "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" })
                    .protocols(new String[] { "TLSv1.2" });
            Certificate[] gotServerCerts = TlsTester
                    .connect(server, kmfClient.getKeyManagers(), tmfClient.getTrustManagers())
                    .getServerCertificate();
            assertArrayEquals(serverEcCreds.getCertificates(), gotServerCerts);
            assertArrayEquals(clientEcCreds.getCertificates(), server.getClientCertificates());
        }
    }

    @Test
    void testMultipleClientCertificatesWithAuthoritySelection(@TempDir Path tempDir) throws Exception {

        // Create server CA and server certificate.
        Credential serverCaCreds = new Credential().subject("CN=server-ca");
        Credential serverCreds = new Credential().subject("CN=server").issuer(serverCaCreds);

        Credential clientCa1Creds = new Credential().subject("CN=client-ca-1");
        Credential clientCa2Creds = new Credential().subject("CN=client-ca-2");
        Credential client1Creds = new Credential().subject("CN=client-1").issuer(clientCa1Creds);
        Credential client2Creds = new Credential().subject("CN=client-2").issuer(clientCa2Creds);

        KeyManagerFactory kmfServer = TlsTester.createKeyManagerFactory(tempDir, serverCreds);
        TrustManagerFactory tmfClient = TlsTester.createTrustManagerFactory(tempDir, serverCaCreds);
        KeyManagerFactory kmfClient = TlsTester.createKeyManagerFactory(tempDir, client1Creds, client2Creds);

        // Create TLS connection when server has client-ca-1 as trust anchor for client cert auth.
        try (TlsTester.Server server = TlsTester.serverWithMutualAuth(
                kmfServer.getKeyManagers(),
                TlsTester.createTrustManagerFactory(tempDir, clientCa1Creds).getTrustManagers())) {

            Certificate[] gotServerCerts = TlsTester
                    .connect(server, kmfClient.getKeyManagers(), tmfClient.getTrustManagers())
                    .getServerCertificate();
            Certificate[] gotClientCerts = server.getClientCertificates();
            assertArrayEquals(serverCreds.getCertificates(), gotServerCerts);
            assertArrayEquals(client1Creds.getCertificates(), gotClientCerts);
        }

        // Create TLS connection when server has client-ca-2 as trust anchor for client cert auth.
        try (TlsTester.Server server = TlsTester.serverWithMutualAuth(
                kmfServer.getKeyManagers(),
                TlsTester.createTrustManagerFactory(tempDir, clientCa2Creds).getTrustManagers())) {

            Certificate[] gotServerCerts = TlsTester
                    .connect(server, kmfClient.getKeyManagers(), tmfClient.getTrustManagers())
                    .getServerCertificate();
            Certificate[] gotClientCerts = server.getClientCertificates();
            assertArrayEquals(serverCreds.getCertificates(), gotServerCerts);
            assertArrayEquals(client2Creds.getCertificates(), gotClientCerts);
        }
    }

    @Test
    void testKeyStoreEncryptedKeysWithDifferentPasswords(@TempDir Path tempDir) throws Exception {
        Path ksPath = tempDir.resolve("server.p12");
        Path tsPath = tempDir.resolve("trusted.p12");

        // Create CA and server certificates for a server that supports several virtualhosts.
        Credential serverCaCreds = new Credential().subject("CN=server-ca");
        Credential serverFooCreds = new Credential().subject("CN=foo.com").issuer(serverCaCreds);
        Credential serverBarCreds = new Credential().subject("CN=bar.com").issuer(serverCaCreds);

        // Create keystore files.
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry("foo", serverFooCreds.getPrivateKey(), "password foo".toCharArray(),
                serverFooCreds.getCertificates());
        ks.setKeyEntry("bar", serverBarCreds.getPrivateKey(), "password bar".toCharArray(),
                serverBarCreds.getCertificates());
        ks.store(Files.newOutputStream(ksPath), "secret".toCharArray());

        KeyStore ts = KeyStore.getInstance("PKCS12");
        ts.load(null, null);
        ts.setCertificateEntry("trusted", serverCaCreds.getCertificate());
        ts.store(Files.newOutputStream(tsPath), "secret".toCharArray());

        // Create KeyManager for server.
        KeyManagerFactory kmfServer = KeyManagerFactory.getInstance("NewSunX509");
        Map<String, char[]> aliasPasswords = new HashMap<>();
        aliasPasswords.put("foo", "password foo".toCharArray());
        aliasPasswords.put("bar", "password bar".toCharArray());
        kmfServer.init(new KeyStoreBuilderParameters(ReloadingKeyStore.Builder.fromKeyStoreFile("PKCS12", "SunJSSE", ksPath,
                "secret", aliasPasswords)));

        // Create TrustManager for client.
        TrustManagerFactory tmfClient = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()); // algorithm=PKIX
        tmfClient.init(ReloadingKeyStore.Builder.fromKeyStoreFile("PKCS12", "SunJSSE", tsPath,
                "secret").getKeyStore());

        // Create TLS connection with SNI servername: foo.com.
        try (TlsTester.Server server = TlsTester.serverWithServerAuth(kmfServer.getKeyManagers())) {
            Certificate[] gotServerCerts = TlsTester.connectWithSni(server, "foo.com", tmfClient.getTrustManagers())
                    .getServerCertificate();
            assertArrayEquals(serverFooCreds.getCertificates(), gotServerCerts);
        }

        // Create TLS connection with SNI servername: bar.com.
        try (TlsTester.Server server = TlsTester.serverWithServerAuth(kmfServer.getKeyManagers())) {
            Certificate[] gotServerCerts = TlsTester.connectWithSni(server, "bar.com", tmfClient.getTrustManagers())
                    .getServerCertificate();
            assertArrayEquals(serverBarCreds.getCertificates(), gotServerCerts);
        }

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
