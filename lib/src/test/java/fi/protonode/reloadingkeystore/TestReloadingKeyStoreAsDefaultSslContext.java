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

package fi.protonode.reloadingkeystore;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import java.nio.file.Path;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import fi.protonode.certy.Credential;

public class TestReloadingKeyStoreAsDefaultSslContext {

    // Copy of default SSL context so that it can be restored after test case.
    SSLContext systemDefaultContext;

    @BeforeAll
    static void enableJavaLogs() {
        // Enable Java KeyManager and TrustManager debug printouts.
        System.setProperty("javax.net.debug", "keymanager:trustmanager");
    }

    @BeforeEach
    void getDefaultContext() throws NoSuchAlgorithmException {
        systemDefaultContext = SSLContext.getDefault();
    }

    @AfterEach
    void restoreDefaultContext() {
        SSLContext.setDefault(systemDefaultContext);
    }

    @Test
    void testClientWithDefaultSslContext(@TempDir Path tempDir) throws Exception {
        // Create CAs, server and client certificate.
        Credential serverCaCreds = new Credential().subject("CN=server-ca");
        Credential clientCaCreds = new Credential().subject("CN=client-ca");
        Credential serverCreds = new Credential().subject("CN=server").issuer(serverCaCreds);
        Credential clientCreds = new Credential().subject("CN=client").issuer(clientCaCreds);

        // Create KeyManagers and TrustManagers with the credentials.
        KeyManagerFactory kmfServer = TlsTester.createKeyManagerFactory(tempDir, serverCreds);
        TrustManagerFactory tmfServer = TlsTester.createTrustManagerFactory(tempDir, clientCaCreds);

        KeyManagerFactory kmfClient = TlsTester.createKeyManagerFactory(tempDir, clientCreds);
        TrustManagerFactory tmfClient = TlsTester.createTrustManagerFactory(tempDir, serverCaCreds);

        // Override the default SSL context with SSLContext that is initialized with ReloadingKeyStores:
        // - KeyManager with ReloadingKeyStore including client certificate and private key.
        // - TrustManager with ReloadingKeyStore including server CA certificate.
        SSLContext newDefaultContext = SSLContext.getInstance("TLS");
        newDefaultContext.init(kmfClient.getKeyManagers(), tmfClient.getTrustManagers(), null);
        SSLContext.setDefault(newDefaultContext);

        // Create TLS connection with default SSLContext.
        // Successful connection establishment proves that the CA certificate in new default context was in place.
        // Check that server received client certificate, which also proves that the new default context was used.
        try (TlsTester.Server server = TlsTester.serverWithMutualAuth(kmfServer.getKeyManagers(),
                tmfServer.getTrustManagers())) {

            SSLSocket clientSockWithDefaultContext = (SSLSocket) SSLSocketFactory.getDefault()
                    .createSocket(server.getHost(), server.getPort());
            clientSockWithDefaultContext.startHandshake();

            Certificate[] gotClientCerts = server.getClientCertificates();
            assertArrayEquals(clientCreds.getCertificates(), gotClientCerts);
        }
    }

}
