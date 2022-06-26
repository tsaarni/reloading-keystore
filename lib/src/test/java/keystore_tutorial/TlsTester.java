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

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
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
import java.util.Arrays;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.KeyStoreBuilderParameters;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import fi.protonode.certy.Credential;

public class TlsTester {

    private TlsTester() {
    }

    /**
     * Server that accepts client connections, executes TLS handshake and then
     * closes the client connection.
     */
    static public class Server implements Runnable, Closeable {

        private final String host = "localhost";
        private final int port = 18040;
        private ExecutorService executor = Executors.newSingleThreadExecutor();
        private final SSLContext ctx = SSLContext.getInstance("TLS");
        private SSLServerSocket sock;
        private String[] protocols = new String[] { "TLSv1.2" }; // Easier to troubleshoot with Wireshark than TLSv1.3.
        private boolean clientAuthentication;

        CompletableFuture<Certificate[]> clientCertificates;

        Server(KeyManager[] kms, TrustManager[] tms)
                throws NoSuchAlgorithmException, KeyManagementException, IOException {

            // Initialize server socket.
            ctx.init(kms, tms, null);
            SSLServerSocketFactory ssf = ctx.getServerSocketFactory();
            sock = (SSLServerSocket) ssf.createServerSocket(port, 1, InetAddress.getByName(host));
            sock.setEnabledProtocols(protocols);

            // Enable client authentication if TrustManager(s) are given.
            if (tms == null) {
                clientAuthentication = false;
                sock.setWantClientAuth(false);
                sock.setNeedClientAuth(false);
            } else {
                clientAuthentication = true;
                sock.setWantClientAuth(true);
                sock.setNeedClientAuth(true);
            }

            // Future for passing client credentials back to main thread.
            clientCertificates = new CompletableFuture<>();

            // Start the server.
            executor.execute(this);
        }

        @Override
        public void close() {
            try {
                sock.close();
                executor.shutdown();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        @Override
        public void run() {

            // Wait for client to connect.
            try (SSLSocket client = (SSLSocket) sock.accept()) {
                InputStream is = new BufferedInputStream(client.getInputStream());
                OutputStream os = new BufferedOutputStream(client.getOutputStream());

                // Execute TLS handshake.
                client.startHandshake();

                // Pass the client credentials to main thread if client authentication was
                // enabled.
                if (clientAuthentication) {
                    SSLSession sess = client.getSession();
                    clientCertificates.complete(sess.getPeerCertificates());
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        int getPort() {
            return port;
        }

        String getHost() {
            return host;
        }

        /**
         * Returns the client certificates that were used to connect the server.
         * If client authentication was not used, times out in two seconds and raises an
         * exception.
         * Can be called in main thread.
         */
        public Certificate[] getClientCertificates()
                throws InterruptedException, ExecutionException, SSLPeerUnverifiedException {
            try {
                return clientCertificates.get(2, TimeUnit.SECONDS);
            } catch (TimeoutException e) {
                throw new SSLPeerUnverifiedException("Did not receive client certificate");
            }
        }
    }

    /**
     * Creates server with server authentication only.
     */
    public static Server serverWithServerAuth(KeyManager[] kms)
            throws KeyManagementException, NoSuchAlgorithmException, IOException {
        return new Server(kms, null);
    }

    /**
     * Creates server with mutual authentication.
     */
    public static Server serverWithMutualAuth(KeyManager[] kms, TrustManager[] tms)
            throws KeyManagementException, NoSuchAlgorithmException, IOException {
        return new Server(kms, tms);
    }

    /**
     * Client that establishes connection, executes TLS handshake and then closes
     * the connection.
     */
    static public class Client {

        private final SSLContext ctx = SSLContext.getInstance("TLS");
        SSLSocket socket;

        public Client(KeyManager[] kms, TrustManager[] tms)
                throws NoSuchAlgorithmException, KeyManagementException, IOException {
            ctx.init(kms, tms, null);
            SSLSocketFactory sf = ctx.getSocketFactory();
            socket = (SSLSocket) sf.createSocket();
        }

        public Client serverName(String serverName) {
            SSLParameters params = socket.getSSLParameters();
            SNIHostName sni = new SNIHostName(serverName);
            params.setServerNames(Arrays.asList(sni));
            socket.setSSLParameters(params);
            return this;
        }

        public Client ciphers(String[] suites) {
            socket.setEnabledCipherSuites(suites);
            return this;
        }

        public Client protocols(String[] protocols) {
            socket.setEnabledProtocols(protocols);
            return this;
        }

        public Client connect(Server server) throws IOException {
            return connect(server.getHost(), server.getPort());
        }

        public Client connect(String host, int port) throws IOException  {
            socket.connect(new InetSocketAddress(host, port), 2000 /* msec */);
            socket.startHandshake();
            return this;
        }

        public  Certificate[] getServerCertificate() throws SSLPeerUnverifiedException {
            return socket.getSession().getPeerCertificates();
        }
    }

    /**
     * Creates client that connects to the server using TLS server authentication
     * only.
     */
    public static  Client connect(Server server, TrustManager[] tms)
            throws UnknownHostException, IOException, KeyManagementException, NoSuchAlgorithmException {
        return new Client(null, tms).connect(server);
    }

    /**
     * Creates client that connects to the server using mutual TLS authentication.
     */
    public static Client connect(Server server, KeyManager[] kms, TrustManager[] tms)
            throws KeyManagementException, UnknownHostException, NoSuchAlgorithmException, IOException {
        return new Client(kms, tms).connect(server);
    }

    /**
     * Creates client that connects to the server using server authentication only,
     * sends server name in SNI extension.
     */
    public static Client connectWithSni(Server server, String serverName, TrustManager[] tms)
            throws KeyManagementException, UnknownHostException, NoSuchAlgorithmException, IOException {
        return new Client(null, tms).serverName(serverName).connect(server);
    }


    public static KeyManagerFactory createKeyManagerFactory(Path tempDir, Credential... credentials)
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

        // Load the keystore from disk with ReloadingKeyStore and construct
        // KeyManagerFactory for it.
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("NewSunX509");
        kmf.init(new KeyStoreBuilderParameters(ReloadingKeyStore.Builder.fromKeyStoreFile("PKCS12", "SUN", ksPath,
                "", null, null)));

        return kmf;
    }

    public static TrustManagerFactory createTrustManagerFactory(Path tempDir, Credential... credentials)
            throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException,
            NoSuchProviderException {

        // Create empty KeyStore.
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);

        // Add given trusted certificates as CertificateEntries.
        for (Credential c : credentials) {
            ks.setCertificateEntry(c.getX509Certificate().getSubjectX500Principal().toString(), c.getCertificate());
        }

        // Store keystore to disk.
        Path ksPath = tempDir.resolve(ks.toString());
        ks.store(Files.newOutputStream(ksPath), "".toCharArray());

        // Load the keystore from disk with ReloadingKeyStore and construct
        // TrustManagerFactory for it.
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()); // algorithm=PKIX
        tmf.init(ReloadingKeyStore.Builder.fromKeyStoreFile("PKCS12", "SUN", ksPath,
                "", null, null).getKeyStore());

        return tmf;
    }
}
