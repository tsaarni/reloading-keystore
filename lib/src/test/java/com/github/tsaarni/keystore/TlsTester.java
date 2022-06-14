package com.github.tsaarni.keystore;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;

public class TlsTester {


    private TlsTester() {
    }

    static class Server implements Runnable, Closeable {

        private final String host = "localhost";
        private final int port = 18040;
        private ExecutorService executor = Executors.newSingleThreadExecutor();
        private final SSLContext ctx = SSLContext.getInstance("TLS");
        private SSLServerSocket sock;
        private String[] protocols = new String[] {"TLSv1.2"};

        CompletableFuture<Certificate[]> clientCertificates;

        Server(KeyManager[] kms, TrustManager[] tms) throws NoSuchAlgorithmException, KeyManagementException, IOException {
            ctx.init(kms, tms, null);

            SSLServerSocketFactory ssf = ctx.getServerSocketFactory();
            sock = (SSLServerSocket) ssf.createServerSocket(port, 1, InetAddress.getByName(host));
            sock.setEnabledProtocols(protocols);
            sock.setWantClientAuth(false);
            sock.setNeedClientAuth(false);

            clientCertificates = new CompletableFuture<>();

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
            try (SSLSocket client = (SSLSocket) sock.accept()) {
                InputStream is = new BufferedInputStream(client.getInputStream());
                OutputStream os = new BufferedOutputStream(client.getOutputStream());
                byte[] data = new byte[2048];
                int len = is.read(data);
                SSLSession sess = client.getSession();
                clientCertificates.complete(sess.getPeerCertificates());
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

    }

    static class Client {

        private final SSLContext ctx = SSLContext.getInstance("TLS");
        SSLSocket socket;

        Client(KeyManager[] kms, TrustManager[] tms) throws NoSuchAlgorithmException, KeyManagementException {
            ctx.init(kms, tms, null);

        }

        Client connect(String host, int port) throws UnknownHostException, IOException {
            SSLSocketFactory sf = ctx.getSocketFactory();
            socket = (SSLSocket) sf.createSocket(host, port);
            return this;
        }

        Certificate[] getServerCertificate() throws SSLPeerUnverifiedException {
            return socket.getSession().getPeerCertificates();
        }
    }

    static public Server withServerAuth(KeyManager[] kms)
            throws KeyManagementException, NoSuchAlgorithmException, IOException {
        return new Server(kms, null);
    }

    static public Server withMutualAuth(KeyManager[] kms, TrustManager[] tms)
            throws KeyManagementException, NoSuchAlgorithmException, IOException {
        return new Server(kms, tms);
    }

    static public Client connectTo(TrustManager[] tms, Server server) throws UnknownHostException, IOException, KeyManagementException, NoSuchAlgorithmException {
        return new Client(null, tms).connect(server.getHost(), server.getPort());
    }
}
