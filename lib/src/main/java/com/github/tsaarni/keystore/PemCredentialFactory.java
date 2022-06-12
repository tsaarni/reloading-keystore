package com.github.tsaarni.keystore;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;

public class PemCredentialFactory {

    private PemCredentialFactory() {
        // Empty.
    }

    public static Certificate[] generateCertificates(Path p) throws IOException, CertificateException {
        List<Certificate> certs = new ArrayList<>();
        try (InputStream input = Files.newInputStream(p)) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            for (Certificate c : cf.generateCertificates(input)) {
                certs.add(c);
            }
        }
        return certs.toArray(new Certificate[0]);
    }

    public static PrivateKey generatePrivateKey(Path p) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
        // Loop through PEM blocks until PRIVATE KEY type.
        PemReader.Block block;
        while ((block = new PemReader(p).decode()) != null) {
            if (block.getType().equals("PRIVATE KEY")) {
                break;
            }
        }

        // Throw exception if no PRIVATE KEY in PEM file.
        if (block == null) {
            throw new IllegalArgumentException("PEM file does not have private key");
        }

        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(block.getBytes());

        // First try to parse content as RSA key.
        PrivateKey pkey = tryDecodePkey("RSA", spec);

        // If it did not succeed, try parse content as EC key.
        if (pkey == null) {
            pkey = tryDecodePkey("EC", spec);
        }

        // Throw exception if parsing failed for all algorithms.
        if (pkey == null) {
            throw new InvalidKeySpecException("Invalid private key");
        }

        return pkey;
    }

    private static PrivateKey tryDecodePkey(String algo, PKCS8EncodedKeySpec spec) throws NoSuchAlgorithmException {
        try {
            return KeyFactory.getInstance(algo).generatePrivate(spec);
        } catch (InvalidKeySpecException e) {
            // Ignore exception and return null if decoding fails.
            return null;
        }
    }

}
