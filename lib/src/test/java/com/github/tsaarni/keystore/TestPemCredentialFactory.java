package com.github.tsaarni.keystore;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.github.tsaarni.keystore.Certy.KeyType;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

public class TestPemCredentialFactory {

    @Test
    void loadPemCertificateFile(@TempDir Path tempDir) throws Exception {
        Path certPath = tempDir.resolve("cert.pem");
        Certy.newCredential().subject("CN=joe").keyType(KeyType.RSA).writeCertificateAsPem(certPath);

        Certificate[] certs = PemCredentialFactory.generateCertificates(certPath);
        assertNotNull(certs);
        assertEquals(1, certs.length);
        assertEquals("CN=joe", ((X509Certificate) certs[0]).getSubjectDN().getName());
    }

    @Test
    void loadPemPrivateKeyFile(@TempDir Path tempDir) throws Exception {
        Path ecPath = tempDir.resolve("pkey-ec.pem");
        Certy.newCredential().subject("CN=ec").keyType(KeyType.EC).writePrivateKeyAsPem(ecPath);

        PrivateKey pKeyEc = PemCredentialFactory.generatePrivateKey(ecPath);
        assertNotNull(pKeyEc);
        assertEquals("EC", pKeyEc.getAlgorithm());

        Path rsaPath = tempDir.resolve("pkey-rsa.pem");
        Certy.newCredential().subject("CN=rsa").keyType(KeyType.RSA).writePrivateKeyAsPem(rsaPath);

        PrivateKey pKeyRsa = PemCredentialFactory.generatePrivateKey(rsaPath);
        assertNotNull(pKeyRsa);
        assertEquals("RSA", pKeyRsa.getAlgorithm());
    }
}
