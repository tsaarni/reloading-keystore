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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import fi.protonode.certy.Credential;
import fi.protonode.certy.Credential.KeyType;

/**
 * Decode certificates and private keys from PEM files.
 */
public class TestPemCredentialFactory {

    @Test
    void loadPemCertificateFile(@TempDir Path tempDir) throws Exception {
        Path certPath = tempDir.resolve("cert.pem");
        new Credential().subject("CN=joe").keyType(KeyType.RSA).writeCertificateAsPem(certPath);

        Certificate[] certs = PemCredentialFactory.generateCertificates(certPath);
        assertNotNull(certs);
        assertEquals(1, certs.length);
        assertEquals("CN=joe", ((X509Certificate) certs[0]).getSubjectX500Principal().getName());
    }

    @Test
    void loadPemPrivateKeyFile(@TempDir Path tempDir) throws Exception {
        Path ecPath = tempDir.resolve("pkey-ec.pem");
        new Credential().subject("CN=ec").keyType(KeyType.EC).writePrivateKeyAsPem(ecPath);

        PrivateKey pKeyEc = PemCredentialFactory.generatePrivateKey(ecPath);
        assertNotNull(pKeyEc);
        assertEquals("EC", pKeyEc.getAlgorithm());

        Path rsaPath = tempDir.resolve("pkey-rsa.pem");
        new Credential().subject("CN=rsa").keyType(KeyType.RSA).writePrivateKeyAsPem(rsaPath);

        PrivateKey pKeyRsa = PemCredentialFactory.generatePrivateKey(rsaPath);
        assertNotNull(pKeyRsa);
        assertEquals("RSA", pKeyRsa.getAlgorithm());
    }
}
