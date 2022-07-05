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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Reads PEM files and constructs {@code Certificates} and {@code PrivateKeys} from them.
 */
public class PemCredentialFactory {

    private static final Logger log = LoggerFactory.getLogger(PemCredentialFactory.class);

    private PemCredentialFactory() {
        // Empty.
    }

    /**
     * Reads PEM encoded certificate or certificate bundle from file and constructs an array of {@code Certificate}.
     *
     * @param path Path to PEM file.
     * @return Array of one or more certificates.
     */
    public static Certificate[] generateCertificates(Path path) throws IOException, CertificateException {
        log.debug("Loading PEM certificate(s) from {}", path);
        List<Certificate> certs = new ArrayList<>();
        try (InputStream input = Files.newInputStream(path)) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            for (Certificate c : cf.generateCertificates(input)) {
                certs.add(c);
            }
        }
        return certs.toArray(new Certificate[0]);
    }

    /**
     * Reads PEM encoded private key (PKCS#8) from file and construct {@code PrivateKey}.
     *
     * @param path Path to PEM file.
     * @return Private key.
     */
    public static PrivateKey generatePrivateKey(Path path)
            throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
        log.debug("Loading PEM private key from {}", path);

        // Loop through PEM blocks until PRIVATE KEY type.
        PemReader reader = new PemReader(path);
        PemReader.Block block = null;
        while ((block = reader.decode()) != null) {
            if (block.getType().equals("PRIVATE KEY")) {
                break;
            }
        }

        // Throw exception if no PRIVATE KEY in PEM file.
        if (block == null) {
            log.error("Cannot find PRIVATE KEY PEM block in {}", path);
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
            log.error("Cannot decode private key {}", path);
            throw new InvalidKeySpecException("Invalid private key");
        }

        return pkey;
    }

    /**
     * Attempts to decode PKCS8 key as a key of given {@code algo}.
     *
     * @param algo Key algorithm name.
     * @param spec Private key spec,
     * @return PrivateKey pointer if successful, null if private key could not be parsed as given algorithm.
     */
    private static PrivateKey tryDecodePkey(String algo, PKCS8EncodedKeySpec spec) throws NoSuchAlgorithmException {
        PrivateKey pkey = null;
        try {
            pkey = KeyFactory.getInstance(algo).generatePrivate(spec);
            log.debug("Found {} private key", algo);
        } catch (InvalidKeySpecException e) {
            // Ignore exception and return null if decoding fails.
        }
        return pkey;
    }

}
