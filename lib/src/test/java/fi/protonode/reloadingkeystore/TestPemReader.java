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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.io.IOException;

import org.junit.jupiter.api.Test;

import fi.protonode.certy.Credential;

/**
 * Parse PEM files.
 */
public class TestPemReader {

    @Test
    void testPemBundle() throws Exception {
        // Create bundle with certificate and private key in single file.
        Credential cred = new Credential().subject("CN=joe");
        String pemBundle = cred.getCertificateAsPem() + cred.getPrivateKeyAsPem();

        PemReader reader = new PemReader(pemBundle.getBytes());
        PemReader.Block block = reader.decode();
        assertEquals("CERTIFICATE", block.getType());

        block = reader.decode();
        assertEquals("PRIVATE KEY", block.getType());

        block = reader.decode();
        assertNull(block);
    }

    @Test
    void testFailWhenInvalidPemFile() throws IOException {
        String invalid = "this\nis\nnot\nPEM\n";
        PemReader reader = new PemReader(invalid.getBytes());
        PemReader.Block block = reader.decode();
        assertNull(block);
    }
}
