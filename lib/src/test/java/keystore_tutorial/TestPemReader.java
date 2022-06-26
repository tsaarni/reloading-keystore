package keystore_tutorial;

import org.junit.jupiter.api.Test;

import fi.protonode.certy.Credential;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;

public class TestPemReader {

    @Test
    void testPemBundle() throws Exception {
        // Create bundle with certificate and private key.
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
