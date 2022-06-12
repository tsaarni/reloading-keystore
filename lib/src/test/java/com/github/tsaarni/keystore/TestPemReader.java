package com.github.tsaarni.keystore;

import org.junit.jupiter.api.Test;


import static org.junit.jupiter.api.Assertions.*;

public class TestPemReader {

    @Test
    void testPemReader() throws Exception {
        Certy cred = Certy.newCredential().subject("CN=joe");
        String pemBundle = cred.getCertificateAsPem() + cred.getPrivateKeyAsPem();

        PemReader reader = new PemReader(pemBundle.getBytes());
        PemReader.Block block = reader.decode();
        assertEquals("CERTIFICATE", block.getType());

        block = reader.decode();
        assertEquals("PRIVATE KEY", block.getType());

        block = reader.decode();
        assertNull(block);
    }
}
