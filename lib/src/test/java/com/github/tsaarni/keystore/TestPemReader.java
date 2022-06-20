package com.github.tsaarni.keystore;

import org.junit.jupiter.api.Test;

import fi.protonode.certy.Credential;

import static org.junit.jupiter.api.Assertions.*;

public class TestPemReader {

    @Test
    void testPemReader() throws Exception {
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
}
