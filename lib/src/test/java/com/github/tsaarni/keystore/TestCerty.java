package com.github.tsaarni.keystore;

import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.util.io.pem.PemObject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.github.tsaarni.keystore.Certy.ExtKeyUsage;
import com.github.tsaarni.keystore.Certy.KeyType;
import com.github.tsaarni.keystore.Certy.KeyUsage;

import static org.junit.jupiter.api.Assertions.*;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Date;

public class TestCerty {

    @Test
    void testSubjectName() throws Exception {
        X509Certificate cert = Certy.newCredential().subject("CN=joe").getX509Certificate();
        assertNotNull(cert);
        assertEquals("CN=joe", cert.getSubjectDN().getName());
    }

    @Test
    void testSubjectAltName() throws Exception {
        X509Certificate cert = Certy.newCredential().subject("CN=joe")
                .subjectAltNames(Arrays.asList("DNS:host.example.com", "URI:http://www.example.com", "IP:1.2.3.4"))
                .getX509Certificate();
        assertNotNull(cert);
        assertEquals("CN=joe", cert.getSubjectDN().getName());
        Object expected[] = new Object[] {
                Arrays.asList(GeneralName.dNSName, "host.example.com"),
                Arrays.asList(GeneralName.uniformResourceIdentifier, "http://www.example.com"),
                Arrays.asList(GeneralName.iPAddress, "1.2.3.4") };
        assertArrayEquals(expected, cert.getSubjectAlternativeNames().toArray());
    }

    @Test
    void testEcKeySize() throws Exception {
        Certy cred = Certy.newCredential().subject("CN=joe")
                .keyType(KeyType.EC)
                .keySize(256);
        expectKey(cred.getX509Certificate(), "EC", 256);
        cred.keySize(384).generate();
        expectKey(cred.getX509Certificate(), "EC", 384);
        cred.keySize(521).generate();
        expectKey(cred.getX509Certificate(), "EC", 521);
    }

    @Test
    void testRsaKeySize() throws Exception {
        Certy cred = Certy.newCredential().subject("CN=joe")
                .keyType(KeyType.RSA)
                .keySize(1024);
        expectKey(cred.getX509Certificate(), "RSA", 1024);
        cred.keySize(2048).generate();
        expectKey(cred.getX509Certificate(), "RSA", 2048);
        cred.keySize(4096).generate();
        expectKey(cred.getX509Certificate(), "RSA", 4096);
    }

    void expectKey(X509Certificate cert, String expectedKeyType, int expectedSize) {
        assertNotNull(cert);
        switch (expectedKeyType) {
            case "EC":
                assertEquals("EC", cert.getPublicKey().getAlgorithm());
                ECPublicKey ecKey = (ECPublicKey) cert.getPublicKey();
                ECParameterSpec spec = ecKey.getParams();
                assertEquals(expectedSize, spec.getOrder().bitLength());
                break;
            case "RSA":
                assertEquals("RSA", cert.getPublicKey().getAlgorithm());
                RSAPublicKey rsaKey = (RSAPublicKey) cert.getPublicKey();
                assertEquals(expectedSize, rsaKey.getModulus().bitLength());
                break;
            default:
                fail("invalid key type given to test case");
        }
    }

    @Test
    void testExpires() throws Exception {
        Duration hour = Duration.of(1, ChronoUnit.DAYS);
        X509Certificate cert = Certy.newCredential().subject("CN=joe").expires(hour).getX509Certificate();
        assertNotNull(cert);
        assertEquals(hour, Duration.between(cert.getNotBefore().toInstant(), cert.getNotAfter().toInstant()));
    }

    @Test
    void testKeyUsage() throws Exception {
        Certy cred = Certy.newCredential().subject("CN=joe");

        // Order of the boolean array from:
        //    boolean[] java.security.cert.X509Certificate.getKeyUsage()
        //
        //  digitalSignature        (0),
        //  nonRepudiation          (1),
        //  keyEncipherment         (2),
        //  dataEncipherment        (3),
        //  keyAgreement            (4),
        //  keyCertSign             (5),
        //  cRLSign                 (6),
        //  encipherOnly            (7),
        //  decipherOnly            (8)
        assertArrayEquals(new boolean[] { true, false, false, false, false, false, false, false, false },
                cred.keyUsages(Arrays.asList(KeyUsage.DIGITAL_SIGNATURE)).getX509Certificate().getKeyUsage());

        assertArrayEquals(new boolean[] { true, false, true, false, false, false, false, false, false },
                cred.keyUsages(Arrays.asList(KeyUsage.DIGITAL_SIGNATURE, KeyUsage.KEY_ENCIPHERMENT))
                        .generate()
                        .getX509Certificate().getKeyUsage());

        assertArrayEquals(new boolean[] { true, true, true, true, true, true, true, true, true },
                cred.keyUsages(Arrays.asList(KeyUsage.DIGITAL_SIGNATURE, KeyUsage.NON_REPUDIATION,
                        KeyUsage.KEY_ENCIPHERMENT, KeyUsage.DATA_ENCIPHERMENT, KeyUsage.KEY_AGREEMENT,
                        KeyUsage.KEY_CERT_SIGN, KeyUsage.CRL_SIGN, KeyUsage.ENCIPHER_ONLY, KeyUsage.DECIPHER_ONLY))
                        .generate()
                        .getX509Certificate().getKeyUsage());
    }

    @Test
    void testExtendedKeyUsage() throws Exception {
        Certy cred = Certy.newCredential().subject("CN=joe");

        assertEquals(Arrays.asList(KeyPurposeId.anyExtendedKeyUsage.toString()),
                cred.extKeyUsages(Arrays.asList(ExtKeyUsage.ANY)).getX509Certificate().getExtendedKeyUsage());

        assertEquals(Arrays.asList(KeyPurposeId.id_kp_clientAuth.toString(), KeyPurposeId.id_kp_serverAuth.toString()),
                cred.extKeyUsages(Arrays.asList(ExtKeyUsage.CLIENT_AUTH, ExtKeyUsage.SERVER_AUTH))
                        .generate()
                        .getX509Certificate().getExtendedKeyUsage());

        assertEquals(
                Arrays.asList(KeyPurposeId.id_kp_clientAuth.toString(), KeyPurposeId.id_kp_serverAuth.toString(),
                        KeyPurposeId.id_kp_codeSigning.toString(), KeyPurposeId.id_kp_emailProtection.toString(),
                        KeyPurposeId.id_kp_OCSPSigning.toString(), KeyPurposeId.id_kp_timeStamping.toString()),
                cred.extKeyUsages(
                        Arrays.asList(ExtKeyUsage.CLIENT_AUTH, ExtKeyUsage.SERVER_AUTH, ExtKeyUsage.CODE_SIGNING,
                                ExtKeyUsage.EMAIL_PROTECTION, ExtKeyUsage.OCSP_SIGNING, ExtKeyUsage.TIME_STAMPING))
                        .generate()
                        .getX509Certificate().getExtendedKeyUsage());
    }

    @Test
    void testIssuer() throws Exception {
        Certy issuer = Certy.newCredential().subject("CN=ca");
        assertEquals("CN=ca", issuer.getX509Certificate().getSubjectDN().toString());
        assertEquals("CN=ca", issuer.getX509Certificate().getIssuerDN().toString());
        assertEquals(Integer.MAX_VALUE, issuer.getX509Certificate().getBasicConstraints());

        Certy endEntity = Certy.newCredential().subject("CN=EndEntity").issuer(issuer);
        assertEquals("CN=EndEntity", endEntity.getX509Certificate().getSubjectDN().toString());
        assertEquals("CN=ca", endEntity.getX509Certificate().getIssuerDN().toString());
        assertEquals(-1, endEntity.getX509Certificate().getBasicConstraints());
    }

    @Test
    void testIsCa() throws Exception {
        Certy issuer = Certy.newCredential().subject("CN=joe");
        assertArrayEquals(new boolean[] { false, false, false, false, false, true, true, false, false },
                issuer.getX509Certificate().getKeyUsage());
        assertEquals(Integer.MAX_VALUE, issuer.getX509Certificate().getBasicConstraints());

        issuer.isCa(true).generate();
        assertArrayEquals(new boolean[] { false, false, false, false, false, true, true, false, false },
                issuer.getX509Certificate().getKeyUsage());
        assertEquals(Integer.MAX_VALUE, issuer.getX509Certificate().getBasicConstraints());

        Certy endEntity = Certy.newCredential().subject("CN=EndEntity").issuer(issuer);
        assertArrayEquals(new boolean[] { true, false, true, false, true, false, false, false, false },
                endEntity.getX509Certificate().getKeyUsage());
        assertEquals(-1, endEntity.getX509Certificate().getBasicConstraints());
    }

    @Test
    void testNotBeforeAndNotAfter() throws Exception {
        Date wantNotBefore = Date.from(Instant.parse("2022-01-01T09:00:00Z"));
        Date wantNotAfter = Date.from(Instant.parse("2022-02-01T09:00:00Z"));
        Duration defaultDuration = Duration.of(365, ChronoUnit.DAYS);

        X509Certificate cert1 = Certy.newCredential().subject("CN=joe").notBefore(wantNotBefore).getX509Certificate();
        assertNotNull(cert1);
        assertEquals(wantNotBefore, cert1.getNotBefore());
        assertEquals(Date.from(wantNotBefore.toInstant().plus(defaultDuration)), cert1.getNotAfter());

        X509Certificate cert2 = Certy.newCredential().subject("CN=joe").notBefore(wantNotBefore).notAfter(wantNotAfter)
                .getX509Certificate();
        assertNotNull(cert2);
        assertEquals(wantNotBefore, cert2.getNotBefore());
        assertEquals(wantNotAfter, cert2.getNotAfter());
    }

    @Test
    void testInvalidSubject() throws Exception {
        assertThrows(IllegalArgumentException.class, () -> Certy.newCredential().subject("Foo=Bar").getX509Certificate());
    }

    @Test
    void testEmptySubject() throws Exception {
        // Empty subject is not allowed.
        assertThrows(IllegalArgumentException.class, () -> Certy.newCredential().getX509Certificate());
    }

    @Test
    void testInvalidSubjectAltName() throws Exception {
        assertThrows(IllegalArgumentException.class, () -> Certy.newCredential().subject("CN=joe")
                .subjectAltNames(Arrays.asList("EMAIL:user@example.com")).getX509Certificate());

        assertThrows(IllegalArgumentException.class, () -> Certy.newCredential().subject("CN=joe")
                .subjectAltNames(Arrays.asList("URL:")).getX509Certificate());

        assertThrows(IllegalArgumentException.class, () -> Certy.newCredential().subject("CN=joe")
                .subjectAltNames(Arrays.asList("IP:999.999.999.999")).getX509Certificate());
    }

    @Test
    void testInvalidKeySize() throws Exception {
        assertThrows(IllegalArgumentException.class, () -> Certy.newCredential().subject("CN=joe")
                .keyType(KeyType.EC).keySize(1).getX509Certificate());
        assertThrows(IllegalArgumentException.class, () -> Certy.newCredential().subject("CN=joe")
                .keyType(KeyType.RSA).keySize(1).getX509Certificate());
    }

    @Test
    void testGettingPemsAsStrings() throws Exception {
        Certy ca = Certy.newCredential().subject("CN=ca");
        Certy server = Certy.newCredential().subject("CN=server").issuer(ca).subjectAltName("DNS:localhost");
        Certy client = Certy.newCredential().subject("CN=client").keyType(KeyType.RSA).issuer(ca);

        expectPemCertificate(new BufferedReader(new StringReader(ca.getCertificateAsPem())), "CN=ca");
        expectPemPrivateKey(new BufferedReader(new StringReader(ca.getPrivateKeyAsPem())), "EC");

        expectPemCertificate(new BufferedReader(new StringReader(server.getCertificateAsPem())), "CN=server");
        expectPemPrivateKey(new BufferedReader(new StringReader(server.getPrivateKeyAsPem())), "EC");

        expectPemCertificate(new BufferedReader(new StringReader(client.getCertificateAsPem())), "CN=client");
        expectPemPrivateKey(new BufferedReader(new StringReader(client.getPrivateKeyAsPem())), "RSA");
    }

    @Test
    void testWritingPemFiles(@TempDir Path tempDir) throws Exception {
        Path certPath = tempDir.resolve("joe.pem");
        Path keyPath = tempDir.resolve("joe-key.pem");

        Certy.newCredential().subject("CN=joe").writeCertificateAsPem(certPath).writePrivateKeyAsPem(keyPath);
        expectPemCertificate(Files.newBufferedReader(certPath), "CN=joe");
        expectPemPrivateKey(Files.newBufferedReader(keyPath), "EC");
    }

    void expectPemCertificate(BufferedReader reader, String expectedDn) throws CertificateException, IOException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        PEMParser parser = new PEMParser(reader);
        PemObject obj = parser.readPemObject();
        parser.close();
        assertEquals("CERTIFICATE", obj.getType());
        X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(obj.getContent()));
        assertEquals(expectedDn, cert.getSubjectDN().toString());
    }

    void expectPemPrivateKey(BufferedReader reader, String expectedKeyType)
            throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
        PEMParser parser = new PEMParser(reader);
        PemObject obj = parser.readPemObject();
        parser.close();
        assertEquals("PRIVATE KEY", obj.getType());
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(obj.getContent());
        KeyFactory.getInstance(expectedKeyType).generatePrivate(spec);
    }

    @Test
    void createPkcs12KeyStore() throws Exception {
        Certy ca = Certy.newCredential().subject("CN=ca");
        Certy client = Certy.newCredential().subject("CN=client").issuer(ca);

        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry("client", client.getPrivateKey(), null, client.getCertificates());
        ks.setCertificateEntry("ca", ca.getCertificate());
        assertEquals(2, ks.size());
        assertEquals(ca.getCertificate(), ks.getCertificate("ca"));
        assertEquals(client.getCertificate(), ks.getCertificate("client"));
    }
}
