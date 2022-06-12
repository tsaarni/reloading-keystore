package com.github.tsaarni.keystore;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.EllipticCurve;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class Certy {

    public enum KeyType {
        EC,
        RSA
    }

    public enum KeyUsage {
        DIGITAL_SIGNATURE(org.bouncycastle.asn1.x509.KeyUsage.digitalSignature),
        NON_REPUDIATION(org.bouncycastle.asn1.x509.KeyUsage.nonRepudiation),
        KEY_ENCIPHERMENT(org.bouncycastle.asn1.x509.KeyUsage.keyEncipherment),
        DATA_ENCIPHERMENT(org.bouncycastle.asn1.x509.KeyUsage.dataEncipherment),
        KEY_AGREEMENT(org.bouncycastle.asn1.x509.KeyUsage.keyAgreement),
        KEY_CERT_SIGN(org.bouncycastle.asn1.x509.KeyUsage.keyCertSign),
        CRL_SIGN(org.bouncycastle.asn1.x509.KeyUsage.cRLSign),
        ENCIPHER_ONLY(org.bouncycastle.asn1.x509.KeyUsage.encipherOnly),
        DECIPHER_ONLY(org.bouncycastle.asn1.x509.KeyUsage.decipherOnly);

        private int val;

        private KeyUsage(int val) {
            this.val = val;
        }

        public int getValue() {
            return val;
        }
    }

    public enum ExtKeyUsage {
        ANY(KeyPurposeId.anyExtendedKeyUsage),
        SERVER_AUTH(KeyPurposeId.id_kp_serverAuth),
        CLIENT_AUTH(KeyPurposeId.id_kp_clientAuth),
        CODE_SIGNING(KeyPurposeId.id_kp_codeSigning),
        EMAIL_PROTECTION(KeyPurposeId.id_kp_emailProtection),
        TIME_STAMPING(KeyPurposeId.id_kp_timeStamping),
        OCSP_SIGNING(KeyPurposeId.id_kp_OCSPSigning);

        private KeyPurposeId val;

        private ExtKeyUsage(KeyPurposeId val) {
            this.val = val;
        }

        public KeyPurposeId getValue() {
            return val;
        }
    }

    // Attributes set by user via Certy builder methods.
    private String subject;
    private List<String> subjectAltNames;
    private KeyType keyType;
    private int keySize;
    private Duration expires;
    private Date notBefore;
    private Date notAfter;
    private List<KeyUsage> keyUsages;
    private List<ExtKeyUsage> extKeyUsages;
    private Certy issuer;
    private Boolean isCa;

    // Generated attributes.
    private KeyPair keyPair;
    private Certificate certificate;

    private Certy() {
        subjectAltNames = new ArrayList<>();
        keyUsages = new ArrayList<>();
        extKeyUsages = new ArrayList<>();
    }

    // Defines the distinguished name for the certificate.
    // Example: CN=Joe.
    public Certy subject(String val) {
        new X500Name(val);
        this.subject = val;
        return this;
    }

    // Defines an optional list of values for x509 Subject Alternative Name extension.
    // Examples: DNS:www.example.com, IP:1.2.3.4, URI:https://www.example.com.
    public Certy subjectAltNames(List<String> val) {
        this.subjectAltNames = val;
        return this;
    }

    // Defines an optional value for x509 Subject Alternative Name extension.
    // This version of the method accepts only single name.
    // Examples: DNS:www.example.com, IP:1.2.3.4, URI:https://www.example.com.
    public Certy subjectAltNames(String val) {
        this.subjectAltNames = Arrays.asList(val);
        return this;
    }

    // Defines the certificate key algorithm.
    // Values: {@link #KeyType.EC}, {@link #KeyType.RSA}
    // Default: EC
    public Certy keyType(KeyType val) {
        this.keyType = val;
        return this;
    }

    // Defines the key length in bits.
    // Default value is 256 (EC) or 2048 (RSA) if keySize is undefined (when method has not been called).
    // Examples: For keyType EC: 256, 384, 521. For keyType RSA: 1024, 2048, 4096.
    public Certy keySize(int val) {
        this.keySize = val;
        return this;
    }

    // Automatically defines certificate's NotAfter field by adding duration defined in Expires to the current time.
    // Default value is 1 year if expires is undefined (when method has not been called).
    // NotAfter takes precedence over expires.
    public Certy expires(Duration val) {
        this.expires = val;
        return this;
    }

    // Defines certificate not to be valid before this time.
    // Default value is current time if notBefore is undefined (when method has not been called).
    public Certy notBefore(Date val) {
        this.notBefore = val;
        return this;
    }

    // Defines certificate not to be valid after this time.
    // Default value is current time + expires if notAfter is undefined (when method has not been called).
    public Certy notAfter(Date val) {
        this.notAfter = val;
        return this;
    }

    // Defines a sequence of values for x509 key usage extension.
    // If KeyUsage is undefined (when method has not been called), CertSign and CRLSign are set for CA certificates,
    // KeyEncipherment and DigitalSignature are set for end-entity certificates.
    public Certy keyUsages(List<KeyUsage> val) {
        this.keyUsages = val;
        return this;
    }

    // Defines a sequence of x509 extended key usages.
    // Not set by default.
    public Certy extKeyUsages(List<ExtKeyUsage> val) {
        this.extKeyUsages = val;
        return this;
    }

    // Defines the issuer Certificate.
    // Self-signed certificate is generated if Issuer is undefined (when method has not been called).
    public Certy issuer(Certy val) {
        this.issuer = val;
        return this;
    }

    // Defines if certificate is / is not CA.
    // If IsCA is undefined (when method has not been called), true is set by default for self-signed certificates
    // (when issuer is not defined).
    public Certy isCa(Boolean val) {
        this.isCa = val;
        return this;
    }

    // Regenerate certificate and private key with currently defined attributes.
    public Certy generate()
            throws OperatorCreationException, CertificateException, NoSuchAlgorithmException, CertIOException {
        // Traverse the certificate hierarchy recursively to ensure issuing CAs have
        // been generated as well.
        if (issuer != null) {
            issuer.ensureGenerated();
        }

        setDefaults();

        keyPair = newKeyPair(keyType, keySize);

        // Calculate the validity dates according to given values and current time.
        Date effectiveNotBefore, effectiveNotAfter;
        if (notBefore != null) {
            effectiveNotBefore = notBefore;
        } else {
            effectiveNotBefore = new Date();
        }

        if (notAfter != null) {
            effectiveNotAfter = notBefore;
        } else {
            effectiveNotAfter = Date.from(effectiveNotBefore.toInstant().plus(expires));
        }

        if (subject == null) {
            throw new IllegalArgumentException("subject name must be set");
        }

        X500Name effectiveSubject = new X500Name(subject);

        X500Name effectiveIssuer;
        ContentSigner signer;
        if (issuer == null) {
            effectiveIssuer = effectiveSubject;
            signer = new JcaContentSignerBuilder(signatureAlgorithm(keyPair.getPublic()))
                    .build(keyPair.getPrivate());
        } else {
            effectiveIssuer = new X500Name(issuer.subject);
            signer = new JcaContentSignerBuilder(signatureAlgorithm(issuer.keyPair.getPublic()))
                    .build(issuer.keyPair.getPrivate());
        }

        Instant now = Instant.now();
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                effectiveIssuer,
                BigInteger.valueOf(now.toEpochMilli()),
                effectiveNotBefore,
                effectiveNotAfter,
                effectiveSubject,
                keyPair.getPublic());

        JcaX509ExtensionUtils utils = new JcaX509ExtensionUtils();
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(isCa))
                .addExtension(Extension.subjectKeyIdentifier, false,
                        utils.createAuthorityKeyIdentifier(keyPair.getPublic()))
                .addExtension(Extension.keyUsage, true, new org.bouncycastle.asn1.x509.KeyUsage(
                        keyUsages.stream().collect(Collectors.summingInt(KeyUsage::getValue))));

        if (!subjectAltNames.isEmpty()) {
            builder.addExtension(Extension.subjectAlternativeName, subject.isEmpty(),
                    asGeneralNames(subjectAltNames));
        }

        if (!extKeyUsages.isEmpty()) {
            builder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(
                    extKeyUsages.stream().map(v -> v.getValue()).toArray(KeyPurposeId[]::new)));
        }

        certificate = new JcaX509CertificateConverter().setProvider(new BouncyCastleProvider())
                .getCertificate(builder.build(signer));

        return this;
    }

    // Return certificate as PEM.
    public String getCertificateAsPem() throws OperatorCreationException, CertificateException, NoSuchAlgorithmException, IOException {
        ensureGenerated();

        StringWriter writer = new StringWriter();
        JcaPEMWriter pemWriter = new JcaPEMWriter(writer);
        pemWriter.writeObject(certificate);
        pemWriter.flush();
        pemWriter.close();

        return writer.toString();
    }

    // Return private key as PEM.
    public String getPrivateKeyAsPem()
            throws IOException, OperatorCreationException, CertificateException, NoSuchAlgorithmException {
        ensureGenerated();

        StringWriter writer = new StringWriter();
        JcaPEMWriter pemWriter = new JcaPEMWriter(writer);
        pemWriter.writeObject(new JcaPKCS8Generator(keyPair.getPrivate(), null));
        pemWriter.flush();
        pemWriter.close();

        return writer.toString();
    }

    // Write certificate as PEM to a named file.
    public Certy writeCertificateAsPem(Path out)
            throws IOException, OperatorCreationException, CertificateException, NoSuchAlgorithmException {
        ensureGenerated();

        try (BufferedWriter writer = Files.newBufferedWriter(out, StandardCharsets.UTF_8)) {
            JcaPEMWriter pemWriter = new JcaPEMWriter(writer);
            pemWriter.writeObject(certificate);
            pemWriter.flush();
            pemWriter.close();
        } catch (IOException e) {
            throw e;
        }

        return this;
    }

    // Write private key as PEM to a named file.
    public Certy writePrivateKeyAsPem(Path out) throws IOException, OperatorCreationException, CertificateException, NoSuchAlgorithmException {
        ensureGenerated();

        try (BufferedWriter writer = Files.newBufferedWriter(out, StandardCharsets.UTF_8)) {
            JcaPEMWriter pemWriter = new JcaPEMWriter(writer);
            pemWriter.writeObject(new JcaPKCS8Generator(keyPair.getPrivate(), null));
            pemWriter.flush();
            pemWriter.close();
        } catch (IOException e) {
            throw e;
        }

        return this;
    }

    // Return private key.
    public PrivateKey getPrivateKey() throws OperatorCreationException, CertificateException, NoSuchAlgorithmException, CertIOException {
        ensureGenerated();

        return keyPair.getPrivate();
    }

    // Return certificate.
    public Certificate getCertificate() throws OperatorCreationException, CertificateException, NoSuchAlgorithmException, CertIOException {
        ensureGenerated();

        return certificate;
    }

    // Convenience method for returning certificate as an array of certificates (returns always just one certificate).
    public Certificate[] getCertificates()
            throws OperatorCreationException, CertificateException, NoSuchAlgorithmException, CertIOException {
        ensureGenerated();

        return new Certificate[] { certificate };
    }

    // Convenience method for returning X509Certificate.
    public X509Certificate getX509Certificate() throws OperatorCreationException, CertificateException, NoSuchAlgorithmException, CertIOException {
        ensureGenerated();

        return (X509Certificate) certificate;
    }

    private void ensureGenerated()
            throws OperatorCreationException, CertificateException, NoSuchAlgorithmException, CertIOException {
        if (certificate == null || keyPair == null) {
            generate();
        }
    }

    private void setDefaults() {
        if (keyType == null) {
            keyType = KeyType.EC;
        }

        if (keySize == 0) {
            if (keyType == KeyType.EC) {
                keySize = 256;
            } else if (keyType == KeyType.RSA) {
                keySize = 2048;
            }
        }

        if (expires == null && notAfter == null) {
            expires = Duration.of(365, ChronoUnit.DAYS);
        }

        if (isCa == null) {
            boolean noExplicitIssuer = (issuer == null);
            isCa = noExplicitIssuer;
        }

        if (keyUsages.isEmpty()) {
            if (isCa) {
                keyUsages = Arrays.asList(KeyUsage.KEY_CERT_SIGN, KeyUsage.CRL_SIGN);
            } else {
                keyUsages = Arrays.asList(KeyUsage.KEY_ENCIPHERMENT, KeyUsage.DIGITAL_SIGNATURE);
            }
        }
    }

    // Instantiate new credential.
    public static Certy newCredential() {
        return new Certy();
    }

    private static KeyPair newKeyPair(KeyType keyType, int keySize) throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen;
        keyGen = KeyPairGenerator.getInstance(keyType.name());
        SecureRandom prng = new SecureRandom();
        keyGen.initialize(keySize, prng);
        return keyGen.genKeyPair();
    }

    private static String signatureAlgorithm(PublicKey pub) {
        switch (pub.getAlgorithm()) {
            case "EC":
                EllipticCurve curve = ((ECPublicKey) pub).getParams().getCurve();
                switch (curve.getField().getFieldSize()) {
                    case 224:
                    case 256:
                        return "SHA256withECDSA";
                    case 384:
                        return "SHA384withECDSA";
                    case 521:
                        return "SHA512withECDSA";
                    default:
                        throw new IllegalArgumentException("unknown elliptic curve: " + curve);
                }
            case "RSA":
                return "SHA256WithRSAEncryption";
            default:
                throw new UnsupportedOperationException("unsupported private key algorithm: " + pub.getAlgorithm());
        }
    }

    private static GeneralNames asGeneralNames(List<String> sans) {
        List<GeneralName> altNames = new ArrayList<>();
        for (String name : sans) {

            // Parse type and value.
            int separatorPos = name.indexOf(":");
            if (separatorPos == -1) {
                // Bail out when invalid syntax.
                throw new IllegalArgumentException("cannot parse " + name
                        + ": all subjectAltNames must be of format: DNS:www.example.com, IP:1.2.3.4, URI:https://www.example.com");
            }
            String type = name.substring(0, separatorPos);
            String value = name.substring(separatorPos + 1);

            // Convert to GeneralName.
            switch (type) {
                case "DNS":
                    altNames.add(new GeneralName(GeneralName.dNSName, value));
                    break;
                case "IP":
                    altNames.add(new GeneralName(GeneralName.iPAddress, value));
                    break;
                case "URI":
                    altNames.add(new GeneralName(GeneralName.uniformResourceIdentifier, value));
                    break;

                default:
                    break;
            }
        }

        if (altNames.isEmpty()) {
            throw new IllegalArgumentException(
                    "subjectAltNames must be of format: DNS:www.example.com, IP:1.2.3.4, URI:https://www.example.com");
        }

        return GeneralNames.getInstance(new DERSequence(altNames.toArray(new GeneralName[] {})));
    }

}
