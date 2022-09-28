package no.idporten.seid2;

import lombok.SneakyThrows;
import no.digdir.eid.certgenerator.CustomCertBuilder;
import no.digdir.eid.certgenerator.TestVirksomhetGenerator;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.cert.*;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.Random;
import java.util.Set;

import static no.idporten.seid2.X509CertificateUtils.pemEncodedCert;

public class TestData {

    private TestVirksomhetGenerator generator;
    private KeyStore.PrivateKeyEntry intermediate;

    @SneakyThrows
    public TestData() {
        generator = new TestVirksomhetGenerator();
        intermediate = generator.generateIntermediate(generator.generateRot());
    }

    public X509Certificate createCertificate() throws Exception {
        return createCertificate(distributionPointUrl());
    }

    public X509Certificate createCertificate(String... distributionPointUrls) throws Exception {
        return (X509Certificate) generator.generateVirksomhet(
                "123456789",
                intermediate,
                new BigInteger(String.valueOf(new Random().nextLong())),
                distributionPointUrls
        ).getCertificate();
    }

    public String distributionPointUrl() {
        return "http://localhost:123/crl";
    }

    private X509CRL crl(BigInteger... serialNumbersOfRevokedCertificates) throws OperatorCreationException, CertificateException, CRLException, IOException {
        return crl(LocalDateTime.now().plusDays(1), serialNumbersOfRevokedCertificates);
    }

    private X509CRL crl(LocalDateTime nextUpdate, BigInteger... serialNumbersOfRevokedCertificates) throws IOException, OperatorCreationException, CertificateException, CRLException {
        X509v2CRLBuilder builder = crlBuilder();
        for (BigInteger serialNumber : serialNumbersOfRevokedCertificates)
            builder.addCRLEntry(serialNumber, new Date(), 1);
        if (nextUpdate != null)
            builder.setNextUpdate(Date.from(nextUpdate.atZone(ZoneId.systemDefault()).toInstant()));
        ContentSigner signer = new JcaContentSignerBuilder("SHA1WithRSAEncryption").setProvider("BC").build(intermediate.getPrivateKey());
        return (X509CRL) CertificateFactory.getInstance("X.509").generateCRL(new ByteArrayInputStream(
                builder.build(signer).getEncoded()
        ));
    }

    private X509v2CRLBuilder crlBuilder() {
        return new X509v2CRLBuilder(
                new X500Name(
                        RFC4519Style.INSTANCE,
                        ((X509Certificate) intermediate.getCertificate()).getSubjectX500Principal().getName()
                ),
                new Date()
        );
    }

    public CertificateAuthoritiesProperties props() throws Exception {
        CertificateAuthoritiesProperties props = new CertificateAuthoritiesProperties();
        props.setPolicies(Set.of("2.16.578.1.1.1.1.100"));
        props.setCriticalExtensionsRecognized(Set.of("2.5.29.15", "2.5.29.19"));
        props.setCriticalExtensionsRequired(Set.of("2.5.29.15"));
        props.setIntermediateCertificates(Set.of(pemEncodedCert(intermediate.getCertificate())));
        props.setRootCertificates(Set.of(pemEncodedCert(intermediate.getCertificateChain()[0])));
        return props;
    }


    public X509Certificate selfSignedCertificate() throws Exception {
        CustomCertBuilder custom = (certGen, keyPair) -> {
            certGen.addExtension(org.bouncycastle.asn1.x509.Extension.subjectKeyIdentifier, false, (new JcaX509ExtensionUtils()).createSubjectKeyIdentifier(keyPair.getPublic()));
            certGen.addExtension(org.bouncycastle.asn1.x509.Extension.basicConstraints, false, new BasicConstraints(false));
            certGen.addExtension(org.bouncycastle.asn1.x509.Extension.certificatePolicies, false, new CertificatePolicies(new PolicyInformation(new ASN1ObjectIdentifier("2.16.578.1.1.1.1.100"))));
            certGen.addExtension(org.bouncycastle.asn1.x509.Extension.keyUsage, true, new KeyUsage(176));
            CRLDistPoint crl = TestVirksomhetGenerator.createDistributionPointExtention((X509Certificate) intermediate.getCertificate());
            certGen.addExtension(Extension.cRLDistributionPoints, false, crl);
        };
        return (X509Certificate) generator.generateSelfSignedGenerisk(
                        "CN=DIFI test virksomhetssertifiat, SERIALNUMBER=987464291",
                        custom,
                        Date.from(LocalDateTime.now().minusYears(1).toInstant(ZoneOffset.UTC)),
                        Date.from(LocalDateTime.now().plusYears(2).toInstant(ZoneOffset.UTC)))
                .getCertificate();
    }

}
