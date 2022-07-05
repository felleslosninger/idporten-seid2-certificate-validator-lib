package no.idporten.eseal.config;

import lombok.SneakyThrows;
import no.digdir.certvalidator.rule.CRLRule;
import no.idporten.eseal.CertificateAuthoritiesProperties;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.StringReader;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public class CRLDownloads {

    @Test
    void testDownloadCRL() throws Exception {
        CertificateAuthoritiesProperties certificateAuthoritiesProperties = CertificateAuthoritiesProperties.testProperties();
        Set<String> crlUrls = certificateAuthoritiesProperties.getRootCertificates().stream()
                        .map(cert -> readCertificate(cert))
                                .map(cert -> getCrlDistributionPoints(cert))
                .flatMap(List::stream)
                        .collect(Collectors.toSet());



        CRLRule.getCrlDistributionPoints(readCertificate(certificateAuthoritiesProperties.getIntermediateCertificates().get(0)));


        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        certificateFactory.generateCRL(null);

        System.out.println(crlUrls);





    }

    @SneakyThrows
    private List<String> getCrlDistributionPoints(X509Certificate certificate) {
        return CRLRule.getCrlDistributionPoints(certificate);


    }


    @SneakyThrows
    private X509Certificate readCertificate(String cert) {
        if (!cert.startsWith("-----BEGIN CERTIFICATE-----")) {
            cert = "-----BEGIN CERTIFICATE-----\n" + cert;
        }
        if (!cert.endsWith("-----END CERTIFICATE-----")) {
            cert = cert + "\n-----END CERTIFICATE-----";
        }

        StringReader certPem = new StringReader(cert);
        PemReader pemReader = new PemReader(certPem);
        PemObject pemObject = pemReader.readPemObject();
        ByteArrayInputStream bIn = new ByteArrayInputStream(pemObject.getContent());
        CertificateFactory instance = CertificateFactory.getInstance("X.509");
        return (X509Certificate) instance.generateCertificate(bIn);
    }


}
