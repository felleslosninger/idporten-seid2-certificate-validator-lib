package no.idporten.seid2;


import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

@DisplayName("When using default properties for certificate authorities")
public class CertificateAuthoritiesPropertiesTest {

    @DisplayName("then TEST and PROD properties differ")
    @Test
    void testTestAndProdDiffers() {
        assertNotEquals(CertificateAuthoritiesProperties.testProperties(), CertificateAuthoritiesProperties.prodProperties());
    }

    @DisplayName("then TEST properties can be referenced using environment")
    @Test
    void testGetTestPropertiesFromEnvironment() {
        assertEquals(CertificateAuthoritiesProperties.testProperties(), CertificateAuthoritiesProperties.defaultProperties(Environment.TEST));
    }

    @DisplayName("then PROD properties can be referenced using environment")
    @Test
    void testGetProductionPropertiesFromEnvironment() {
        assertEquals(CertificateAuthoritiesProperties.prodProperties(), CertificateAuthoritiesProperties.defaultProperties(Environment.PROD));
    }

    @DisplayName("then default intermediate certificates for PROD are valid")
    @Test
    void testValidProdIntermediateCertificates() throws Exception {
        SEID2CertificateValidator SEID2CertificateValidator = new SEID2CertificateValidatorBuilder(Environment.PROD).build();
        CertificateAuthoritiesProperties prodProperties = CertificateAuthoritiesProperties.prodProperties();
        for (String cert : prodProperties.getIntermediateCertificates()) {
            assertDoesNotThrow(() -> SEID2CertificateValidator.validate(X509CertificateUtils.readX509Certificate(cert)), "Invalid certificate " + cert);
        }
    }

    @DisplayName("then default intermediate certificates for TEST are valid")
    @Test
    void testValidTestIntermediateCertificates() throws Exception {
        SEID2CertificateValidator SEID2CertificateValidator = new SEID2CertificateValidatorBuilder(Environment.TEST).build();
        CertificateAuthoritiesProperties testProperties = CertificateAuthoritiesProperties.testProperties();
        for (String cert : testProperties.getIntermediateCertificates()) {
            assertDoesNotThrow(() -> SEID2CertificateValidator.validate(X509CertificateUtils.readX509Certificate(cert)), "Invalid certificate " + cert);
        }
    }

    @DisplayName("then default root certificates for PROD are self signed")
    @Test
    void testValidProdRootCertificates() throws Exception {
        CertificateAuthoritiesProperties prodProperties = CertificateAuthoritiesProperties.prodProperties();
        for (String cert : prodProperties.getRootCertificates()) {
            X509Certificate x509Certificate = X509CertificateUtils.readX509Certificate(cert);
            assertEquals(x509Certificate.getSubjectX500Principal(), x509Certificate.getIssuerX500Principal());
        }
    }


    @DisplayName("then default root certificates for TEST are self signed")
    @Test
    void testValidTestRootCertificates() throws Exception {
        CertificateAuthoritiesProperties testProperties = CertificateAuthoritiesProperties.testProperties();
        for (String cert : testProperties.getRootCertificates()) {
            X509Certificate x509Certificate = X509CertificateUtils.readX509Certificate(cert);
            assertEquals(x509Certificate.getSubjectX500Principal(), x509Certificate.getIssuerX500Principal());
        }
    }

}
