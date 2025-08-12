package no.idporten.seid2;


import lombok.SneakyThrows;
import no.idporten.validator.certificate.Validator;
import no.idporten.validator.certificate.ValidatorBuilder;
import no.idporten.validator.certificate.rule.ChainRule;
import no.idporten.validator.certificate.rule.ExpirationRule;
import no.idporten.validator.certificate.rule.SigningRule;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;

import static no.idporten.seid2.SEID2CertificateValidatorFactory.getCertificateBucket;
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
    void testValidProdIntermediateCertificates() {
        CertificateAuthoritiesProperties prodProperties = CertificateAuthoritiesProperties.prodProperties();
        Validator validator = intermediateCertValidator(prodProperties);
        for (String cert : prodProperties.getIntermediateCertificates()) {
            assertDoesNotThrow(() -> validator.validate(X509CertificateUtils.readX509Certificate(cert)), "Invalid certificate " + cert);
        }
    }

    @DisplayName("then default intermediate certificates for TEST are valid")
    @Test
    void testValidTestIntermediateCertificates() {
        CertificateAuthoritiesProperties testProperties = CertificateAuthoritiesProperties.testProperties();
        Validator validator = intermediateCertValidator(testProperties);
        for (String cert : testProperties.getIntermediateCertificates()) {
            assertDoesNotThrow(() -> validator.validate(X509CertificateUtils.readX509Certificate(cert)), "Invalid certificate " + cert);
        }
    }

    @DisplayName("then default root certificates for PROD are self signed")
    @Test
    void testValidProdRootCertificates() throws Exception {
        CertificateAuthoritiesProperties prodProperties = CertificateAuthoritiesProperties.prodProperties();
        Validator validator = rootCertValidator();
        for (String cert : prodProperties.getRootCertificates()) {
            X509Certificate x509Certificate = X509CertificateUtils.readX509Certificate(cert);
            assertTrue(validator.isValid(x509Certificate));
        }
    }

    @DisplayName("then default root certificates for TEST are self signed")
    @Test
    void testValidTestRootCertificates() throws Exception {
        CertificateAuthoritiesProperties testProperties = CertificateAuthoritiesProperties.testProperties();
        Validator validator = rootCertValidator();
        for (String cert : testProperties.getRootCertificates()) {
            X509Certificate x509Certificate = X509CertificateUtils.readX509Certificate(cert);
            assertTrue(validator.isValid(x509Certificate));
        }
    }

    Validator rootCertValidator () {
        return ValidatorBuilder.newInstance()
                .addRule(new ExpirationRule())
                .addRule(new SigningRule(SigningRule.Kind.SELF_SIGNED_ONLY))
                .build();
    }

    @SneakyThrows
    Validator intermediateCertValidator (CertificateAuthoritiesProperties properties) {
        return ValidatorBuilder.newInstance()
                .addRule(new ExpirationRule())
                .addRule(new SigningRule(SigningRule.Kind.PUBLIC_SIGNED_ONLY))
                .addRule(new ChainRule(getCertificateBucket(properties.getRootCertificates()), getCertificateBucket(properties.getIntermediateCertificates())))
                .build();
    }

}
