package no.idporten.eseal;


import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

@DisplayName("When using default properties for certificate authorities")
public class CertificateAuthoritiesPropertiesTest {

    @DisplayName("then test and production properties differ")
    @Test
    void testTestAndProdDiffers() {
        assertNotEquals(CertificateAuthoritiesProperties.testProperties(), CertificateAuthoritiesProperties.prodProperties());
    }

    @DisplayName("then test properties can be referenced using environment")
    @Test
    void testGetTestPropertiesFromEnvironment() {
        assertEquals(CertificateAuthoritiesProperties.testProperties(), CertificateAuthoritiesProperties.defaultProperties(Environment.TEST));
    }

    @DisplayName("then production properties can be referenced using environment")
    @Test
    void testGetProductionPropertiesFromEnvironment() {
        assertEquals(CertificateAuthoritiesProperties.prodProperties(), CertificateAuthoritiesProperties.defaultProperties(Environment.PROD));
    }

}
