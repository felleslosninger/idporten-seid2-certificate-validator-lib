package no.idporten.seid2;

import no.digdir.certvalidator.api.CrlCache;
import no.digdir.certvalidator.util.DirectoryCrlCache;
import no.digdir.certvalidator.util.SimpleCrlCache;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@DisplayName("When building validators")
public class SEID2CertificateValidatorBuilderTest {

    @DisplayName("then an environment must be specified")
    @Test
    void testEnvironmentMustBeSpecified() throws Exception {
        NullPointerException e = assertThrows(NullPointerException.class, () -> new SEID2CertificateValidatorBuilder(null));
        assertAll(
                () -> assertNotNull(e),
                () -> assertEquals("Specify environment", e.getMessage())
        );
    }

    @DisplayName("then the default is to use environment specific properties and in-memory CRL cache")
    @Test
    void testBuildWithDefaults() throws Exception {
        SEID2CertificateValidatorBuilder builder = spy(new SEID2CertificateValidatorBuilder(Environment.TEST));
        SEID2CertificateValidator SEID2CertificateValidator = builder.build();
        verify(builder).createValidator(eq(Environment.TEST), eq(CertificateAuthoritiesProperties.testProperties()), any(SimpleCrlCache.class));
        assertNotNull(SEID2CertificateValidator);
    }

    @DisplayName("then defaults can be set programmatically")
    @Test
    void testProgrammaticallySetDefaults() throws Exception {
        SEID2CertificateValidatorBuilder builder = spy(new SEID2CertificateValidatorBuilder(Environment.TEST));
        SEID2CertificateValidator SEID2CertificateValidator = builder.withDefaults().build();
        verify(builder).createValidator(eq(Environment.TEST), eq(CertificateAuthoritiesProperties.testProperties()), any(SimpleCrlCache.class));
        assertNotNull(SEID2CertificateValidator);
    }

    @DisplayName("then properties can be overridden")
    @Test
    void testOverrideProperties() throws Exception {
        SEID2CertificateValidatorBuilder builder = spy(new SEID2CertificateValidatorBuilder(Environment.PROD));
        SEID2CertificateValidator SEID2CertificateValidator = builder.withProperties(CertificateAuthoritiesProperties.testProperties()).build();
        verify(builder).createValidator(eq(Environment.PROD), eq(CertificateAuthoritiesProperties.testProperties()), any(CrlCache.class));
        assertNotNull(SEID2CertificateValidator);
    }

    @DisplayName("then CRL cache strategy can be overridden to use disk")
    @Test
    void testOverrideCRLCache(@TempDir Path cacheDir) throws Exception {
        SEID2CertificateValidatorBuilder builder = spy(new SEID2CertificateValidatorBuilder(Environment.TEST));
        SEID2CertificateValidator SEID2CertificateValidator = builder.withCrlCacheOnDisk(cacheDir).build();
        verify(builder).createValidator(eq(Environment.TEST), eq(CertificateAuthoritiesProperties.testProperties()), any(DirectoryCrlCache.class));
        assertNotNull(SEID2CertificateValidator);
    }

    @DisplayName("then default intermediate certificates for prod are valid")
    @Test
    void testValidProdIntermediateCertificates() throws Exception {
        SEID2CertificateValidator SEID2CertificateValidator = new SEID2CertificateValidatorBuilder(Environment.PROD).build();
        CertificateAuthoritiesProperties prodProperties = CertificateAuthoritiesProperties.prodProperties();
        for (String cert : prodProperties.getIntermediateCertificates()) {
            assertDoesNotThrow(() -> SEID2CertificateValidator.validate(X509CertificateUtils.readX509Certificate(cert)), "Invalid certificate " + cert);
        }
    }

    @DisplayName("then default intermediate certificates for test are valid")
    @Test
    void testValidTestIntermediateCertificates() throws Exception {
        SEID2CertificateValidator SEID2CertificateValidator = new SEID2CertificateValidatorBuilder(Environment.TEST).build();
        CertificateAuthoritiesProperties testProperties = CertificateAuthoritiesProperties.testProperties();
        for (String cert : testProperties.getIntermediateCertificates()) {
            assertDoesNotThrow(() -> SEID2CertificateValidator.validate(X509CertificateUtils.readX509Certificate(cert)), "Invalid certificate " + cert);
        }
    }

}
