package no.idporten.eseal;

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
public class ESealValidatorBuilderTest {

    @DisplayName("then an environment must be specified")
    @Test
    void testEnvironmentMustBeSpecified() throws Exception {
        NullPointerException e = assertThrows(NullPointerException.class, () -> new ESealValidatorBuilder(null));
        assertAll(
                () -> assertNotNull(e),
                () -> assertEquals("Specify environment", e.getMessage())
        );
    }

    @DisplayName("then the default is to use environment specific properties and in-memory CRL cache")
    @Test
    void testBuildWithDefaults() throws Exception {
        ESealValidatorBuilder builder = spy(new ESealValidatorBuilder(Environment.TEST));
        ESealValidator eSealValidator = builder.build();
        verify(builder).createValidator(eq(Environment.TEST), eq(CertificateAuthoritiesProperties.testProperties()), any(SimpleCrlCache.class));
        assertNotNull(eSealValidator);
    }

    @DisplayName("then defaults can be set programmatically")
    @Test
    void testProgrammaticallySetDefaults() throws Exception {
        ESealValidatorBuilder builder = spy(new ESealValidatorBuilder(Environment.TEST));
        ESealValidator eSealValidator = builder.withDefaults().build();
        verify(builder).createValidator(eq(Environment.TEST), eq(CertificateAuthoritiesProperties.testProperties()), any(SimpleCrlCache.class));
        assertNotNull(eSealValidator);
    }

    @DisplayName("then properties can be overridden")
    @Test
    void testOverrideProperties() throws Exception {
        ESealValidatorBuilder builder = spy(new ESealValidatorBuilder(Environment.TEST));
        // TODO prod
        ESealValidator eSealValidator = builder.withProperties(CertificateAuthoritiesProperties.testProperties()).build();
        verify(builder).createValidator(eq(Environment.TEST), eq(CertificateAuthoritiesProperties.testProperties()), any(CrlCache.class));
        assertNotNull(eSealValidator);
    }

    @DisplayName("then CRL cache strategy can be overridden to use disk")
    @Test
    void testOverrideCRLCache(@TempDir Path cacheDir) throws Exception {
        ESealValidatorBuilder builder = spy(new ESealValidatorBuilder(Environment.TEST));
        ESealValidator eSealValidator = builder.withCrlCacheOnDisk(cacheDir).build();
        verify(builder).createValidator(eq(Environment.TEST), eq(CertificateAuthoritiesProperties.testProperties()), any(DirectoryCrlCache.class));
        assertNotNull(eSealValidator);
    }

    @DisplayName("then default intermediate certificates for prod are valid")
    @Test
    void testValidProdIntermediateCertificates() throws Exception {
        ESealValidator eSealValidator = new ESealValidatorBuilder(Environment.PROD).build();
        CertificateAuthoritiesProperties prodProperties = CertificateAuthoritiesProperties.prodProperties();
        for (String cert : prodProperties.getIntermediateCertificates()) {
            assertDoesNotThrow(() -> eSealValidator.validate(X509CertificateUtils.readX509Certificate(cert)), "Invalid certificate " + cert);
        }
    }

    @DisplayName("then default intermediate certificates for test are valid")
    @Test
    void testValidTestIntermediateCertificates() throws Exception {
        ESealValidator eSealValidator = new ESealValidatorBuilder(Environment.TEST).build();
        CertificateAuthoritiesProperties testProperties = CertificateAuthoritiesProperties.testProperties();
        for (String cert : testProperties.getIntermediateCertificates()) {
            assertDoesNotThrow(() -> eSealValidator.validate(X509CertificateUtils.readX509Certificate(cert)), "Invalid certificate " + cert);
        }
    }

}
