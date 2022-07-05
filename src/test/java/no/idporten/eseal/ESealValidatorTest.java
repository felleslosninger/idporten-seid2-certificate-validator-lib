package no.idporten.eseal;

import lombok.SneakyThrows;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.assertFalse;

@DisplayName("When validating certificates")
@ExtendWith(MockitoExtension.class)
public class ESealValidatorTest {

    private static TestData testData;

    @BeforeAll
    public static void setUp() {
        testData = new TestData();
    }

    @SneakyThrows
    protected ESealValidator createTestBusinessCertificateValidator(CertificateAuthoritiesProperties properties) {
        return new ESealValidatorBuilder(Environment.TEST).withProperties(properties).build();
        // TODO crl
    }

    @DisplayName("then a valid certificate is accepted")
    @Test
    void testValidateValidCertificate() throws Exception {
        ESealValidator validator = createTestBusinessCertificateValidator(testData.props());
        validator.isValid(testData.createCertificate());
    }

    @Test
    @DisplayName("then a self-signed certificate is rejected")
    public void testSelfSignedCertificateIsInvalid() throws Exception {
        ESealValidator validator = createTestBusinessCertificateValidator(testData.props());
        X509Certificate certificate = testData.selfSignedCertificate();
        assertFalse(validator.isValid(certificate));
    }

}

