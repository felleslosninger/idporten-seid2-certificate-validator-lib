package no.idporten.seid2;

import lombok.SneakyThrows;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("When validating certificates")
@ExtendWith(MockitoExtension.class)
public class SEID2CertificateValidatorTest {

    private static TestData testData;

    @BeforeAll
    public static void setUp() {
        testData = new TestData();
    }

    @SneakyThrows
    protected SEID2CertificateValidator createTestBusinessCertificateValidator(CertificateAuthoritiesProperties properties) {
        return new SEID2CertificateValidatorBuilder(Environment.TEST).withProperties(properties).build();
    }

    @DisplayName("then a valid certificate is accepted")
    @Test
    void testValidateValidCertificate() throws Exception {
        SEID2CertificateValidator validator = createTestBusinessCertificateValidator(testData.props());
        validator.isValid(testData.createCertificate());
    }

    @Test
    @DisplayName("then a self-signed certificate is rejected")
    public void testSelfSignedCertificateIsInvalid() throws Exception {
        SEID2CertificateValidator validator = createTestBusinessCertificateValidator(testData.props());
        X509Certificate certificate = testData.selfSignedCertificate();
        assertFalse(validator.isValid(certificate));
    }

    @Test
    @DisplayName("then this test can be used in support cases to check certificate")
    @Disabled
    void testCommfidesFinanstilsynet() throws Exception {
        Environment environment = Environment.TEST;
        String certificate = "-----BEGIN CERTIFICATE-----\n" +
                "MIIGTTCCBTWgAwIBAgIIFt7itt/AO3AwDQYJKoZIhvcNAQELBQAwgfExPDA6BgNV\n" +
                "BAMTM0NvbW1maWRlcyBDUE4gRW50ZXJwcmlzZS1Ob3J3ZWdpYW4gU0hBMjU2IENB\n" +
                "IC0gVEVTVDFGMEQGA1UECxM9Q29tbWZpZGVzIFRydXN0IEVudmlyb25tZW50KEMp\n" +
                "IDIwMTQgQ29tbWZpZGVzIE5vcmdlIEFTIC0gVEVTVDExMC8GA1UECxMoQ1BOIEVu\n" +
                "dGVycHJpc2UtTm9yd2VnaWFuIFNIQTI1NiBDQS0gVEVTVDEpMCcGA1UEChMgQ29t\n" +
                "bWZpZGVzIE5vcmdlIEFTIC0gOTg4IDMxMiA0OTUxCzAJBgNVBAYTAk5PMB4XDTE5\n" +
                "MDkyMjIyMDAwMFoXDTIyMTAwMzEyNTM0NFowgZ4xFzAVBgNVBAMTDkZJTkFOU1RJ\n" +
                "TFNZTkVUMRIwEAYDVQQFEwk4NDA3NDc5NzIxGDAWBgNVBGETD05UUk5PLTg0MDc0\n" +
                "Nzk3MjEjMCEGA1UEChMaRklOQU5TVElMU1lORVQgLSA4NDA3NDc5NzIxIzAhBgNV\n" +
                "BAcTGlJldmllcnN0cmVkZXQgMywgMDE1MSBPU0xPMQswCQYDVQQGEwJOTzCCASAw\n" +
                "CwYJKoZIhvcNAQEBA4IBDwAwggEKAoIBAQCJDXdjWwSuAh0edoOIR2jjfhj1JYEs\n" +
                "sWQXELfIeT1ZtWTBESsaQD0JM7OMcb5o178axZtDje32auuKHlD9e18WHPwlKOlP\n" +
                "GVmra/p79RFBkc/UVpteGvpTPV8tVjsl7NpHbfSaVcIirvKjTVpS7D8a3wipy+jW\n" +
                "v5NvPyxKh6/ReLNhTa5MbxTB8dbdYV0Q7oCDiRPCjQ2bQdhLNXfEGzcIL3tEsBvj\n" +
                "qzcOj9onDy3fqxaE6oG2/13Liyq6af6CAj5ChC2eVESB9+m0eaiA4PPwjPZ7J/Fh\n" +
                "OvcZw00nEz7jRkq6twmsBpt6YHItdCHhntFTcM1CC++XK5xPnzUuLIcXAgMBAAGj\n" +
                "ggI6MIICNjAOBgNVHQ8BAf8EBAMCB4AwDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAW\n" +
                "gBR/stYtZW5Q/CtrDJOHJXKU9gBELzCB2AYIKwYBBQUHAQEEgcswgcgwSQYIKwYB\n" +
                "BQUHMAKGPWh0dHA6Ly9jcmwxLnRlc3QuY29tbWZpZGVzLmNvbS9Db21tZmlkZXNF\n" +
                "bnRlcnByaXNlLVNIQTI1Ni5jcnQwSQYIKwYBBQUHMAKGPWh0dHA6Ly9jcmwyLnRl\n" +
                "c3QuY29tbWZpZGVzLmNvbS9Db21tZmlkZXNFbnRlcnByaXNlLVNIQTI1Ni5jcnQw\n" +
                "MAYIKwYBBQUHMAGGJGh0dHA6Ly9vY3NwMS50ZXN0LmNvbW1maWRlcy5jb20vb2Nz\n" +
                "cDAhBgNVHREEGjAYgRZwb3N0QGZpbmFuc3RpbHN5bmV0Lm5vMBcGA1UdIAQQMA4w\n" +
                "DAYKYIRCAR2HEQEBADAnBgNVHSUEIDAeBggrBgEFBQcDAgYIKwYBBQUHAwQGCCsG\n" +
                "AQUFBwMBMIGVBgNVHR8EgY0wgYowQ6BBoD+GPWh0dHA6Ly9jcmwxLnRlc3QuY29t\n" +
                "bWZpZGVzLmNvbS9Db21tZmlkZXNFbnRlcnByaXNlLVNIQTI1Ni5jcmwwQ6BBoD+G\n" +
                "PWh0dHA6Ly9jcmwyLnRlc3QuY29tbWZpZGVzLmNvbS9Db21tZmlkZXNFbnRlcnBy\n" +
                "aXNlLVNIQTI1Ni5jcmwwHQYDVR0OBBYEFGGgWKcjVloubDGINcEaANBqP5MrMA0G\n" +
                "CSqGSIb3DQEBCwUAA4IBAQBpWfjrejIZvZnPxzUA8Nf4s5erzEWwrNcYKtq7RAQM\n" +
                "tgdOBcEd/HQFZ51jQWNS9D90O0tChL7qvARyahAt31Gv0Ow4DPMY/wRvJ8gVKFpk\n" +
                "MKTHo71HnNhSArhEkOHe8SCWuOEJgl0Oci3fW5iwEDC2wtH5d7H79MSh3Xs4YCBj\n" +
                "EkdRW6VpFey4VdCFtKn4a9Vm4loarnskeil/yi+jB8J2rCpGjjQu+X9bas2CQQ1I\n" +
                "4E3FLkKa6298Kw323FJrBxzGfltd3XHvWBBzW66yWGa81FO/QzTTufMwPHmH9PrT\n" +
                "bsIQfuUN+P18yWnn+TygtDcUu8eoQMQB62J5eIUydSRx\n" +
                "-----END CERTIFICATE-----";
        SEID2CertificateValidator validator = createTestBusinessCertificateValidator(CertificateAuthoritiesProperties.defaultProperties(environment));
        assertTrue(validator.isValid(X509CertificateUtils.readX509Certificate(certificate)));
    }

}

