package no.idporten.seid2;

import lombok.SneakyThrows;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.*;

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
        X509Certificate certificate = testData.createCertificate();
        assertTrue(validator.isValid(certificate));
        assertTrue(validator.isValid(X509CertificateUtils.pemEncodedCert(certificate)));
    }

    @Test
    @DisplayName("then a self-signed certificate is rejected")
    public void testSelfSignedCertificateIsInvalid() throws Exception {
        SEID2CertificateValidator validator = createTestBusinessCertificateValidator(testData.props());
        X509Certificate certificate = testData.selfSignedCertificate();
        assertFalse(validator.isValid(certificate));
        assertFalse(validator.isValid(X509CertificateUtils.pemEncodedCert(certificate)));
    }

    @Test
    @DisplayName("then Digdirs new Commfides certificate is valid")
    void testCommfidesDigdir() throws Exception {
        Environment environment = Environment.TEST;
        String certificate = "-----BEGIN CERTIFICATE-----\n" +
                "MIIIPTCCBiWgAwIBAgIUUYB1wif9ZVgHEXnq1bhEjaMtTbUwDQYJKoZIhvcNAQEN\n" +
                "BQAwcTELMAkGA1UEBhMCTk8xGzAZBgNVBAoMEkNvbW1maWRlcyBOb3JnZSBBUzEY\n" +
                "MBYGA1UEYQwPTlRSTk8tOTg4MzEyNDk1MSswKQYDVQQDDCJDb21tZmlkZXMgTGVn\n" +
                "YWwgUGVyc29uIC0gRzMgLSBURVNUMB4XDTI1MTExNDA4NTAyOVoXDTI4MTEyODA4\n" +
                "NTAyOFowgdsxCzAJBgNVBAYTAk5PMSEwHwYDVQQHDBhMw7hyZW5mYXJldCAxQyww\n" +
                "NTg1IE9TTE8xJDAiBgNVBAoTG0RpZ2l0YWxpc2VyaW5nc2RpcmVrdG9yYXRldDEY\n" +
                "MBYGA1UEYRMPTlRSTk8tOTkxODI1ODI3MS8wLQYDVQQLEyZUZXN0IGZvciB0aWxy\n" +
                "ZXR0ZWxlZ2dpbmcgYXYgU0VJRC52LjIuMDESMBAGA1UEBRMJOTkxODI1ODI3MSQw\n" +
                "IgYDVQQDExtEaWdpdGFsaXNlcmluZ3NkaXJla3RvcmF0ZXQwggGiMA0GCSqGSIb3\n" +
                "DQEBAQUAA4IBjwAwggGKAoIBgQCv52JyqsBR3chHZXTHhZ462vv/kybQD1f60Iic\n" +
                "PxW1ynWiBeTQkKY4JyBjg64kL41B10WipoGen1k+QYSnZzeyD64/8hNPQXxU9PAx\n" +
                "CGDw3aL2SixeZl6kLMRkipkKIwZ0EcV+n7Af9T8aH6DseDFQZU0Q6X5Hc87l53dt\n" +
                "z8v7WShMCSpCVjxAHhPKw0u6SAdTSs9CKwWeTVigUaqfdD0O38FLSLCF9xgMXWRc\n" +
                "Z8NGn9Zcp0OABWNx6x5U4K3gEwF65lWlNqATyQ9Ty8DQOR+qxe5yI8jcvWBTlgmB\n" +
                "owwvFgvfT184mlHqfEJH8LFMUMHZYrgNRVHXf4+VR/MedHGYLIaYWxYjUZbdCNtH\n" +
                "zjpZgvrsbDlKeHLaN2PMJgPQx/JBkXCM89GBkmEXi9jmeqFLs00y3DHngBMYukV7\n" +
                "bpkp/AcLXdFPCbuWleLX/2MPqdxn+748NF5v0iWuPGoAVYeCHSyP50tgIalRFIpq\n" +
                "u3U7XyGpMAZniiPxmR2nf+jeS6kCAwEAAaOCAuAwggLcMAwGA1UdEwEB/wQCMAAw\n" +
                "HwYDVR0jBBgwFoAUqz0xNZCg928p6qzoin53bJOYw1wwgYsGCCsGAQUFBwEBBH8w\n" +
                "fTBPBggrBgEFBQcwAoZDaHR0cDovL2NydC50ZXN0LmNvbW1maWRlcy5jb20vRzMv\n" +
                "Q29tbWZpZGVzTGVnYWxQZXJzb25DQS1HMy1URVNULmNydDAqBggrBgEFBQcwAYYe\n" +
                "aHR0cDovL29jc3AudGVzdC5jb21tZmlkZXMuY29tMCAGA1UdEQQZMBeBFXNlcnZp\n" +
                "Y2VkZXNrQGRpZ2Rpci5ubzBQBgNVHSAESTBHMAkGBwQAi+xAAQEwOgYLYIRCAR2H\n" +
                "EYFSAQAwKzApBggrBgEFBQcCARYdaHR0cHM6Ly9wZHMuY29tbWZpZGVzLmNvbS9H\n" +
                "My8wMwYDVR0lBCwwKgYIKwYBBQUHAwIGCCsGAQUFBwMEBgorBgEEAYI3FAICBggr\n" +
                "BgEFBQcDATCB7gYIKwYBBQUHAQMEgeEwgd4wFQYIKwYBBQUHCwIwCQYHBACL7EkB\n" +
                "AjAIBgYEAI5GAQEwFQYGBACORgECMAsTA05PSwIBAQIBBDATBgYEAI5GAQYwCQYH\n" +
                "BACORgEGAjCBjgYGBACORgEFMIGDMIGAFnpodHRwczovL3Bkcy5jb21tZmlkZXMu\n" +
                "Y29tL0czL0NvbW1maWRlcy1QRFMtZm9yLUNlcnRpZmljYXRlcy1hbmQtRVUtUXVh\n" +
                "bGlmaWVkLUNlcnRpZmljYXRlcy1MZWdhbC1QZXJzb24tQ2VudHJhbC1HM192MS0w\n" +
                "LnBkZhMCZW4wVAYDVR0fBE0wSzBJoEegRYZDaHR0cDovL2NybC50ZXN0LmNvbW1m\n" +
                "aWRlcy5jb20vRzMvQ29tbWZpZGVzTGVnYWxQZXJzb25DQS1HMy1URVNULmNybDAd\n" +
                "BgNVHQ4EFgQUp/LsRsrfprdDv4F21fEcoNxx8yEwDgYDVR0PAQH/BAQDAgeAMA0G\n" +
                "CSqGSIb3DQEBDQUAA4ICAQCONSk3mg3zFXF8comTJ4+aXtvSMJR2HF+pTmgFtKEz\n" +
                "qgTFzZTzHwKvHdSBLZlTBxJACOqt8f4zj/TpBqWu3qArWALsstF6kB320KWxNbDD\n" +
                "Wi0aWBM/PHRJKrycWG0AiQJYKhX/QD3C+BxzcXhNb/0VAg2Qff/229rsqYnmYTWK\n" +
                "1h5v+2/8nk4osREyiPhMjxdPjNKn39fSBM3iFK7ShT4ZuBfRbMxilZtOnJs3eokO\n" +
                "uXfRkicP5ftKJzz70gIeLMDHapm3beOzt3+wSHd3zF3ZebInJBHAQdgRlaIYZRiC\n" +
                "Q/TcZdxEodHTk1z+lbRw/ho6UTnwQnKNfkBTIkJY7vaLrE/wxU2NAkHCpctZgfCK\n" +
                "c/nB4N4WJT064N+v/dtpFp8RxxHwirgxEEjXmQrT0KqATLRcxT5qMkD9TImx46VA\n" +
                "qH3XT/8yiCWfCLadAxZ0FXvPnqj95Qz2iAyeqTyLwpWhVecmwBGuevfdPyxnI/d8\n" +
                "CW3E/ZwekYgh8DdTF/x2svmk24FMh0uyPsixzPwF3nZNyFSIuifJbuXmMS9ZsxaW\n" +
                "q0sjxYgbUayWXRj4qsDbXSjcxU1V8MqyXztfYZMn/VpOPf2iZrfaJxVBGWXn74K1\n" +
                "jWcmUQiMcaglpoTCTyyit9gyKagtLj1g/TFRkjlPkvR3GRKCnaSjBYa/aesrmO1t\n" +
                "ow==\n" +
                "-----END CERTIFICATE-----\n";
        SEID2CertificateValidator validator = createTestBusinessCertificateValidator(CertificateAuthoritiesProperties.defaultProperties(environment));
        assertDoesNotThrow(() -> validator.validate(X509CertificateUtils.readX509Certificate(certificate)));
        assertDoesNotThrow(() -> validator.validate(certificate));
    }

    @Test
    @DisplayName("then Digdirs Buypass test SoftToken cert is invalid (expired)")
    void testDigdirBuypassExpiredSoftToken() throws Exception {
        Environment environment = Environment.TEST;
        String certificate = "-----BEGIN CERTIFICATE-----\n" +
                "MIIGZjCCBE6gAwIBAgIKBSmqVtkz9l9mijANBgkqhkiG9w0BAQsFADBuMQswCQYD\n" +
                "VQQGEwJOTzEYMBYGA1UEYQwPTlRSTk8tOTgzMTYzMzI3MRMwEQYDVQQKDApCdXlw\n" +
                "YXNzIEFTMTAwLgYDVQQDDCdCdXlwYXNzIENsYXNzIDMgVGVzdDQgQ0EgRzIgU1Qg\n" +
                "QnVzaW5lc3MwHhcNMjEwNTIxMTU1NjE5WhcNMjQwNTIxMjE1OTAwWjCBijELMAkG\n" +
                "A1UEBhMCTk8xJDAiBgNVBAoMG0RJR0lUQUxJU0VSSU5HU0RJUkVLVE9SQVRFVDEl\n" +
                "MCMGA1UECwwcU0VJRCAyIHRlc3QgZmVsbGVzbMO4eXNpbmdhcjEUMBIGA1UEAwwL\n" +
                "RGlnZGlyIHRlc3QxGDAWBgNVBGEMD05UUk5PLTk5MTgyNTgyNzCCAaIwDQYJKoZI\n" +
                "hvcNAQEBBQADggGPADCCAYoCggGBAKij4NoNPuGlis2y8CmPP7pSYB8Rw/ANv59g\n" +
                "Mx++B25ScMfCba0pV0qQlB6BmV8koq8ySFeydsDLBAQimj6eocolUkR1JAto8DHo\n" +
                "MvoQgraQTXWQ0orXpQrDx8v0fW0eM6cCOwUNRke70bDv1BnlcLil66YAv3/kBUWt\n" +
                "C+AeDjJw/lvyddVgGAOY5EUmNnyMqmRPiONf8i248g5bhswEdXpZUGL9z7mRlJBk\n" +
                "gpzOe4Ifhq6vGOz6WDUPZjqEr5LQrDZpYfRJNpwwo8QZRO90flTR6CUwkEbJ6TUx\n" +
                "zXw7kI5BPRtePwMqHLwwOykaqk6p9isUPi4UGwS3nnKosuKtpkQ8ZU7gzWLfuruq\n" +
                "MM/+w1ri24HAyhH59Pvh/6xU2Yj35T5hBA3idVm8RP6ksZiHj7UGllRIhWZiwnHh\n" +
                "SMrhYR6yaU6Dhol5pPpzBmPh2+OFkYgSpX+fP7jCUEx0qLoxF5UYU1TGv+/+bv2E\n" +
                "rzIAwYy/HI3Z7adEt1kFEMeMRPamWQIDAQABo4IBZzCCAWMwCQYDVR0TBAIwADAf\n" +
                "BgNVHSMEGDAWgBSn/rtsWYitdC5GXnpo+dG7v8+2izAdBgNVHQ4EFgQUuob2AwrH\n" +
                "+qsEyYVbgBnvrv+D3P8wDgYDVR0PAQH/BAQDAgWgMB8GA1UdIAQYMBYwCgYIYIRC\n" +
                "ARoBAwIwCAYGBACPegEBMEEGA1UdHwQ6MDgwNqA0oDKGMGh0dHA6Ly9jcmwudGVz\n" +
                "dDQuYnV5cGFzc2NhLmNvbS9CUENsM0NhRzJTVEJTLmNybDB7BggrBgEFBQcBAQRv\n" +
                "MG0wLQYIKwYBBQUHMAGGIWh0dHA6Ly9vY3NwYnMudGVzdDQuYnV5cGFzc2NhLmNv\n" +
                "bTA8BggrBgEFBQcwAoYwaHR0cDovL2NydC50ZXN0NC5idXlwYXNzY2EuY29tL0JQ\n" +
                "Q2wzQ2FHMlNUQlMuY2VyMCUGCCsGAQUFBwEDBBkwFzAVBggrBgEFBQcLAjAJBgcE\n" +
                "AIvsSQECMA0GCSqGSIb3DQEBCwUAA4ICAQCizHPUlNd2Tju357a2cejWkOwYnJOa\n" +
                "kuexjd+99NF8eQcr2w4kWP1zwz1ssxPw7/57yX+ruzHT/EHqOkXhpM4MHRSLbPMY\n" +
                "4iPAIv8LeEYtQwb2u3PXwhUcpB7bNWUzSYOAA+GktZ5ObtCKZ7tIa/i1Ms4GgEOV\n" +
                "vffuxgo6mw4uIJrLrCaEzLIXKo89sxbSNujS892TNEcNHtINEmg9JG3jF8NBuo8l\n" +
                "uJrhawPCBSFImfz0cj+i81n4OGgHCO+jxDPgiebTao8IPvZGNgz1faqP9sqstH++\n" +
                "q8K2ohpT7fMvgrgEro1Jal775DgI3u+35SeeCgQOg8H4bvtDf0NXr6MFLL+vsMTR\n" +
                "6puIBm+y/2z2n2ZdD27aW+R3As147xicRwsH8vVbXHXMiCfYP8XYtonI913mC5lA\n" +
                "Gh4zeY6SlflQDW7PO04PkkuM+m5G5rMB6U8rpllbWagNlN/V24E/540n43E/haTG\n" +
                "PY+YdGoFqiujpeKjkEscVPX+oQbDmXcORRxpGdup20U0Rsw8+GXCr8htRANSY2oY\n" +
                "sHcbTQ0jT4TRcF9zJeVQ3BKUKGXete/TV6jXxsxucGGTsM0mvMBPsqESrGXqxzXb\n" +
                "xap+BtE1oE2drcnKSiAzQqGME2QOm652EITSKMMIPcqL6XSQYcBVF9qNiQF8/+TY\n" +
                "vbtKaa4BsjPZAg==\n" +
                "-----END CERTIFICATE-----";
        SEID2CertificateValidator validator = createTestBusinessCertificateValidator(CertificateAuthoritiesProperties.defaultProperties(environment));
        assertFalse(validator.isValid(X509CertificateUtils.readX509Certificate(certificate)));
        assertFalse(validator.isValid(certificate));
    }

    @Test
    @DisplayName("then Digdirs Buypass 4096 cert is valid")
    void testDigdirBuypassSoftToken() throws Exception {
        Environment environment = Environment.TEST;
        String certificate = "-----BEGIN CERTIFICATE-----\n" +
                "MIIG1DCCBLygAwIBAgILAZt5rbJFDP5MyJgwDQYJKoZIhvcNAQELBQAwbjELMAkG\n" +
                "A1UEBhMCTk8xGDAWBgNVBGEMD05UUk5PLTk4MzE2MzMyNzETMBEGA1UECgwKQnV5\n" +
                "cGFzcyBBUzEwMC4GA1UEAwwnQnV5cGFzcyBDbGFzcyAzIFRlc3Q0IENBIEcyIFNU\n" +
                "IEJ1c2luZXNzMB4XDTIzMDkwNTA4NDYwNFoXDTI2MDkwNTIxNTkwMFoweDELMAkG\n" +
                "A1UEBhMCTk8xJDAiBgNVBAoMG0RJR0lUQUxJU0VSSU5HU0RJUkVLVE9SQVRFVDEp\n" +
                "MCcGA1UEAwwgRElHSVRBTElTRVJJTkdTRElSRUtUT1JBVEVUIFRFU1QxGDAWBgNV\n" +
                "BGEMD05UUk5PLTk5MTgyNTgyNzCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoC\n" +
                "ggIBAK7FQqr3C9NikTYPAJFLgd6m80cwxSbdD+QfBOewwCrUqIHMmvtS0W1mPiSv\n" +
                "2gJ67gJGEoldkQuQtFW69+m33oO8QDWXsLCJjrgrXU7aRG1yKiMimgp8gw5R9+es\n" +
                "PyyqHojE7OtKrnrAhgfp2cFUyKK/bFJp7y7C8YUcd7J++CneU8UgZYOnvbWo7HAA\n" +
                "2xjds5/SR/eAbF5HYdMM951ukEZ7rsDcvrED9V/+I6iM8Igy8B7SChdCYjhdhC3p\n" +
                "w0nPCfGUZjq9CFOYkIK9LJ820r3npR0zQ3trD9g0YTjo8Y3Z/4xkotxBrHSZzGvQ\n" +
                "hAJJwWusajNeCji5T3p5ptaAXciD5dl7CGvqSykhUysHwbJoOqTEi4+1ZUK2klaQ\n" +
                "1L9FG8kfbZ/pYpMQx7VX4Q9vhI0dg+ct33iZzLlfMPGefp3GcU1s1SyhloczGM8K\n" +
                "wIpHBBcNkh6zpnqte/lRyf4V4W/rvcJcMbvDvIzmPHmJp/l/qXmrvrp+PUU6+10+\n" +
                "8AlUIDnIGUxKueDE6voAmO9tht16Gnq2XFsZ58YFbzZebHicONvLDpq8kIDM0F99\n" +
                "Ry08+xagwqvVKWne8aJEahqyIT4nDrL/1HXTGZNn3RVSQgdsC0yCqLVGlQ74wFpa\n" +
                "cGOvPdLckSqd/ccbyPK1sijjnLqwdCBLcjCBqYAVzDGOn7GXAgMBAAGjggFnMIIB\n" +
                "YzAJBgNVHRMEAjAAMB8GA1UdIwQYMBaAFKf+u2xZiK10LkZeemj50bu/z7aLMB0G\n" +
                "A1UdDgQWBBSrwKSRlhmheKrxflyWAT9oH6l6YzAOBgNVHQ8BAf8EBAMCBkAwHwYD\n" +
                "VR0gBBgwFjAKBghghEIBGgEDAjAIBgYEAI96AQEwQQYDVR0fBDowODA2oDSgMoYw\n" +
                "aHR0cDovL2NybC50ZXN0NC5idXlwYXNzY2EuY29tL0JQQ2wzQ2FHMlNUQlMuY3Js\n" +
                "MHsGCCsGAQUFBwEBBG8wbTAtBggrBgEFBQcwAYYhaHR0cDovL29jc3Bicy50ZXN0\n" +
                "NC5idXlwYXNzY2EuY29tMDwGCCsGAQUFBzAChjBodHRwOi8vY3J0LnRlc3Q0LmJ1\n" +
                "eXBhc3NjYS5jb20vQlBDbDNDYUcyU1RCUy5jZXIwJQYIKwYBBQUHAQMEGTAXMBUG\n" +
                "CCsGAQUFBwsCMAkGBwQAi+xJAQIwDQYJKoZIhvcNAQELBQADggIBAFW+YfGKzCcP\n" +
                "4uQH+aXjPnSTsT6ad/F7Ze5hOb+9USefOyG+RsJBDRn0lJpbfto64PUDcp0EGOux\n" +
                "gg4zHsfJXCIoUwrVIHNHGIDQE8MLXDaGcaUTmSgGW2QMlTvRYZWl8Z627Fhc0ku0\n" +
                "w5gUO+xoHhSR67niKuTn3ovQHIMP3roJ8jB0F/jYn4l0QpHydPSdn0Sqeb+eRfOJ\n" +
                "BBD7EgrRbHFCfF9/v67tyj1NAJab3YYMB/ejf7oChdjHW5YszbeFAbCie4X7Zm/h\n" +
                "/N/HLKOcSi/hL1bUtphJZ/9lxL9Z4FsffsrVuwvFzAGXn+rSj1c73hHfL4jG4MBw\n" +
                "HxEo9ebqBoAbXdOrVZru0vwkTdnliX7KwNvMZVElq76uY6SG8vnvXhklE0gxzAmo\n" +
                "rdEE8/1uSL3EtAcR0e5R1tSpoSsIP8nkqDRnsFzCOrfNCi0qPbXp8M+HqQuPc9nD\n" +
                "ggwxXd21soqi5dNo+o74T7jXx5sxH/BjC1AqtGbJFGBSln4Ow+P/jdSwvUakey0b\n" +
                "qxdNqS001QJZ3PQgboHmeoQGoFE1XuVR7BT58oP2qk1I+tI/kddilWRlnM2UlRCj\n" +
                "s/vBqdlp6Ec525+Q3XWlECzPP3jfOdaDvzBlP/t93hh6kGICixoP77Jc4p/YsSNz\n" +
                "YCIJgssoP0wyS1d1BFeNLzV1yd0ZhANp\n" +
                "-----END CERTIFICATE-----";
        SEID2CertificateValidator validator = createTestBusinessCertificateValidator(CertificateAuthoritiesProperties.defaultProperties(environment));
        assertTrue(validator.isValid(X509CertificateUtils.readX509Certificate(certificate)));
        assertTrue(validator.isValid(certificate));
    }

    @DisplayName("Test ny policies fra Commfides certs prod")
    @Test
    void testKSCommfidesProdCerts() throws Exception {
        String certificateSign = "MIIIajCCBlKgAwIBAgIUXk4tZD1dwKbH76AF5BEndOjS6iAwDQYJKoZIhvcNAQEN\n" +
                "BQAwajELMAkGA1UEBhMCTk8xGzAZBgNVBAoMEkNvbW1maWRlcyBOb3JnZSBBUzEY\n" +
                "MBYGA1UEYQwPTlRSTk8tOTg4MzEyNDk1MSQwIgYDVQQDDBtDb21tZmlkZXMgTGVn\n" +
                "YWwgUGVyc29uIC0gRzMwHhcNMjMwOTEzMTI1OTMzWhcNMjYwOTI3MTI1OTMyWjCB\n" +
                "yDELMAkGA1UEBhMCTk8xJTAjBgNVBAcMHEhhYWtvbiBWSUlzIGdhdGUgOSwwMTYx\n" +
                "IE9TTE8xKTAnBgNVBAoMIEtTLUtPTU1VTkVTRUtUT1JFTlMgT1JHQU5JU0FTSk9O\n" +
                "MRgwFgYDVQRhDA9OVFJOTy05NzEwMzIxNDYxDjAMBgNVBAsMBUFubmV0MRIwEAYD\n" +
                "VQQFEwk5NzEwMzIxNDYxKTAnBgNVBAMMIEtTLUtPTU1VTkVTRUtUT1JFTlMgT1JH\n" +
                "QU5JU0FTSk9OMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA+JxyrSvv\n" +
                "nimNX26LkYp94eUjV5/pazpHBj/VQi3O8sWlRH8fLJAElw6J288MfqitwUQGF6SM\n" +
                "PMX7JOsby55IKg8gBW6Yp34urdyIIYMPnbIn8DYeucd1jXpiI6HLmWmKPtCKC6II\n" +
                "Ri61zlTVAejql2pkRqDydiX7lpBHhyEOZaQWjWytFPhTqoT4oZ+B7ZVW29E4fc/J\n" +
                "HG0CfGV2m7T+OKOWJMkttyPJ1vc8GY7vA/yw2ClEr9ndCcId/6Mp5mb3hAJAcqkk\n" +
                "1nsvptDSdGCuyo3I0CFZj32rd4eAk/Jj2csH7Q7Z2AM+6F+jELpKgzQN9q5HtjDv\n" +
                "kajhMkv2OST4qPPnl+URqh2RDeXH+/CYtjtQrxmcLnhxKoeIxCyE04j57wt9s/zT\n" +
                "f/grx62DgXphYGK3Y4dAV+q2TCrpQyFOgkPKkWx39QwYlJ5ke1geFD/bs4YVvQP9\n" +
                "QyS5OZAdIBwr5kaZcEBjfYIMa0LSoDGamexQRLtz+gxD6J2OnWFOpiilAgMBAAGj\n" +
                "ggMnMIIDIzAMBgNVHRMBAf8EAjAAMB8GA1UdIwQYMBaAFPE0SOC+YTGcIxYCemTx\n" +
                "pUfH5edpMHwGCCsGAQUFBwEBBHAwbjBFBggrBgEFBQcwAoY5aHR0cDovL2NydC5j\n" +
                "b21tZmlkZXMuY29tL0czL0NvbW1maWRlc0xlZ2FsUGVyc29uQ0EtRzMuY3J0MCUG\n" +
                "CCsGAQUFBzABhhlodHRwOi8vb2NzcC5jb21tZmlkZXMuY29tMB8GA1UdEQQYMBaB\n" +
                "FGZpa3MtdXR2aWtsaW5nQGtzLm5vMIGxBgNVHSAEgakwgaYwCQYHBACL7EABATCB\n" +
                "mAYKYIRCAR0NgVIBATCBiTCBhgYIKwYBBQUHAgEWemh0dHBzOi8vcGRzLmNvbW1m\n" +
                "aWRlcy5jb20vRzMvQ29tbWZpZGVzLVBEUy1mb3ItQ2VydGlmaWNhdGVzLWFuZC1F\n" +
                "VS1RdWFsaWZpZWQtQ2VydGlmaWNhdGVzLUxlZ2FsLVBlcnNvbi1DZW50cmFsLUcz\n" +
                "X3YxLTEucGRmMDMGA1UdJQQsMCoGCCsGAQUFBwMCBggrBgEFBQcDBAYKKwYBBAGC\n" +
                "NxQCAgYIKwYBBQUHAwEwge4GCCsGAQUFBwEDBIHhMIHeMBUGCCsGAQUFBwsCMAkG\n" +
                "BwQAi+xJAQIwCAYGBACORgEBMBUGBgQAjkYBAjALEwNOT0sCAQECAQQwEwYGBACO\n" +
                "RgEGMAkGBwQAjkYBBgIwgY4GBgQAjkYBBTCBgzCBgBZ6aHR0cHM6Ly9wZHMuY29t\n" +
                "bWZpZGVzLmNvbS9HMy9Db21tZmlkZXMtUERTLWZvci1DZXJ0aWZpY2F0ZXMtYW5k\n" +
                "LUVVLVF1YWxpZmllZC1DZXJ0aWZpY2F0ZXMtTGVnYWwtUGVyc29uLUNlbnRyYWwt\n" +
                "RzNfdjEtMS5wZGYTAmVuMEoGA1UdHwRDMEEwP6A9oDuGOWh0dHA6Ly9jcmwuY29t\n" +
                "bWZpZGVzLmNvbS9HMy9Db21tZmlkZXNMZWdhbFBlcnNvbkNBLUczLmNybDAdBgNV\n" +
                "HQ4EFgQUOJQthvcm4gYkhV6w7m2AfGFYsOcwDgYDVR0PAQH/BAQDAgeAMA0GCSqG\n" +
                "SIb3DQEBDQUAA4ICAQB4NoEnKvtNxxBdNJBu5tIVmWivy3gJtiPgjQc4c5Pc1dNW\n" +
                "zhWF+X1t9/Txgff3xPU6VCxoCcf2YfxlgSuLELwUQviGvBWZzuAJxnBn/AUtsuWr\n" +
                "KFn1CGBhb67AeArkxRU6WHzz2mF1OSjs1gQC+s1dstd7qS8OcspFSv/MOB0yQi4T\n" +
                "SRF24wHUACoJBot2Uq6qnC6itwvBJo/uJ8sDCAprVkpaTOF+hs6W2x9e17FY5cZs\n" +
                "t3PtA3UOcX9yYDHsOtHsxtTuzEjzJWSpyZ4PF5H0r8vFp1+YxXKL9RQIhRJ4rcqL\n" +
                "QotdS7FoOw6ifoFuOxiV/r6VEYq2rw/XMk5q8hM7RqVRHYObIoaRKJzlKxD9NeK/\n" +
                "8/gsKIbab8a8KUqQ1fA0nigFraMtGqldReUjvFxp0sVdu5vPy2aImQLmXc3lUE0w\n" +
                "B0vgjojshZLwSVsrRUztogiAMS/Bvv1Rf/Lbogsu7I97sdLNgY38hO8nDChmlU4n\n" +
                "bhpFCpa+tPPh7xGkKdOe8s0OFrPhDi5EceBObE2xt+VeE4ONSxy+4HBG9Hip+Mnc\n" +
                "kDIvAElJyFqVlVIekIW41i7h3NWMZGd7FbFaHi2hItAuBsdEF3A8IlsNiTisfM/f\n" +
                "5MYLt4XLaFbDNOfbEjCUjQuwTAOm1khGE31bNs5QRzuZ2RkBdQf8fwelOOc3Qg==";
        String certificateNonRep = "MIIIXDCCBkSgAwIBAgIUTD734J8L0HjK3H221B2P7Kbx8tYwDQYJKoZIhvcNAQEN\n" +
                "BQAwajELMAkGA1UEBhMCTk8xGzAZBgNVBAoMEkNvbW1maWRlcyBOb3JnZSBBUzEY\n" +
                "MBYGA1UEYQwPTlRSTk8tOTg4MzEyNDk1MSQwIgYDVQQDDBtDb21tZmlkZXMgTGVn\n" +
                "YWwgUGVyc29uIC0gRzMwHhcNMjMwOTEzMTI1OTUyWhcNMjYwOTI3MTI1OTUxWjCB\n" +
                "yTELMAkGA1UEBhMCTk8xJjAkBgNVBAcMHUhhYWtvbiBWSUlzIGdhdGUgOSwgMDE2\n" +
                "MSBPU0xPMSkwJwYDVQQKDCBLUy1LT01NVU5FU0VLVE9SRU5TIE9SR0FOSVNBU0pP\n" +
                "TjEYMBYGA1UEYQwPTlRSTk8tOTcxMDMyMTQ2MQ4wDAYDVQQLDAVBbm5ldDESMBAG\n" +
                "A1UEBRMJOTcxMDMyMTQ2MSkwJwYDVQQDDCBLUy1LT01NVU5FU0VLVE9SRU5TIE9S\n" +
                "R0FOSVNBU0pPTjCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCCAYoCggGBAK/FegBW\n" +
                "gevlxIbbtSYyJ9u3ExswRMq8m/+5o/NM1md0Jl50X/SpUOrDAwL013pE6ayG3my1\n" +
                "xFGxBGjumXsLkc9rikrJezNVSl77QeSVsXwg6li9RKwIkn2DI9qzh34NkQqIwJlg\n" +
                "Rgu5yiF3nogxHswT26noHawbiwncKEgVZ/AVb4NkApwHznYLaAa1NSqcu25ACjcC\n" +
                "QN+JCQCZnBtu4qg9GTyMRWR/+KGGngiFcz4FWYSfalNl7qs87DhgbaRjZt2etboE\n" +
                "GHzj93Iastcw7hgkdRoYo4HlfzzUes3z53IZQ3KlIkvVu38tlb5MBcSFEFhIdyMe\n" +
                "BfZklEiSZDDf3dEBPW2ZXNcW4vMJZ5eB7Yb1aL8DJnUO6j/MmKZvdjCq7WqEp/yv\n" +
                "8q2F9OiYVnzDSNwAplbQK6XhlYuERzn7aQ1ujmpS0q6B0eWQ0al9WzV2Hl/RfwmP\n" +
                "T+fP9PiwPhSHy4y3AR+HXJGbkFtoxVfL2ViMpYY29ZYGozfnqvUN7ts8GwIDAQAB\n" +
                "o4IDGDCCAxQwDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBTxNEjgvmExnCMWAnpk\n" +
                "8aVHx+XnaTB8BggrBgEFBQcBAQRwMG4wRQYIKwYBBQUHMAKGOWh0dHA6Ly9jcnQu\n" +
                "Y29tbWZpZGVzLmNvbS9HMy9Db21tZmlkZXNMZWdhbFBlcnNvbkNBLUczLmNydDAl\n" +
                "BggrBgEFBQcwAYYZaHR0cDovL29jc3AuY29tbWZpZGVzLmNvbTAfBgNVHREEGDAW\n" +
                "gRRmaWtzLXV0dmlrbGluZ0Brcy5ubzCBsQYDVR0gBIGpMIGmMAkGBwQAi+xAAQEw\n" +
                "gZgGCmCEQgEdDYFIAQEwgYkwgYYGCCsGAQUFBwIBFnpodHRwczovL3Bkcy5jb21t\n" +
                "ZmlkZXMuY29tL0czL0NvbW1maWRlcy1QRFMtZm9yLUNlcnRpZmljYXRlcy1hbmQt\n" +
                "RVUtUXVhbGlmaWVkLUNlcnRpZmljYXRlcy1MZWdhbC1QZXJzb24tQ2VudHJhbC1H\n" +
                "M192MS0xLnBkZjAnBgNVHSUEIDAeBggrBgEFBQcDAgYIKwYBBQUHAwQGCCsGAQUF\n" +
                "BwMBMIHrBggrBgEFBQcBAwSB3jCB2zAVBggrBgEFBQcLAjAJBgcEAIvsSQECMAgG\n" +
                "BgQAjkYBATASBgYEAI5GAQIwCBMAAgEBAgEEMBMGBgQAjkYBBjAJBgcEAI5GAQYC\n" +
                "MIGOBgYEAI5GAQUwgYMwgYAWemh0dHBzOi8vcGRzLmNvbW1maWRlcy5jb20vRzMv\n" +
                "Q29tbWZpZGVzLVBEUy1mb3ItQ2VydGlmaWNhdGVzLWFuZC1FVS1RdWFsaWZpZWQt\n" +
                "Q2VydGlmaWNhdGVzLUxlZ2FsLVBlcnNvbi1DZW50cmFsLUczX3YxLTEucGRmEwJl\n" +
                "bjBKBgNVHR8EQzBBMD+gPaA7hjlodHRwOi8vY3JsLmNvbW1maWRlcy5jb20vRzMv\n" +
                "Q29tbWZpZGVzTGVnYWxQZXJzb25DQS1HMy5jcmwwHQYDVR0OBBYEFD9bym8vuZoB\n" +
                "VgqqYcBHrWQXDXUbMA4GA1UdDwEB/wQEAwIGQDANBgkqhkiG9w0BAQ0FAAOCAgEA\n" +
                "c+0PkxcpBxi9jrpEvYwOIHxV6mpevKoy/nG4Vf1GsuqnT7WQ7+Fqul1w1osFUpHt\n" +
                "FFohQdpL9HkqoO9p4V4qJqzqTMeJvBjZmqkIEX6JpTdmwa/5A0tN3UEDphhSmhCi\n" +
                "euXyJotd+fSEtuzTTNe3YO9JmwgtRe/rc43MGUUMs0y9sFDaA9ZFN9WcgvM24iNS\n" +
                "ERUql7TZEe78ixCl7B+A45XvAmmBMMCONyML6rN+Ag/P+cWVkEH6h/ZC4LAPAwMy\n" +
                "wLXIkmQArTemeA1/3jxy8mP4ncB2YrsrcszgGDCbp+cR2nV7se60FWZNBoQezvUd\n" +
                "FiCP6ecY9hbbAqQlxC/WcFJ5TLwXI5KAaZN4uHAyyYxzcPSu8pfNP0uoRPVYQq3L\n" +
                "bxQcbAE2IGf+BZ7zEO1s8hGtpIwBxZVXfULgs7YzBUHLQvB9eoWnZtWNAyuLsjke\n" +
                "WtsIxLIi9OntD7s1ZkZKVykDnc4mclkSmIdqMxA4+EvWy3zJyzD40l7dDGmfBUOj\n" +
                "4Pg0pZm3kf6OyHSBvhhDisMhai6kksWW8gjBNnQWlAlpYY0ONDWoqbJJpCML97sT\n" +
                "lLRno2dKkCqrEL4RzbdEZiqadqOCJC6qu7qr0M8FxjvedRHCSuQyqNFp67VaNvjk\n" +
                "R0z+/sVEXPIgfwfYYRg3rZ79rkCQz32cDDQkljk88o8=";
        String certificateEncipherment = "MIIHbTCCBVWgAwIBAgIUZoa7hUetyRxmF4v6FxFhB6KywjMwDQYJKoZIhvcNAQEN\n" +
                "BQAwajELMAkGA1UEBhMCTk8xGzAZBgNVBAoMEkNvbW1maWRlcyBOb3JnZSBBUzEY\n" +
                "MBYGA1UEYQwPTlRSTk8tOTg4MzEyNDk1MSQwIgYDVQQDDBtDb21tZmlkZXMgTGVn\n" +
                "YWwgUGVyc29uIC0gRzMwHhcNMjMwOTEzMTI1OTQyWhcNMjYwOTI3MTI1OTQxWjCB\n" +
                "yTELMAkGA1UEBhMCTk8xJjAkBgNVBAcMHUhhYWtvbiBWSUlzIGdhdGUgOSwgMDE2\n" +
                "MSBPU0xPMSkwJwYDVQQKDCBLUy1LT01NVU5FU0VLVE9SRU5TIE9SR0FOSVNBU0pP\n" +
                "TjEYMBYGA1UEYQwPTlRSTk8tOTcxMDMyMTQ2MQ4wDAYDVQQLDAVBbm5ldDESMBAG\n" +
                "A1UEBRMJOTcxMDMyMTQ2MSkwJwYDVQQDDCBLUy1LT01NVU5FU0VLVE9SRU5TIE9S\n" +
                "R0FOSVNBU0pPTjCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCCAYoCggGBAKqzfnOr\n" +
                "B3RojXKQxLebbM1+irlDH2G0BFFUxS7zbTDuSRad6b9u1NGyiF6D+MUqcyzmH9+k\n" +
                "JjVEDHRZPEmLn318AWHjzUBDWkFsWV1Lq6vlRovsVwfknhT7a0aLQdBrQzurHkem\n" +
                "N7v513UNpuSBnnZrl0HdUFTxh7wWkG593ZZZDrELtpRjmkgfLLDn/PK942zElqta\n" +
                "2AEFxjHx8HpgX6edlHZJVXswlwCIryui2LUeJNjS3l9jEdRsfAvb6Jgg3M3WlJSQ\n" +
                "BnIg7gfOr/04h4PMpVr8EiePjz6YIIZf2/LL8DK/IbNcta3DaE/FCB+O+eF4LNty\n" +
                "R3cQelfrpNC/MaNzZu/kElMR7rvvBU77D/9bKu5VxoeS8S7Qi9utYjje9ZJj3mKS\n" +
                "+hHqPIFH6MQNps3Rv25djzoQD8SNTnYgh8GKasVsWNow8BLIOP6rNObPyVFR/FL9\n" +
                "5A3073K6dL8psAGrd1bmKBEiEp0JvH+znbH7JL15/gysSlDXtC7CU/J6ewIDAQAB\n" +
                "o4ICKTCCAiUwDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBTxNEjgvmExnCMWAnpk\n" +
                "8aVHx+XnaTB8BggrBgEFBQcBAQRwMG4wRQYIKwYBBQUHMAKGOWh0dHA6Ly9jcnQu\n" +
                "Y29tbWZpZGVzLmNvbS9HMy9Db21tZmlkZXNMZWdhbFBlcnNvbkNBLUczLmNydDAl\n" +
                "BggrBgEFBQcwAYYZaHR0cDovL29jc3AuY29tbWZpZGVzLmNvbTAfBgNVHREEGDAW\n" +
                "gRRmaWtzLXV0dmlrbGluZ0Brcy5ubzCBsAYDVR0gBIGoMIGlMAgGBgQAj3oBATCB\n" +
                "mAYKYIRCAR0NgVwBATCBiTCBhgYIKwYBBQUHAgEWemh0dHBzOi8vcGRzLmNvbW1m\n" +
                "aWRlcy5jb20vRzMvQ29tbWZpZGVzLVBEUy1mb3ItQ2VydGlmaWNhdGVzLWFuZC1F\n" +
                "VS1RdWFsaWZpZWQtQ2VydGlmaWNhdGVzLUxlZ2FsLVBlcnNvbi1DZW50cmFsLUcz\n" +
                "X3YxLTEucGRmMCcGA1UdJQQgMB4GCCsGAQUFBwMCBggrBgEFBQcDBAYIKwYBBQUH\n" +
                "AwEwSgYDVR0fBEMwQTA/oD2gO4Y5aHR0cDovL2NybC5jb21tZmlkZXMuY29tL0cz\n" +
                "L0NvbW1maWRlc0xlZ2FsUGVyc29uQ0EtRzMuY3JsMB0GA1UdDgQWBBSbaY5J8NlN\n" +
                "JhQ/7BlyDKSkuelacjAOBgNVHQ8BAf8EBAMCAzgwDQYJKoZIhvcNAQENBQADggIB\n" +
                "AHi7MPwFMjRnt2qiIzYUEfgNRQ4ZsDsJwn5lTqTyw2pnjOnKkMTRVenwGWUQMGgi\n" +
                "YZs3RmfVgJN+yU/3BhvirlfpQkDTv2jWvD+/m71e+q210us5QwZNGXtmJqPTx11z\n" +
                "BJqiY1xrwy8pQeef9Q1HbN0oIOdFq4a/0qVFqPQtqtM+1RoNi0xpNhwAaFpC3QNY\n" +
                "4TT2uyhQ/9FhENAYam+cXe1mpRXYprD5MsXrCCoFxF4xh1pXRj0hEZiFjWU5jK0S\n" +
                "2epNkIQkl9bXqmQEu+c9DSjVr67w2qtONOKh717XkLyilaeDmqIIAnqJW0HTEc1e\n" +
                "TUS8p++xjcmjDxdSDpYyNfSt5i/f43zPW9udaW2b73xmfkCguM8LLmE5Gk1ERUB4\n" +
                "TRODfwTmf6or8bohof9fgsCVEaHTexgEHEkjLM+i3hCTtofw4VLGnQvK3Kg5GBMT\n" +
                "6Y42N7VTqqXWU0bXx2ZNVK5rnKoxsVIr5anAUz7QWLwc7V66P0+wKeTiEwJHw5S5\n" +
                "M2u+ed9HCoarG5P6xq9GA81HxvPupCWRMouIV6evXDLDeEen4mpXJIMtY9uJXCti\n" +
                "/jbQ8wHcwFyfexna7VQ4nA8MNp+tDoMA2uWhtSe3QFTOi5YcfKjkTilIOxrNEx4C\n" +
                "BqKUxWeATp3mV5og5RKg3IKE9GYfxLQ9ErKdED2Nb2o7";


        Environment environment = Environment.PROD;
        SEID2CertificateValidator validator = createTestBusinessCertificateValidator(CertificateAuthoritiesProperties.defaultProperties(environment));
        assertAll(
                () -> assertDoesNotThrow(() -> validator.validate(X509CertificateUtils.readX509Certificate(certificateSign))),
                () -> assertDoesNotThrow(() -> validator.validate(certificateSign)),
                () -> assertDoesNotThrow(() -> validator.validate(X509CertificateUtils.readX509Certificate(certificateNonRep))),
                () -> assertDoesNotThrow(() -> validator.validate(certificateNonRep)),
                () -> assertDoesNotThrow(() -> validator.validate(X509CertificateUtils.readX509Certificate(certificateEncipherment))),
                () -> assertDoesNotThrow(() -> validator.validate(certificateEncipherment))
        );
    }

}
