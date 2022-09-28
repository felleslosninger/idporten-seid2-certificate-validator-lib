package no.idporten.seid2;

import lombok.SneakyThrows;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;

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
    @DisplayName("then Digdirs new Commfides certificate is valid")
    void testCommfidesDigdir() throws Exception {
        Environment environment = Environment.TEST;
        String certificate = "-----BEGIN CERTIFICATE-----\n" +
                "MIIIkDCCBnigAwIBAgIUAtlkj0EtaxWl5NFxIHGGR9r8+QwwDQYJKoZIhvcNAQEL\n" +
                "BQAwcTELMAkGA1UEBhMCTk8xGzAZBgNVBAoMEkNvbW1maWRlcyBOb3JnZSBBUzEY\n" +
                "MBYGA1UEYQwPTlRSTk8tOTg4MzEyNDk1MSswKQYDVQQDDCJDb21tZmlkZXMgTGVn\n" +
                "YWwgUGVyc29uIC0gRzMgLSBURVNUMB4XDTIyMDgxOTExMjgxM1oXDTI1MDkwMjEx\n" +
                "MjgxMlowggEtMQswCQYDVQQGEwJOTzE7MDkGA1UEBxMyU2tyaXZhcnZlZ2VuIDIg\n" +
                "Njg2MyBMZWlrYW5nZXIgTGVpa2FuZ2VyIDY4NjMgTm9yZ2UxJDAiBgNVBAoTG0Rp\n" +
                "Z2l0YWxpc2VyaW5nc2RpcmVrdG9yYXRldDEYMBYGA1UEYRMPTlRSTk8tOTkxODI1\n" +
                "ODI3MWcwZQYDVQQLDF5UZXN0IG9nIHV0dmlrbGluZyBhdiBsw7hzbmluZ2VyIHNv\n" +
                "bSBza2FsIHZhbGlkZXJlcmUgc2VydGlmaWthdGVyIChJRC1wb3J0ZW4sIE1hc2tp\n" +
                "bnBvcnRlbiBvc3YpMRIwEAYDVQQFEwk5OTE4MjU4MjcxJDAiBgNVBAMTG0RpZ2l0\n" +
                "YWxpc2VyaW5nc2RpcmVrdG9yYXRldDCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCC\n" +
                "AYoCggGBAMq6omoQ/3GFCejcJ6DBLZ2137EMgYRcSEINQ10md5YAB+4LC/oOuVMn\n" +
                "9UpY2mQamwXIykx1LQd2V56lZ0nSpxFIgqG49DfQiyXXPmsie/TbQZP78j9lmUXh\n" +
                "wd9eFRgOsDUWuPNEfMbRMoyX26znHICjdhs+2Ms8YUC6Rxb2HjOD/5n+OStMcXq5\n" +
                "zkumdylns7AzRV3TtQBFhHS+4vpJum7AdfZRQSWVQMvf5aS+/6A7wIHYclvY7c5M\n" +
                "O+IT6ejXEAhzv4VaGx0+tRoIJybB4ztphP6TCsfRWkqThCqgi8+AnK9FxmHW9VqQ\n" +
                "ZON2hM0zhiGHttvxtrfPVVrWNL2LN87Pt+0VyXDYOHojBKTCJztNW9xZHKdLbqog\n" +
                "uVnjMCICZPleTheOFFfZ2iJMBlcXJ3ELYcb3xwTKy5s9AZtF4bHL+UI9bQVQAYbK\n" +
                "ISuyq2b+8YpiNvyDj8QwoW6loaufmefBQHWfZVVIFE+Xq5xbiRL70KD/xsdlKa+6\n" +
                "ygkBSuqLKQIDAQABo4IC4DCCAtwwDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBSr\n" +
                "PTE1kKD3bynqrOiKfndsk5jDXDCBiwYIKwYBBQUHAQEEfzB9ME8GCCsGAQUFBzAC\n" +
                "hkNodHRwOi8vY3J0LnRlc3QuY29tbWZpZGVzLmNvbS9HMy9Db21tZmlkZXNMZWdh\n" +
                "bFBlcnNvbkNBLUczLVRFU1QuY3J0MCoGCCsGAQUFBzABhh5odHRwOi8vb2NzcC50\n" +
                "ZXN0LmNvbW1maWRlcy5jb20wIAYDVR0RBBkwF4EVc2VydmljZWRlc2tAZGlnZGly\n" +
                "Lm5vMFAGA1UdIARJMEcwCQYHBACL7EABATA6BgtghEIBHYcRgVIBADArMCkGCCsG\n" +
                "AQUFBwIBFh1odHRwczovL3Bkcy5jb21tZmlkZXMuY29tL0czLzAzBgNVHSUELDAq\n" +
                "BggrBgEFBQcDAgYIKwYBBQUHAwQGCisGAQQBgjcUAgIGCCsGAQUFBwMBMIHuBggr\n" +
                "BgEFBQcBAwSB4TCB3jAVBggrBgEFBQcLAjAJBgcEAIvsSQECMAgGBgQAjkYBATAV\n" +
                "BgYEAI5GAQIwCxMDTk9LAgEBAgEEMBMGBgQAjkYBBjAJBgcEAI5GAQYCMIGOBgYE\n" +
                "AI5GAQUwgYMwgYAWemh0dHBzOi8vcGRzLmNvbW1maWRlcy5jb20vRzMvQ29tbWZp\n" +
                "ZGVzLVBEUy1mb3ItQ2VydGlmaWNhdGVzLWFuZC1FVS1RdWFsaWZpZWQtQ2VydGlm\n" +
                "aWNhdGVzLUxlZ2FsLVBlcnNvbi1DZW50cmFsLUczX3YxLTAucGRmEwJlbjBUBgNV\n" +
                "HR8ETTBLMEmgR6BFhkNodHRwOi8vY3JsLnRlc3QuY29tbWZpZGVzLmNvbS9HMy9D\n" +
                "b21tZmlkZXNMZWdhbFBlcnNvbkNBLUczLVRFU1QuY3JsMB0GA1UdDgQWBBRAbsc4\n" +
                "soXEsjcA1/iEA7ARpPqLfjAOBgNVHQ8BAf8EBAMCB4AwDQYJKoZIhvcNAQELBQAD\n" +
                "ggIBAFY+zAqW+mpp2V8NhQOOCJUOczsGEqnKNydO6WQBd3gMQadKI3SNq+nsGyfh\n" +
                "W9z377I1GHmUBqZkW0i2gpXMlhoTqq0uINLf5Fonpsbqjv77pHLKi6SEwlmFNLwL\n" +
                "wTpKN/FfCnQCAoHAPncGxHYqdaEeImuF9vu6fymuJm+I7uwYxOp0VTW3uIlvskXQ\n" +
                "Zf5yZwM6pmhhy7ylpVIGmxRKeko/mEMz6y8CjlqUlH83vOoFWYk2TY8ELtfS1amJ\n" +
                "QKQ7iGeBhc49GEWl2wAWKc4RTR0AYmoX1f5qvI2fyrQxUrdtVWOMlMjbV2lovuZv\n" +
                "UuELLigz54u9/xi7F/fjAyl3jH2xb9LDd42YVAYPj2NV4Tc8nC5xBLr49hBQi4Z1\n" +
                "/67Q4WOzV+WoaeehCboxfQdUaNYFHuLTzoRiuGXStRU/bjnLoLAww74BmU0PDLX5\n" +
                "onGkLyG8wOT+XHngS0sdDOzLoFD46obqi516JRvJK8N2MJ82ydTKd21j/kWIm7p9\n" +
                "uawmJAZefqsOvjlYuX0seQOld5Ge4T9dVH/Yqli923RJwJUgsRFRl/bvGC+h1OCl\n" +
                "vLWC3dTePGKjlQlLjxufqp2H+1rj3rOl/+AQYzZmjxck0a7A97oDwjfDN6OVN7tr\n" +
                "SWkkEFHnSnFJvHL4A5Gy/H67MFiM5xmky1fPvtXbxESEBeGw\n" +
                "-----END CERTIFICATE-----";
        SEID2CertificateValidator validator = createTestBusinessCertificateValidator(CertificateAuthoritiesProperties.defaultProperties(environment));
        assertDoesNotThrow(() -> validator.validate(X509CertificateUtils.readX509Certificate(certificate)));
    }

    @Test
    @DisplayName("then Digdirs Buypass SoftToken cert is valid")
    void testDigdirBuypassSoftToken() throws Exception {
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
        assertDoesNotThrow(() -> validator.validate(X509CertificateUtils.readX509Certificate(certificate)));
    }

}


