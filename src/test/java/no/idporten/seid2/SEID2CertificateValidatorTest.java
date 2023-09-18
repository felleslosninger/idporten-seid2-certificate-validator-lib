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
        assertDoesNotThrow(() -> validator.validate(certificate));
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
        assertDoesNotThrow(() -> validator.validate(certificate));
    }

    @Test
    void testKartverket() throws Exception {
        Environment environment = Environment.TEST;
        String certificate = "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";
        SEID2CertificateValidator validator = createTestBusinessCertificateValidator(CertificateAuthoritiesProperties.defaultProperties(environment));
        assertDoesNotThrow(() -> validator.validate(X509CertificateUtils.readX509Certificate(certificate)));
        assertDoesNotThrow(() -> validator.validate(certificate));
    }


    @DisplayName("Test ny policy fra Commfides prod")
    @Test
    void testKSCommfidesProdCert() throws Exception {
        String certificate = "MIIIajCCBlKgAwIBAgIUXk4tZD1dwKbH76AF5BEndOjS6iAwDQYJKoZIhvcNAQEN\n" +
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

        Environment environment = Environment.PROD;
        SEID2CertificateValidator validator = createTestBusinessCertificateValidator(CertificateAuthoritiesProperties.defaultProperties(environment));
        assertDoesNotThrow(() -> validator.validate(X509CertificateUtils.readX509Certificate(certificate)));
        assertDoesNotThrow(() -> validator.validate(certificate));
    }




}


