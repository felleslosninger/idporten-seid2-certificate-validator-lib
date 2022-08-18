package no.idporten.seid2;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * When these tests are run, fresh CRLs are downloaded.  Remember du commit them along with your other changes!
 */
@DisplayName("When handling preloading of CRLs")
public class X509CRLUtilsTest {

    @Test
    @DisplayName("then CRLs are downloaded and saved to src/main/resources and can be loaded from classpath")
    void testDownloadAndSaveCRLs() {
        for (Environment environment : Environment.values()) {
            X509CRLUtils.downloadCRLAndSaveToResources(environment);
            for (String url : CertificateAuthoritiesProperties.defaultProperties(environment).getCrlDistributionPoints()) {
                assertNotNull(X509CRLUtils.loadCRLFromClasspath(url, environment));
            }
        }
    }



}
