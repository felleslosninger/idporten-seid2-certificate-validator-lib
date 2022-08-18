package no.idporten.seid2;

import no.digdir.certvalidator.util.CrlUtils;

import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.cert.X509CRL;

/**
 * Utilities for handling CRLs for pre-loaded caches.
 */
class X509CRLUtils {

    /**
     * URL-encode an url so it can be used as a filename.
     */
    static String toFilename(String url) {
        return URLEncoder.encode(url, Charset.forName("UTF-8"));
    }

    /**
     * Downloads CRL and saves to resources directory for environment. Downloaded CRLs are stored in resources/crl/TEST
     * and resources/crl/PROD under src/main.
     *
     * @param environment environment
     */
    static void downloadCRLAndSaveToResources(Environment environment) {
        try {
            for (String crlDistributionPoint : CertificateAuthoritiesProperties.defaultProperties(environment).getCrlDistributionPoints()) {
                X509CRL crl = CrlUtils.load(new URL(crlDistributionPoint).openStream());
                Path path = Paths.get("src","main","resources","crl", environment.name(), toFilename(crlDistributionPoint));
                CrlUtils.save(Files.newOutputStream(path, StandardOpenOption.CREATE, StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING), crl);
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Loads a CRL from classpath.
     *
     * @param distributionPointUrl url to distribution point.  The encoded url is the file name.
     * @param environment environment for CRL.  The environment is used to find the directory for the CRL file.
     * @return CRL
     */
    static X509CRL loadCRLFromClasspath(String distributionPointUrl, Environment environment) {
        try {
            return CrlUtils.load(X509CRLUtils.class.getClassLoader().getResourceAsStream("crl/" + environment.name() + "/" + toFilename(distributionPointUrl)));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

}
