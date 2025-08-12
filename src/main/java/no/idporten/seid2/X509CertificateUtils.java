package no.idporten.seid2;

import no.idporten.validator.certificate.api.CertificateValidationException;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.ByteArrayInputStream;
import java.io.StringReader;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

/**
 * Utilities for handling PEM-encoded certificates.
 */
class X509CertificateUtils {

    public static final String BEGIN_CERT = "-----BEGIN CERTIFICATE-----";
    public static final String END_CERT = "-----END CERTIFICATE-----";

    /**
     * Read X509 pem encoded certificate.  Adds header and footer if missing.
     */
    static X509Certificate readX509Certificate(String cert) throws CertificateValidationException {
        try {
            if (!cert.startsWith(BEGIN_CERT)) {
                cert = BEGIN_CERT + "\n" + cert;
            }
            if (!cert.endsWith(END_CERT)) {
                cert = cert + "\n" + END_CERT;
            }

            StringReader certPem = new StringReader(cert);
            PemReader pemReader = new PemReader(certPem);
            PemObject pemObject = pemReader.readPemObject();
            ByteArrayInputStream bIn = new ByteArrayInputStream(pemObject.getContent());
            CertificateFactory instance = CertificateFactory.getInstance("X.509");
            return (X509Certificate) instance.generateCertificate(bIn);
        } catch (Exception e) {
            throw new CertificateValidationException("Failed to read certificate", e);
        }
    }

    /**
     * Encode certificate.
     */
    static String pemEncodedCert(Certificate cert) throws Exception {
        return String.format("%s\n%s\n%s", BEGIN_CERT, Base64.getEncoder().encodeToString(cert.getEncoded()), END_CERT);
    }

}
