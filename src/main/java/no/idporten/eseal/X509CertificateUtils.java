package no.idporten.eseal;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class X509CertificateUtils {

    public static final String BEGIN_CERT = "-----BEGIN CERTIFICATE-----";
    public static final String END_CERT = "-----END CERTIFICATE-----";

    /**
     * Read X509 pem encoded certificate.
     */
    public static X509Certificate readX509Certificate(String cert) throws IOException, CertificateException {
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
    }

    /**
     * Enode certificate.
     */
    public static String pemEncodedCert(Certificate cert) throws Exception {
        StringBuilder sb = new StringBuilder();
        sb.append(BEGIN_CERT + "\n");
        sb.append(Base64.getEncoder().encodeToString(cert.getEncoded()));
        sb.append("\n" + END_CERT);
        return sb.toString();
    }

}
