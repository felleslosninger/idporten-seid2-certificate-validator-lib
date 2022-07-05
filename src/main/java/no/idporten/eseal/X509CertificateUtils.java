package no.idporten.eseal;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class X509CertificateUtils {
    public static X509Certificate readX509Certificate(String cert) throws IOException, CertificateException {
        if (!cert.startsWith("-----BEGIN CERTIFICATE-----")) {
            cert = "-----BEGIN CERTIFICATE-----\n" + cert;
        }
        if (!cert.endsWith("-----END CERTIFICATE-----")) {
            cert = cert + "\n-----END CERTIFICATE-----";
        }

        StringReader certPem = new StringReader(cert);
        PemReader pemReader = new PemReader(certPem);
        PemObject pemObject = pemReader.readPemObject();
        ByteArrayInputStream bIn = new ByteArrayInputStream(pemObject.getContent());
        CertificateFactory instance = CertificateFactory.getInstance("X.509");
        return (X509Certificate) instance.generateCertificate(bIn);
    }
}
