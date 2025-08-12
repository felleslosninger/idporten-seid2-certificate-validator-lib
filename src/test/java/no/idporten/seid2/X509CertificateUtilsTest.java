package no.idporten.seid2;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.*;

class X509CertificateUtilsTest {


    @DisplayName("When encoded X509 certificates as PEM it should have the correct CERT header and footer")
    @Test
    void testPemEncodedCert() throws Exception {
        X509Certificate certificate = new TestData().selfSignedCertificate();
        String pemEncodedCert = X509CertificateUtils.pemEncodedCert(certificate);
        assertNotNull(pemEncodedCert);
        assertTrue(pemEncodedCert.startsWith(X509CertificateUtils.BEGIN_CERT));
        assertTrue(pemEncodedCert.endsWith(X509CertificateUtils.END_CERT));
        assertEquals(3, pemEncodedCert.lines().count());
        assertTrue(pemEncodedCert.length() > X509CertificateUtils.BEGIN_CERT.length()+
                X509CertificateUtils.END_CERT.length() + 2  ); // +2 for newlines);
    }

}