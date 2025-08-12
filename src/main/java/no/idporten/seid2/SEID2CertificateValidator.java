package no.idporten.seid2;

import no.idporten.validator.certificate.Validator;
import no.idporten.validator.certificate.api.CertificateValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.cert.X509Certificate;
import java.util.Objects;

/**
 * SEID2 certificate validator for X509 certificates.
 */
public class SEID2CertificateValidator {

    private final Logger log = LoggerFactory.getLogger(SEID2CertificateValidator.class);

    private final Validator validator;

    public SEID2CertificateValidator(Validator validator) {
        this.validator = Objects.requireNonNull(validator);
    }

    public void validate(X509Certificate certificate) throws CertificateValidationException {
        validator.validate(certificate);
    }

    public void validate(String certificate) throws CertificateValidationException {
        this.validate(X509CertificateUtils.readX509Certificate(certificate));
    }

    public boolean isValid(X509Certificate certificate) {
        try {
            validator.validate(certificate);
            return true;
        } catch (CertificateValidationException e) {
            log.error("Invalid certificate", e);
            return false;
        }
    }

    public boolean isValid(String certificate) {
        try {
            return this.isValid(X509CertificateUtils.readX509Certificate(certificate));
        } catch (CertificateValidationException e) {
            log.error("Invalid certificate", e);
            return false;
        }
    }

}
