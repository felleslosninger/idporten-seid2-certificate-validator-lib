package no.idporten.seid2;

import no.digdir.certvalidator.Validator;
import no.digdir.certvalidator.api.CertificateValidationException;

import java.security.cert.X509Certificate;
import java.util.Objects;

/**
 * SEID2 certificate validator for X509 certificates.
 */
public class SEID2CertificateValidator {
    private final Validator validator;

    public SEID2CertificateValidator(Validator validator) {
        this.validator = Objects.requireNonNull(validator);
    }

    public void validate(X509Certificate certificate) throws CertificateValidationException {
        validator.validate(certificate);
    }

    public boolean isValid(X509Certificate certificate) {
        try {
            validator.validate(certificate);
            return true;
        } catch (CertificateValidationException e) {
            // TODO hvordan kan lib logge?
            return false;
        }
    }

}
