package no.idporten.eseal;

import no.digdir.certvalidator.Validator;
import no.digdir.certvalidator.api.CertificateValidationException;

import java.security.cert.X509Certificate;
import java.util.Objects;

/**
 * Validator for x509 electronic seals.
 */
public class ESealValidator {
    private final Validator validator;

    public ESealValidator(Validator validator) {
        this.validator = Objects.requireNonNull(validator);
    }

    public void validate(X509Certificate certificate) throws CertificateValidationException {
        validator.validate(certificate);
    }

}
