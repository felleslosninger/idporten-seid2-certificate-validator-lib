package no.idporten.seid2;

import no.idporten.validator.certificate.Validator;
import no.idporten.validator.certificate.ValidatorBuilder;
import no.idporten.validator.certificate.api.CertificateBucket;
import no.idporten.validator.certificate.api.CertificateValidationException;
import no.idporten.validator.certificate.api.CrlCache;
import no.idporten.validator.certificate.api.ValidatorRule;
import no.idporten.validator.certificate.rule.*;
import no.idporten.validator.certificate.util.CachingCrlFetcher;
import no.idporten.validator.certificate.util.SimpleCertificateBucket;

import java.util.Objects;
import java.util.Set;

/**
 * Factory creating validator instances. Load certificates and create rules.  Consider using the builder for easy
 * setup.
 *
 * @see SEID2CertificateValidatorBuilder
 */
public class SEID2CertificateValidatorFactory {

    /**
     * Creates a validator.
     *
     * @param environment                      environment
     * @param certificateAuthoritiesProperties properties (certificates and policies)
     * @param crlCache                         CRL cache implementation
     * @return certificate validator
     * @throws Exception if create fails
     */
    public SEID2CertificateValidator createValidator(Environment environment, CertificateAuthoritiesProperties certificateAuthoritiesProperties, CrlCache crlCache) throws Exception {
        Objects.requireNonNull(environment);
        Objects.requireNonNull(certificateAuthoritiesProperties);
        Objects.requireNonNull(crlCache);
        Validator validator = ValidatorBuilder.newInstance()
                .addRule(new ExpirationRule())
                .addRule(new SigningRule(SigningRule.Kind.PUBLIC_SIGNED_ONLY))
                .addRule(new CriticalExtensionRecognizedRule((certificateAuthoritiesProperties.getCriticalExtensionsRecognized().toArray(new String[0]))))
                .addRule(new CriticalExtensionRequiredRule(certificateAuthoritiesProperties.getCriticalExtensionsRequired().toArray(new String[0])))
                .addRule(createChainRule(environment, certificateAuthoritiesProperties))
                .addRule(new PolicyRule(certificateAuthoritiesProperties.getPolicies()))
                .addRule(new CRLRule(new CachingCrlFetcher(crlCache)))
                .build();
        return new SEID2CertificateValidator(validator);
    }

    private ValidatorRule createChainRule(Environment environment, CertificateAuthoritiesProperties certificateAuthoritiesProperties) throws CertificateValidationException {
        return new ChainRule(
                getCertificateBucket(certificateAuthoritiesProperties.getRootCertificates()),
                getCertificateBucket(certificateAuthoritiesProperties.getIntermediateCertificates()));
    }

    protected static CertificateBucket getCertificateBucket(Set<String> certs) throws CertificateValidationException {
        SimpleCertificateBucket bucket = new SimpleCertificateBucket();
        for (String cert : certs) {
            bucket.add(X509CertificateUtils.readX509Certificate(cert));
        }
        return bucket;
    }

}
