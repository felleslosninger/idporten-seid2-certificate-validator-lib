package no.idporten.seid2;

import no.digdir.certvalidator.Validator;
import no.digdir.certvalidator.ValidatorBuilder;
import no.digdir.certvalidator.api.CertificateBucket;
import no.digdir.certvalidator.api.CertificateValidationException;
import no.digdir.certvalidator.api.CrlCache;
import no.digdir.certvalidator.api.ValidatorRule;
import no.digdir.certvalidator.rule.*;
import no.digdir.certvalidator.util.CachingCrlFetcher;
import no.digdir.certvalidator.util.SimpleCertificateBucket;

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
                .addRule(new CRLRule(new CachingCrlFetcher(crlCache)))
                .build();
        return new SEID2CertificateValidator(validator);
    }

    private ValidatorRule createChainRule(Environment environment, CertificateAuthoritiesProperties certificateAuthoritiesProperties) throws CertificateValidationException {
        return new ChainRule(
                getCertificateBucket(certificateAuthoritiesProperties.getRootCertificates()),
                getCertificateBucket(certificateAuthoritiesProperties.getIntermediateCertificates()),
                certificateAuthoritiesProperties.getPolicies().toArray(new String[0]));
    }

    private static CertificateBucket getCertificateBucket(Set<String> certs) throws CertificateValidationException {
        SimpleCertificateBucket bucket = new SimpleCertificateBucket();
        for (String cert : certs) {
            bucket.add(X509CertificateUtils.readX509Certificate(cert));
        }
        return bucket;
    }

}
