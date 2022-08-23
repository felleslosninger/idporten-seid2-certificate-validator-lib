package no.idporten.seid2;

import no.digdir.certvalidator.Validator;
import no.digdir.certvalidator.ValidatorBuilder;
import no.digdir.certvalidator.api.CertificateBucket;
import no.digdir.certvalidator.api.CrlCache;
import no.digdir.certvalidator.api.ValidatorRule;
import no.digdir.certvalidator.rule.*;
import no.digdir.certvalidator.structure.AndJunction;
import no.digdir.certvalidator.structure.OrJunction;
import no.digdir.certvalidator.util.CachingCrlFetcher;
import no.digdir.certvalidator.util.SimpleCertificateBucket;
import no.digdir.certvalidator.util.SimplePrincipalNameProvider;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.List;
import java.util.Objects;

/**
 * Factory creating validator instances. Load certificates and create rules.  Consider using the builder for easy
 * setup.
 * @see SEID2CertificateValidatorBuilder
 */
public class SEID2CertificateValidatorFactory {

    /**
     * Creates a validator.
     *
     * @param environment environment
     * @param certificateAuthoritiesProperties properties (certificates and policies)
     * @param crlCache CRL cache implementation
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

    private ValidatorRule createChainRule(Environment environment, CertificateAuthoritiesProperties certificateAuthoritiesProperties) throws IOException, CertificateException {
        final ValidatorRule chainRule;
        switch (environment) {
            case TEST:
                //Ignoring validation of policies of Commfides certificates in test ca chains.
                ValidatorRule buypassChainRule = new ChainRule(getCertificateBucket(certificateAuthoritiesProperties.getRootCertificates()), getCertificateBucket(certificateAuthoritiesProperties.getIntermediateCertificates()), certificateAuthoritiesProperties.getPolicies().toArray(new String[0]));
                ValidatorRule commfidesChainRule = new ChainRule(getCertificateBucket(certificateAuthoritiesProperties.getRootCertificates()), getCertificateBucket(certificateAuthoritiesProperties.getIntermediateCertificates()));
                PrincipalNameRule commfidesIssuerRule = new PrincipalNameRule("O", new SimplePrincipalNameProvider("Commfides Norge AS - 988 312 495"), PrincipalNameRule.Principal.ISSUER);
                AndJunction commfidesChainValidationJunction = new AndJunction(commfidesIssuerRule, commfidesChainRule);
                chainRule = new OrJunction(commfidesChainValidationJunction, buypassChainRule);
                break;
            case PROD:
            default:
                chainRule = new ChainRule(
                        getCertificateBucket(certificateAuthoritiesProperties.getRootCertificates()),
                        getCertificateBucket(certificateAuthoritiesProperties.getIntermediateCertificates()),
                        certificateAuthoritiesProperties.getPolicies().toArray(new String[0]));
        }
        return chainRule;
    }

    private static CertificateBucket getCertificateBucket(List<String> certs) throws IOException, CertificateException {
        SimpleCertificateBucket bucket = new SimpleCertificateBucket();
        for (String cert : certs) {
            bucket.add(X509CertificateUtils.readX509Certificate(cert));
        }
        return bucket;
    }

}
