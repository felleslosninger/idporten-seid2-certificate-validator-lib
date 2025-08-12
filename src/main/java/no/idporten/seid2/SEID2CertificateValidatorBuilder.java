package no.idporten.seid2;


import no.idporten.validator.certificate.api.AsyncCrlCache;
import no.idporten.validator.certificate.api.CrlCache;
import no.idporten.validator.certificate.util.SimpleAsyncCrlCache;

import java.util.Objects;

/**
 * Builder configuring and creating certificate validator instances.  Has default configuration for test and production
 * environments, and options for CRL handling.
 */
public class SEID2CertificateValidatorBuilder {

    private Environment environment;
    private CertificateAuthoritiesProperties certificateAuthoritiesProperties;
    private CrlCache crlCache;

    /**
     * Creates builder with default settings for environment.
     *
     * @param environment environment
     * @see #withDefaults()
     */
    public SEID2CertificateValidatorBuilder(Environment environment) {
        this.environment = Objects.requireNonNull(environment, "Specify environment");
        this.withDefaults();
    }

    /**
     * Sets default properties for environment and default in-memory CRL caching containing pre-loaded CRLs and async
     * CRL cache updates.
     *
     * @return builder with default values
     */
    public SEID2CertificateValidatorBuilder withDefaults() {
        this.certificateAuthoritiesProperties = CertificateAuthoritiesProperties.defaultProperties(this.environment);
        this.withAsyncInMemoryCrlCache(15 * 60 * 1000); // 15 minutes
        this.withPreloadedCrlCache();
        return this;
    }

    /**
     * Override properties for environment.  Ignores null properties.
     *
     * @param certificateAuthoritiesProperties new environment properties
     * @return builder with new environment properties
     */
    public SEID2CertificateValidatorBuilder withProperties(CertificateAuthoritiesProperties certificateAuthoritiesProperties) {
        if (certificateAuthoritiesProperties != null) {
            this.certificateAuthoritiesProperties = certificateAuthoritiesProperties;
        }
        return this;
    }

    /**
     * Sets CRL caching strategy.  Use this to override defaults.
     *
     * It's a good ide to call {@link #withPreloadedCrlCache()} when overriding the default cache.
     *
     * @param crlCache CRL cache
     * @return builder with CRL cache
     */
    public SEID2CertificateValidatorBuilder withCrlCache(CrlCache crlCache) {
        this.crlCache = Objects.requireNonNull(crlCache);
        return this;
    }

    /**
     * Sets CRL caching to in-memory with async updates.  This is a default setting.
     *
     * @return builder with in-memory CRL cache
     */
    public SEID2CertificateValidatorBuilder withAsyncInMemoryCrlCache(long cacheRefreshIntervalMillis) {
        this.crlCache = new SimpleAsyncCrlCache(cacheRefreshIntervalMillis);
        return this;
    }

    /**
     * Pre-loads CRL cache with known CRLs.  This is a default setting.
     *
     * @return builder with data in CRL cache
     */
    public SEID2CertificateValidatorBuilder withPreloadedCrlCache() {
        Objects.requireNonNull(crlCache);
        for (String crlDistributionPoint : this.certificateAuthoritiesProperties.getCrlDistributionPoints()) {
            this.crlCache.set(crlDistributionPoint, X509CRLUtils.loadCRLFromClasspath(crlDistributionPoint, environment));
        }
        return this;
    }

    /**
     * Builds validator instance.
     *
     * @return
     * @throws Exception
     */
    public SEID2CertificateValidator build() throws Exception {
        Objects.requireNonNull(certificateAuthoritiesProperties);
        Objects.requireNonNull(crlCache);
        if (crlCache instanceof AsyncCrlCache) {
            ((AsyncCrlCache) crlCache).start();
        }
        return createValidator(environment, certificateAuthoritiesProperties, crlCache);
    }

    protected SEID2CertificateValidator createValidator(Environment environment, CertificateAuthoritiesProperties certificateAuthoritiesProperties, CrlCache crlCache) throws Exception {
        return new SEID2CertificateValidatorFactory().createValidator(environment, certificateAuthoritiesProperties, crlCache);
    }

}
