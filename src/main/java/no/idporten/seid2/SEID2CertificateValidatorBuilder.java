package no.idporten.seid2;


import no.digdir.certvalidator.api.CrlCache;
import no.digdir.certvalidator.util.DirectoryCrlCache;
import no.digdir.certvalidator.util.SimpleCrlCache;

import java.io.IOException;
import java.nio.file.Path;
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
     * Sets default properties for environment and default in-memory CRL caching.
     *
     * @return builder with default values
     */
    public SEID2CertificateValidatorBuilder withDefaults() {
        this.certificateAuthoritiesProperties = CertificateAuthoritiesProperties.defaultProperties(this.environment);
        this.withCrlCacheInMemory();
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
     * Sets CRL caching to use disk as backup for in-memory cache.
     *
     * @param folder cache folder
     * @return builder with disk CRL cache
     * @throws IOException if path is not correct
     */
    public SEID2CertificateValidatorBuilder withCrlCacheOnDisk(Path folder) throws IOException {
        this.crlCache = new DirectoryCrlCache(Objects.requireNonNull(folder, "Specify folder"));
        return this;
    }

    /**
     * Sets CRL caching to in-memory.  This is the default setting.
     *
     * @return builder for in-memory CRL cache
     */
    public SEID2CertificateValidatorBuilder withCrlCacheInMemory() {
        this.crlCache = new SimpleCrlCache();
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
        return createValidator(environment, certificateAuthoritiesProperties, crlCache);
    }

    protected SEID2CertificateValidator createValidator(Environment environment, CertificateAuthoritiesProperties certificateAuthoritiesProperties, CrlCache crlCache) throws Exception {
        return new SEID2CertificateValidatorFactory().createValidator(environment, certificateAuthoritiesProperties, crlCache);
    }

}
