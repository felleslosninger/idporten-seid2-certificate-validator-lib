package no.idporten.eseal;


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
public class ESealValidatorBuilder {

    private Environment environment;
    private CertificateAuthoritiesProperties certificateAuthoritiesProperties;
    private CrlCache crlCache;

    /**
     * Creates builder with default settings for environment.
     *
     * @param environment environment
     * @see #withDefaults()
     */
    public ESealValidatorBuilder(Environment environment) {
        this.environment = Objects.requireNonNull(environment, "Specify environment");
        this.withDefaults();
    }

    /**
     * Sets default properties for environment and default in-memory CRL caching.
     *
     * @return builder with default values
     */
    public ESealValidatorBuilder withDefaults() {
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
    public ESealValidatorBuilder withProperties(CertificateAuthoritiesProperties certificateAuthoritiesProperties) {
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
    public ESealValidatorBuilder withCrlCacheOnDisk(Path folder) throws IOException {
        this.crlCache = new DirectoryCrlCache(Objects.requireNonNull(folder, "Specify folder"));
        return this;
    }

    /**
     * Sets CRL caching to in-memory.  This is the default setting.
     *
     * @return builder for in-memory CRL cache
     */
    public ESealValidatorBuilder withCrlCacheInMemory() {
        this.crlCache = new SimpleCrlCache();
        return this;
    }

    /**
     * Builds validator instance.
     *
     * @return
     * @throws Exception
     */
    public ESealValidator build() throws Exception {
        Objects.requireNonNull(certificateAuthoritiesProperties);
        Objects.requireNonNull(crlCache);
        return createValidator(environment, certificateAuthoritiesProperties, crlCache);
    }

    protected ESealValidator createValidator(Environment environment, CertificateAuthoritiesProperties certificateAuthoritiesProperties, CrlCache crlCache) throws Exception {
        return new ESealValidatorFactory().createValidator(environment, certificateAuthoritiesProperties, crlCache);
    }

}
