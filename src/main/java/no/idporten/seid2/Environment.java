package no.idporten.seid2;

import java.util.Objects;

/**
 * Environments.  Test certificates should only be used in test environments, and production certificates should only
 * be used in production environments.
 */
public enum Environment {
    TEST,
    PROD;

    public static Environment of(String caEnvironment) {
        Objects.requireNonNull(caEnvironment, "Specify environment");
        return valueOf(caEnvironment.toUpperCase());
    }

}
