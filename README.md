# idporten-seid2-certificate-validator

Java library setting up [eid-certvalidator](https://github.com/felleslosninger/eid-certvalidator) for SEID 2.0 certificate validation in ID-porten applications.  

Buypass has made a presentation of [SEID v2.0 nye nasjonale sertifikatprofiler](SEID%20v%202.0%20-%20Nye%20nasjonale%20sertifikatprofiler%20-%20Buypass.pdf).

The setup for certificate validation in complex.  Even if the configuration of certificate chains and policies for test and production environments is quite stable, it does change and needs to updated across applications.  Validation rules must be consistent across applications that use different frameworks and runtime environments.  This library makes it easier to use certificate validation in applictations:

* easy setup through builder or factory objects
* application can use pre-defined configuration
* application can override the parts of configuration it wants to override
* dependabot can manage updates in configuration or rules across applications

## Certificate authorities properties

The default properties used in the library is avaibale in the [certificate authorities properties](src/main/java/no/idporten/seid2/CertificateAuthoritiesProperties.java) class.  It contains properties for test and production environments for certificate authorities Buypass and Commfides.

## Pre-loaded CRLs

CRLs are preloaded and added to the CRL cache when using the default setup.  

The CRLs are downloaded [when JUnit tests are run](src/test/java/no/idporten/seid2/X509CRLUtilsTest.java).  They are stored under the [src/main/resources directory](src/main/resources).  Commit the changes if needed.  This will keep the library fairly updated even when CRL services are down on the CA side on application startup.

## Using the library

### Setting up the SEID2 certificate validator
The library uses an enum to [choose between test and production environments](src/main/java/no/idporten/seid2/Environment.java).  The of() method translates strings to enum instances.

Both a builder and a factory to create certificate validators is provided.  The builder makes configuration of a validator easy, and the factory creates the actual rules from the configuration.  The builder uses the factory to create certificate validators.

The [builder](src/main/java/no/idporten/seid2/SEID2CertificateValidatorBuilder.java) is the easy way to set up a validator.  The application must provide the environment, it may override certificates and policies, and may change the default in-memory CRL handling to disk-based caching.  The builder uses the factory to create the certificate validator.  This is the preferred way for an application to create a certificate validator.

To create a certificate validator for a test environment, simply use:
```
SEID2CertificateValidator certificateValidator = new SEID2CertificateValidatorBuilder(Environment.TEST).build();
```
To avoid hardcoding the environment, the application can provide it as a String (maybe read from config?):
```
String environment = "test"; // read from application config
SEID2CertificateValidator certificateValidator = new SEID2CertificateValidatorBuilder(Environment.of(environment)).build();
```
If the application needs to use a different set of properties or wants to replace the CRL caching strategy, the builder has methods to customize this:
```
// read values from application config and populate properties
CertificateAuthoritiesProperties properties = new CertificateAuthoritiesProperties();
SEID2CertificateValidator certificateValidator = new SEID2CertificateValidatorBuilder(Environment.TEST)
        .withProperties(properties)
        .withCrlCacheOnDisk(Path.of("path/to/crl/cache/dir"))
        .build();
```

The [factory](src/main/java/no/idporten/seid2/SEID2CertificateValidatorFactory.java) is the hard way to set up a validator.  The application must provide the environment, the certificates and policies to use, and the CRL handling.  The factory creates the certificate validator using rules from the eid-certvalidator project.  The factory can be used for application that needs more control or wants to access the underlying library.  If the application needs to do this, maybe this library is not a good match for the application?

### Using the SEID2 certificate validator
The [SEID2 certificate validator](src/main/java/no/idporten/seid2/SEID2CertificateValidator.java) has two methods for validating X509 certificates.  

The validate() method throws an exception that must be handled by the application.  The exception contains information about the failed validation.

```
X509Certificate certificate = ...;
SEID2CertificateValidator certificateValidator = new SEID2CertificateValidatorBuilder(Environment.TEST).build();
try {
    certificateValidator.validate(certificate);
} catch (CertificateValidationException e) {
    // handle invalid certificate
}
```

The isValid() method returns true for valid certificates and false for invalid certificates.  