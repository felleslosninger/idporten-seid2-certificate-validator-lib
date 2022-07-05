# idporten-eseal-validator

Java library setting up [eid-certvalidator](https://github.com/felleslosninger/eid-certvalidator) for use in ID-porten applications.  

The setup for certificate validation in complex.  Even if the configuration of certificate chains and policies for test and production environments is quite stable, it does change and needs to updated across applications.  Validation rules must be consistent across applications that use different frameworks and runtime environments.  This library makes it easier to use certificate validation in applictations:

* easy setup through builder or factory objects
* application can use pre-defined configuration
* application can override the parts of configuration it wants to override
* dependabot can manage updates in configuration or rules across applications

## Using the library

The library uses an enum to choose between test and production environments.  It provides both a builder and a factory.  The builder used the factory internally.

The builder is the easy way to set up a validator.  The application must provide the environment, it may override certificates and policies, and may change the default in-memory CRL handling to disk-based caching.

TODO examples

The factory is the hard way to set up a validator.  The application must provide the environment, the certificates and policies to use, and the CRL handling.

TODO examples




