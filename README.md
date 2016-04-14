# locate-ecp-sso

Using the [mech_saml_ec](https://github.com/fedushare/mech_saml_ec) library with SSH
requires the user set an environment variable containing their organization's IDP's
ECP endpoint.

This script parses a federation's metadata to find ECP single sign on services for
IDPs associated with a given scope. This should allow most users at federation member
organizations to determine their IDP's ECP endpoint from their organization's domain name.

## Usage

```
usage: locate-ecp-sso.py [-h] [--verify-with certificate_file]
                         metadata_file scope

Locate an ECP SSO endpoint based on a user's scope

positional arguments:
  metadata_file         Path to federation metadata file
  scope                 Scope of user's EPPN

optional arguments:
  -h, --help            show this help message and exit
  --verify-with certificate_file
                        Path to certificate file to verify metadata file with
```

## References

* [InCommon metadata consumption](https://spaces.internet2.edu/display/InCFederation/Metadata+Consumption)
* [InCommon signing certificate](https://spaces.internet2.edu/display/InCFederation/Metadata+Signing+Certificate)
