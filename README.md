# locate-ecp-sso

Using the [mech_saml_ec](https://github.com/fedushare/mech_saml_ec) library with SSH
requires the user set an environment variable containing their organization's IDP's
ECP endpoint.

This script parses [InCommon metadata](https://www.incommon.org/federation/metadata.html)
to find ECP single sign on services for IDPs associated with a given scope. This should
allow most users at InCommon member organizations to determine their IDP's ECP endpoint
from their organization's domain name.

## Usage

```
usage: locate-ecp-sso.py [-h] [--verify-with incommon-cert]
                         metadata_file scope

Locate an ECP SSO endpoint based on a user's scope

positional arguments:
  metadata_file         Path to InCommon metadata file
  scope                 Scope of user's EPPN

optional arguments:
  -h, --help            show this help message and exit
  --verify-with certificate_file
                        Path to certificate file to verify metadata file with
```
