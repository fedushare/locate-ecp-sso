Using the [mech_saml_ec](https://github.com/fedushare/mech_saml_ec) library with SSH
requires the user set an environment variable containing their organization's IDP's
ECP endpoint.

This script parses [InCommon metadata](https://www.incommon.org/federation/metadata.html)
to find ECP single sign on services for IDPs associated with a given scope. This should
allow most users at InCommon member organizations to determine their IDP's ECP endpoint
from their organization's domain name.
