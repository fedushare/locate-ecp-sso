#!/usr/bin/env python3

# Parse InCommon metadata to locate the ECP single sign on service
# of an IDP associated with a given scope.

import sys
import xml.etree.ElementTree as ElementTree

IDP_XPATH = "{urn:oasis:names:tc:SAML:2.0:metadata}EntityDescriptor/{urn:oasis:names:tc:SAML:2.0:metadata}IDPSSODescriptor"
SCOPE_XPATH = "{urn:oasis:names:tc:SAML:2.0:metadata}Extensions/{urn:mace:shibboleth:metadata:1.0}Scope"
SSO_XPATH = "{urn:oasis:names:tc:SAML:2.0:metadata}SingleSignOnService"
DISPLAY_NAME_XPATH = "{urn:oasis:names:tc:SAML:2.0:metadata}Extensions/{urn:oasis:names:tc:SAML:metadata:ui}UIInfo/{urn:oasis:names:tc:SAML:metadata:ui}DisplayName"
ECP_BINDING = "urn:oasis:names:tc:SAML:2.0:bindings:SOAP"

def idp_matches_scope(idp, scope):
    return bool([s for s in idp.findall(SCOPE_XPATH) if s.text == scope])

def find_idps(tree, scope):
    return [idp for idp in tree.findall(IDP_XPATH) if idp_matches_scope(idp, scope)]

def idp_ecp_sso_locations(idp):
    return [s.get("Location") for s in idp.findall(SSO_XPATH) if s.get("Binding") == ECP_BINDING]

def idp_display_name(idp):
    try:
        return idp.find(DISPLAY_NAME_XPATH).text
    except:
        return None

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: ecp-discover.py metadata_path scope", file=sys.stderr)

    metadata_path = sys.argv[1]
    scope = sys.argv[2]
    tree = ElementTree.parse(metadata_path)
    idps = find_idps(tree, scope)
    print("Found", len(idps), "IDP(s) matching scope", scope)
    for idp in idps:
        print(idp_display_name(idp))
        locations = idp_ecp_sso_locations(idp)
        if locations:
            print("ECP SSO service locations:")
            for url in locations:
                print(url)
        else:
            print("No ECP SSO service found")

        print("")
