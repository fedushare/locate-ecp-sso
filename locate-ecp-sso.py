#!/usr/bin/env python3

# Parse federation metadata to locate the ECP single sign on service
# of an IDP associated with a given scope.

import argparse
import sys
from xml.etree import ElementTree


def _strip_whitespace(s):
    return "".join(s.split())


class IDPDescriptor:

    DISPLAY_NAME_XPATH = _strip_whitespace("""
        {urn:oasis:names:tc:SAML:2.0:metadata}Extensions/
        {urn:oasis:names:tc:SAML:metadata:ui}UIInfo/
        {urn:oasis:names:tc:SAML:metadata:ui}DisplayName
        """)

    SSO_XPATH = "{urn:oasis:names:tc:SAML:2.0:metadata}SingleSignOnService"

    ECP_BINDING = "urn:oasis:names:tc:SAML:2.0:bindings:SOAP"

    def __init__(self, idp_element):
        self._idp_element = idp_element

    def display_name(self):
        display_name_element = self._idp_element.find(self.DISPLAY_NAME_XPATH)
        try:
            return display_name_element.text
        except AttributeError:
            return None

    def ecp_sso_locations(self):
        return [s.get("Location") for s in self._idp_element.findall(self.SSO_XPATH) if s.get("Binding") == self.ECP_BINDING]


class FederationMetadata:

    IDP_XPATH = _strip_whitespace("""
        {urn:oasis:names:tc:SAML:2.0:metadata}EntityDescriptor/
        {urn:oasis:names:tc:SAML:2.0:metadata}IDPSSODescriptor
        """)

    SCOPE_XPATH = _strip_whitespace("""
        {urn:oasis:names:tc:SAML:2.0:metadata}Extensions/
        {urn:mace:shibboleth:metadata:1.0}Scope
        """)

    def __init__(self, metadata):
        self._md_tree = ElementTree.fromstring(metadata)

    def _idp_matches_scope(self, idp_element, scope):
        return bool([s for s in idp_element.findall(self.SCOPE_XPATH) if s.text == scope])

    def idps_matching_scope(self, scope):
        return [IDPDescriptor(idpe) for idpe in self._md_tree.findall(self.IDP_XPATH) if self._idp_matches_scope(idpe, scope)]


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Locate an ECP SSO endpoint based on a user's scope")
    parser.add_argument("metadata_file",
                        help="Path to federation metadata file",
                        type=argparse.FileType("rb"))
    parser.add_argument("scope",
                        help="Scope of user's EPPN")
    parser.add_argument("--verify-with",
                        help="Path to certificate file to validate metadata file with",
                        metavar="certificate_file",
                        type=argparse.FileType("r"))

    args = parser.parse_args()

    md_data = args.metadata_file.read()

    if args.verify_with:

        from cryptography.exceptions import InvalidSignature
        from signxml import xmldsig

        cert = args.verify_with.read()
        try:
            xmldsig(md_data).verify(x509_cert=cert)
        except InvalidSignature:
            print("Metadata signature invalid", file=sys.stderr)
            sys.exit(2)

    md = FederationMetadata(md_data)
    idps = md.idps_matching_scope(args.scope)

    print("Found %d IDP(s) matching scope '%s'" % (len(idps), args.scope), file=sys.stderr)
    for idp in idps:
        display_name = idp.display_name()
        print(display_name, file=sys.stderr)
        locations = idp.ecp_sso_locations()
        if locations:
            for url in locations:
                print("%s: %s" % (display_name, url))
        else:
            print("No ECP SSO service found", file=sys.stderr)
            sys.exit(1)
