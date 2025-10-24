#!/usr/bin/env python3

import sys
import fileinput
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtensionOID
import re
import binascii
from pprint import pprint

# assert (len(sys.argv) == 2), "Need an argument: PEM file to analyze -- provide a filename!"

state = 'start'
cert_count = 0
today_dt = datetime.now()
today = datetime.strftime(today_dt, "%Y-%m-%d")

def is_ca(certificate):
    # TODO: test self signed if no extensions found
    extensions = certificate.extensions
    try:
        return extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value.ca
    except x509.ExtensionNotFound:
        try:
            return extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value.key_cert_sign
        except x509.ExtensionNotFound:
            pass
    return False 


for line in fileinput.input():
# with open(sys.argv[1], "r") as in_file:
#    for line in in_file:
    if True:
        if state == 'start' and re.match(r'^-----BEGIN CERTIFICATE-----', line):
            certificate = line
            state = 'cert'
            cert_count += 1            
        elif state == 'cert' and re.match(r'^-----END CERTIFICATE-----', line):
            certificate += line
            pem_data = certificate.encode('ascii')
            cert = x509.load_pem_x509_certificate(pem_data, default_backend())
            subject = cert.subject.rfc4514_string()
            issuer = cert.issuer.rfc4514_string()
            sha1 = binascii.hexlify(cert.fingerprint(hashes.SHA1())).decode()
            serno = hex(cert.serial_number)
            sha256 = binascii.hexlify(cert.fingerprint(hashes.SHA256())).decode()
            try:
                san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            except x509.ExtensionNotFound:
                san = None
                pass            
            expiry = datetime.strftime(cert.not_valid_after, "%Y-%m-%d")            
            delta = cert.not_valid_after - today_dt
            if cert.not_valid_after > today_dt: 
                expired = f"(got {delta.days} days remaining, checked on {today})"
                if is_ca(cert) and delta.days < 730 or delta.days < 45:
                    # if CA certificate -- warn if less than 2 years left
                    # if not a CA cert. -- warn if less than 45 days left
                    expired += " ***EXPIRES SOON***"
            else:
                expired = "EXPIRED"

            cert_info = [
                f'# SubjectDN: {subject}',
                f'#  IssuerDN: {issuer}',
                f'# Expiry: {expiry} {expired}',
                f'# SerialNo: {serno}',
                f'# SHA1 Fingerprint: {sha1}',
                f'# SHA256 Fingerprint: {sha256}'
            ]
            if (san):
                san_dns_names = san.value.get_values_for_type(x509.DNSName)
                cert_info.append(f'# DNS/SAN(s): {san_dns_names}')
            cert_info.append(certificate)
            print("\n".join(cert_info))
            
            state = 'start'
        else:
            if state == 'cert':
                certificate += line

#    if cert_count > 0:
#        print(f"# Total {cert_count} certificates analyzed")
