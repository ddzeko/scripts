#!/usr/bin/env python3

import sys
import fileinput
import argparse
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtensionOID
import re
import binascii
from pprint import pprint
import json
from typing import Dict, Any, Union, List, IO
import warnings

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

def dumper(obj):
    try:
        return obj.toJSON()
    except:
        return obj.__dict__



def parse_certificate(cert_pem: str, file_name: str = None, cert_index: int = 1, 
                     check_date: datetime = None) -> Dict[str, Any]:
    """Parse a single PEM certificate and return certificate information.
    
    Args:
        cert_pem: PEM-encoded certificate string
        file_name: Source filename for the certificate
        cert_index: Index of certificate within the file
        check_date: Date to check expiry against (defaults to current UTC time)
    
    Returns:
        Dictionary containing certificate information
    """
    if check_date is None:
        check_date = datetime.now(timezone.utc)
    
    today = datetime.strftime(check_date, "%Y-%m-%d")
    
    pem_data = cert_pem.encode('ascii')
    cert = x509.load_pem_x509_certificate(pem_data, default_backend())
    
    subject = cert.subject.rfc4514_string()
    issuer = cert.issuer.rfc4514_string()
    sha1 = binascii.hexlify(cert.fingerprint(hashes.SHA1())).decode()
    serno = hex(cert.serial_number)
    sha256 = binascii.hexlify(cert.fingerprint(hashes.SHA256())).decode()
    
    # Extract SAN if present
    san_dns_names = None
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san_dns_names = san.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        pass

    # Extract Key Identifiers, if present
    subj_key_id = None
    try:
        subj_key_ext = cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        subj_key_id = subj_key_ext.value.digest
    except x509.ExtensionNotFound:
        pass
    
    auth_key_id = None
    try:
        auth_key_ext = cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
        auth_key_id = auth_key_ext.value.key_identifier
    except x509.ExtensionNotFound:
        pass

    # Calculate expiry information
    expiry = datetime.strftime(cert.not_valid_after_utc, "%Y-%m-%d")
    delta = cert.not_valid_after_utc - check_date
    
    is_expired = cert.not_valid_after_utc <= check_date
    expiring_soon = False
    days_remaining = None
    
    if not is_expired:
        days_remaining = delta.days
        ca_cert = is_ca(cert)
        if (ca_cert and delta.days < 730) or (not ca_cert and delta.days < 45):
            expiring_soon = True
    
    # Build certificate info dictionary
    cert_info = {
        'subjectDN': subject,
        'issuerDN': issuer,
        'serialNumber': serno,
        'expiry': expiry,
        'isExpired': is_expired,
        'expiringSoon': expiring_soon,
        'isCA': is_ca(cert),
        'sha1Fingerprint': sha1,
        'sha256Fingerprint': sha256
    }
    
    if file_name:
        cert_info['file'] = file_name
    if cert_index is not None:
        cert_info['index'] = cert_index
    if subj_key_id:
        cert_info['subjectKeyId'] = binascii.hexlify(subj_key_id).decode()
    if auth_key_id:
        cert_info['authorityKeyId'] = binascii.hexlify(auth_key_id).decode()
    if days_remaining is not None:
        cert_info['daysRemaining'] = days_remaining
    if san_dns_names:
        cert_info['SANs'] = list(san_dns_names)
    
    return cert_info


def analyze_pem_bundle(input_source: Union[str, List[str], IO], **kwargs) -> List[Dict[str, Any]]:
    """Analyze PEM certificate bundle(s) and return certificate information.
    
    Args:
        input_source: Can be:
            - String: filename or PEM content
            - List of strings: multiple filenames or PEM content blocks
            - File-like object: opened file handle
        **kwargs: Configuration options:
            - output_format: 'json', 'text', 'summary' (default: 'json')
            - include_pem: Include PEM data in output (default: False)
            - check_date: Date to check expiry against (default: current UTC)
            - ca_warning_days: Days threshold for CA cert warnings (default: 730)
            - cert_warning_days: Days threshold for cert warnings (default: 45)
            - debug: Enable debug output to stderr (default: False)
    
    Returns:
        List of dictionaries containing certificate information
    """
    output_format = kwargs.get('output_format', 'json')
    include_pem = kwargs.get('include_pem', False)
    check_date = kwargs.get('check_date', datetime.now(timezone.utc))
    debug = kwargs.get('debug', False)
    
    certificates = []
    
    # Handle different input types
    if isinstance(input_source, str):
        if input_source.startswith('-----BEGIN CERTIFICATE-----'):
            # Direct PEM content
            input_lines = input_source.splitlines()
            file_name = None
        else:
            # Filename
            with open(input_source, 'r') as f:
                input_lines = f.readlines()
            file_name = input_source
        
        certificates.extend(_parse_pem_lines(input_lines, file_name, check_date, include_pem, debug))
        
    elif isinstance(input_source, list):
        # Multiple files - process each separately
        for item in input_source:
            if item.startswith('-----BEGIN CERTIFICATE-----'):
                # Direct PEM content
                input_lines = item.splitlines()
                file_name = None
            else:
                # Filename
                with open(item, 'r') as f:
                    input_lines = f.readlines()
                file_name = item
            
            certificates.extend(_parse_pem_lines(input_lines, file_name, check_date, include_pem, debug))
    else:
        # File-like object
        input_lines = input_source.readlines()
        file_name = getattr(input_source, 'name', None)
        certificates.extend(_parse_pem_lines(input_lines, file_name, check_date, include_pem, debug))
    
    return certificates


def _parse_pem_lines(input_lines: List[str], file_name: str, check_date: datetime, include_pem: bool, debug: bool = False) -> List[Dict[str, Any]]:
    """Parse PEM lines and return certificate information."""
    certificates = []
    
    # Parse certificates from input
    state = 'start'
    cert_index = 0
    current_cert_lines = []
    
    for line in input_lines:
        line = line.strip() + '\n' if not line.endswith('\n') else line
        
        if state == 'start' and re.match(r'^-----BEGIN CERTIFICATE-----', line):
            current_cert_lines = [line]
            state = 'cert'
            cert_index += 1
        elif state == 'cert' and re.match(r'^-----END CERTIFICATE-----', line):
            current_cert_lines.append(line)
            cert_pem = ''.join(current_cert_lines)
            
            # Debug output
            if debug:
                debug_file = file_name or "<stdin>"
                print(f"DEBUG: Processing certificate {cert_index} from {debug_file}", file=sys.stderr)
            
            try:
                cert_info = parse_certificate(cert_pem, file_name, cert_index, check_date)
                if include_pem:
                    cert_info['pemData'] = cert_pem
                certificates.append(cert_info)
                
                # Additional debug info after successful parsing
                if debug:
                    subject_cn = "Unknown"
                    try:
                        # Extract CN from subject DN for cleaner debug output
                        subject_parts = cert_info['subjectDN'].split(',')
                        for part in subject_parts:
                            if part.strip().startswith('CN='):
                                subject_cn = part.strip()[3:]
                                break
                    except:
                        pass
                    print(f"DEBUG: Successfully parsed certificate {cert_index}: CN={subject_cn}", file=sys.stderr)
                    
            except Exception as e:
                # Handle certificate parsing errors
                if debug:
                    print(f"DEBUG: Error parsing certificate {cert_index}: {str(e)}", file=sys.stderr)
                    
                error_info = {
                    'file': file_name,
                    'index': cert_index,
                    'error': str(e),
                    'pemData': cert_pem if include_pem else None
                }
                certificates.append(error_info)
            
            state = 'start'
            current_cert_lines = []
        elif state == 'cert':
            current_cert_lines.append(line)
    
    return certificates


def format_output(certificates: List[Dict[str, Any]], output_format: str = 'json') -> str:
    """Format certificate analysis results according to specified format.
    
    Args:
        certificates: List of certificate info dictionaries
        output_format: 'json', 'text', or 'summary'
    
    Returns:
        Formatted output string
    """
    if output_format == 'json':
        return '\n'.join(json.dumps(cert, default=dumper) for cert in certificates)
    
    elif output_format == 'text':
        output_lines = []
        for cert in certificates:
            if 'error' in cert:
                output_lines.append(f"# ERROR in certificate {cert.get('index', '?')}: {cert['error']}")
                continue
                
            lines = [
                f"# Certificate {cert.get('index', '?')}:",
                f"# SubjectDN: {cert['subjectDN']}",
                f"#  IssuerDN: {cert['issuerDN']}",
                f"# Expiry: {cert['expiry']}",
                f"# SerialNo: {cert['serialNumber']}",
                f"# SHA1 Fingerprint: {cert['sha1Fingerprint']}",
                f"# SHA256 Fingerprint: {cert['sha256Fingerprint']}"
            ]
            
            if cert.get('subjectKeyId'):
                lines.append(f"# Subject Key ID: {cert['subjectKeyId']}")
            if cert.get('authorityKeyId'):
                lines.append(f"# Authority Key ID: {cert['authorityKeyId']}")
            
            if cert.get('SANs'):
                lines.append(f"# DNS/SAN(s): {cert['SANs']}")
            
            status = []
            if cert.get('isExpired'):
                status.append('EXPIRED')
            elif cert.get('expiringSoon'):
                status.append(f"EXPIRES SOON ({cert.get('daysRemaining', '?')} days remaining)")
            else:
                status.append(f"{cert.get('daysRemaining', '?')} days remaining")
            
            if cert.get('isCA'):
                status.append('CA Certificate')
            
            lines.append(f"# Status: {', '.join(status)}")
            lines.append('')  # Empty line between certificates
            
            output_lines.extend(lines)
        
        return '\n'.join(output_lines)
    
    elif output_format == 'summary':
        total = len(certificates)
        expired = sum(1 for c in certificates if c.get('isExpired', False))
        expiring_soon = sum(1 for c in certificates if c.get('expiringSoon', False))
        ca_certs = sum(1 for c in certificates if c.get('isCA', False))
        errors = sum(1 for c in certificates if 'error' in c)
        
        return f"""Certificate Bundle Analysis Summary:
- Total certificates: {total}
- CA certificates: {ca_certs}
- Expired certificates: {expired}
- Certificates expiring soon: {expiring_soon}
- Parse errors: {errors}"""
    
    else:
        raise ValueError(f"Unknown output format: {output_format}")


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description='Analyze SSL/TLS certificates in PEM format',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  %(prog)s cert.pem
  %(prog)s --format text cert1.pem cert2.pem
  %(prog)s --format summary --include-pem bundle.pem
  cat cert.pem | %(prog)s"""
    )
    
    # the below parser just does not work, Claude - let's figure out what's wrong here below:
    
    parser.add_argument(
        'files', nargs='*', 
        help='PEM certificate files to analyze (default: read from stdin)'
    )
    parser.add_argument(
        '-f', '--format', choices=['json', 'text', 'summary'],
        default='json', help='Output format (default: json)'
    )
    parser.add_argument(
        '--include-pem', action='store_true',
        help='Include PEM data in output'
    )
    parser.add_argument(
        '--ca-warning-days', type=int, default=730,
        help='Days threshold for CA certificate warnings (default: 730)'
    )
    parser.add_argument(
        '--cert-warning-days', type=int, default=45,
        help='Days threshold for certificate warnings (default: 45)'
    )
    parser.add_argument(
        '--debug', action='store_true',
        help='Enable debug output to stderr showing certificate processing'
    )
    parser.add_argument(
        '--show-warnings', action='store_true',
        help='Show cryptography library warnings (default: suppressed)'
    )
    
    args = parser.parse_args()
    
    # Control warning suppression based on command line flag
    if not args.show_warnings:
        # Suppress cryptography warnings about RDN attribute length exceeding X.509 limits
        warnings.filterwarnings('ignore', message=r"Attribute's length must be >= 1 and <= 64, but it was \d+", category=UserWarning)
    
    try:
        if args.files:
            # Analyze specified files
            certificates = analyze_pem_bundle(
                args.files,
                output_format=args.format,
                include_pem=args.include_pem,
                ca_warning_days=args.ca_warning_days,
                cert_warning_days=args.cert_warning_days,
                debug=args.debug
            )
        else:
            # Read from stdin
            certificates = analyze_pem_bundle(
                sys.stdin,
                output_format=args.format,
                include_pem=args.include_pem,
                ca_warning_days=args.ca_warning_days,
                cert_warning_days=args.cert_warning_days,
                debug=args.debug
            )
        
        output = format_output(certificates, args.format)
        print(output)
        
        # Exit with error code if any certificates are expired or expiring soon
        if any(c.get('isExpired') or c.get('expiringSoon') for c in certificates):
            sys.exit(1)
            
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(2)


if __name__ == '__main__':
    main()
