#!/usr/bin/python3.4

import io
import sys
import binascii

sys.path.insert(0, "/usr/local/lib/python3.4/dist-packages/")

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

def _str_from_X509Name(x509_name):
    short_names = {
        'commonName': 'CN',
        'countryName': 'C',
        'organizationName': 'O',
        'organizationalUnitName': 'OU'
    }

    name_str = ""
    for attr in x509_name:
        if len(name_str) > 0:
            name_str += ", "
        name_str += "{0}={1}".format(short_names[attr.oid._name], attr.value)
    return name_str

# cert_path = '/home/vtarasov/projects/sc/github/KMIP/OpenKMIP/apache/httpd-2.4.18/conf/ssl/server-cert.pem'
cert_path = '/home/vtarasov/projects/sc/github/KMIP/OpenKMIP/apache/kmip-pki/httpd-2.4.18/build/conf/ssl/server-cert.pem'

fh = open(cert_path, 'rb')
cert_pem = fh.read()
fh.close()
cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
cert_serial = hex(cert.serial)[2:].upper()
cert_fingerprint = binascii.hexlify(
    cert.fingerprint(hashes.SHA256())
).decode('utf-8').upper()

print ("Content-type:text/html\r\n\r\n")
print ('<html>')
print ('<head>')
print ('<title>KMIP POC: Renewal of apache certificate</title>')
print ('</head>')
print ('<body>')
print ('<h2>Current SSL certificate</h2>')
print ('<p>Subject: {0}</p>'.format(_str_from_X509Name(cert.subject)))
print ('<p>Serial: {0}</p>'.format(cert_serial))
print ('<p>Fingerprint: {0}</p>'.format(cert_fingerprint))
print ('<p>Not valid before: {0}</p>'.format(cert.not_valid_before))
print ('<p>Not valid after: {0}</p>'.format(cert.not_valid_after))
print ('</body>')
print ('</html>')
