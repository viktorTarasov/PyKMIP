# Copyright (c) 2016 The Johns Hopkins University/Applied Physics Laboratory
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import os
import re
import logging
import logging.config
import zeep
from zeep import Client
from zeep.transports import Transport

from OpenSSL import crypto

from kmip.services.server.pki import api
from kmip.core.config_helper import ConfigHelper
from kmip.pie.exceptions import PKIConnectionFailure, PKIServiceError
from kmip.services.server.crypto.engine import CryptographyEngine as ServerCryptographyEngine

'''
logging.config.dictConfig({
    'version': 1,
    'formatters': {
        'verbose': {
            'format': '%(name)s: %(message)s'
        }
    },
    'handlers': {
        'console': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
    },
    'loggers': {
        'zeep.transports': {
            'level': 'DEBUG',
            'propagate': True,
            'handlers': ['console'],
        },
    }
})
'''

def kmip_update_request_message(message=None):
    print("kmip_update_request_message() called; message {0}".format(message))
    return message

class IDCAPKIEngine(api.PKIEngine):
    """
    IDCA PKI engine
    """

    def __init__(self, connector_api=None,
                 keyfile=None, certfile=None, ca_bundle=None,
                 enroll_profile=None,
                 profile_fields=None):
        """
        Construct a IDCAPKIEngine.
        """
        self.logger = logging.getLogger('kmip.server.pki')
        self.soap_client = None
        self.profile_fields = {}

        self.conf = ConfigHelper()
        self.connector_api = self.conf.get_valid_value(
                    connector_api,
                    'idca_pki',
                    'connector_api',
                    'otpkieeconnector-2.2.wsdl')
        self.keyfile = self.conf.get_valid_value(
                    keyfile,
                    'idca_pki',
                    'keyfile',
                    None)
        self.certfile = self.conf.get_valid_value(
                    certfile,
                    'idca_pki',
                    'certfile',
                    None)
        self.ca_bundle = self.conf.get_valid_value(
                    ca_bundle,
                    'idca_pki',
                    'ca_bundle',
                    None)
        self.enroll_profile = self.conf.get_valid_value(
                    enroll_profile,
                    'idca_pki',
                    'enroll_profile',
                    None)

    def parse_profile_fields(self):
        name_prefix = 'profile_field_'
        for item in self.conf.conf.items('pki'):
            if item[0].find(name_prefix) == 0:
                field_id = item[0][len(name_prefix):]
                self.profile_fields[field_id] = item[1]

    def validate(self):
        if self.enroll_profile is None:
            raise PKIServiceError("Enroll profile not defined")

        # version = self.soap_client.service.version('')
        # if version is None:
        #     raise PKIServiceError("'Get version' service failed")

        profile_exists = False
        profiles = self.soap_client.service.listCertificateProfiles('IDCA-Demo OpCA')
        print("Profiles: {0}, self-profile {1}".format(profiles, self.enroll_profile))
        for item in profiles:
            if item == self.enroll_profile:
                profile_exists = True
                break
        if not profile_exists:
            raise PKIServiceError("Profile '{0}' do not configured".format(self.enroll_profile))

    def connect(self):
        # transport = Transport(verify=True)
        transport = Transport()
        transport.session.verify = self.ca_bundle
        transport.session.cert = (
            self.certfile,
            self.keyfile)

        self.soap_client = Client(self.connector_api, transport=transport)
        if self.soap_client is None:
            raise PKIConnectionFailure("Failed to connect {0} service".format(
                self.connector_api))

        self.validate()
        self.parse_profile_fields()

    def enroll_profile_properties(self, profile=None):
        if self.soap_client is None:
            raise PKIConnectionFailure("No connection to PKI Web service")

        if profile is None:
            profile = self.enroll_profile

        profile_properties = self.soap_client.service.getCertificateProfileProperties(profile)
        return profile_properties


    def update_download_request_message(self, message=None, soap_block=None):
        if message == None:
            return message
        print("Update request message {0}".format(message))

        try:
            idx_start = message.index(b'<soap-env:Envelope')
            idx_end = message.index(b'</soap-env:Envelope>') + len(b'</soap-env:Envelope>')
            print("Update request Index {0}, {1}".format(idx_start, idx_end))
            message = message[0:idx_start] + soap_block.encode('ascii') + message[idx_end:-1]
            print("Update request message {0}".format(message))
        except ValueError:
            return message
        return message

    def retrieve_cert_authorities(self, certificate=None):
        download_template = """
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
               xmlns:ns0="http://www.idnomic.com/ngca/connector/ws/1_2"
               xmlns:ns1="http://www.idnomic.com/ngca/connector/1_2">
   <soap:Body>
      <ns0:download>
         <ns1:DownloadRequest xsi:type="ns1:X509DownloadRequestType"
                              xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <issuerDn>{0}</issuerDn>
            <withCaChain>true</withCaChain>
            <serialNumber>{1}</serialNumber>
         </ns1:DownloadRequest>
      </ns0:download>
   </soap:Body>
</soap:Envelope>
"""
        if self.soap_client is None:
            raise PKIConnectionFailure("No connection to PKI Web service")

        issuer_array = list()
        for tt in certificate['issuer'].get_components():
            issuer_array.append(tt[0].decode('ascii') + "=" + tt[1].decode('ascii'))
        issuer_str = ','.join(issuer_array)
        print("Signed cert issuer_str {0}".format(issuer_str))
        print("Signed cert serial {0}".format(certificate['serial number']))

        download_request = download_template.format(issuer_str, certificate['serial number'])
        print("Download request {0}".format(download_request))

        input_data = {
            'issuerDn': issuer_str,
            'withCaChain' : 'true',
            'serialNumber': "{0}".format(certificate['serial number'])
        }

        self.soap_client.transport.update_message_data = download_request
        self.soap_client.transport.update_message = self.update_download_request_message
        response = self.soap_client.service.download(input_data)
        self.soap_client.transport.update_message_data = None
        self.soap_client.transport.update_message = None
        print("Downloaded {0}".format(response))

        x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, response['authorities']['authority'][0])
        print("Serail {0}".format('%x' % x509.get_serial_number()))
        print("Subject {0}".format(x509.get_subject()))
        print("Issuer {0}".format(x509.get_issuer()))

        subject_array = list()
        for tt in x509.get_subject().get_components():
            subject_array.append(tt[0].decode('ascii') + "=" + tt[1].decode('ascii'))
        subject_str = ','.join(subject_array)

        ca_cert = {
            'serialNumber': '%x' % x509.get_serial_number(),
            'subject': subject_str,
            'subject commonName': x509.get_subject().commonName,
            'issuer': x509.get_issuer(),
            'issuer commonName': x509.get_issuer().commonName,
            'value': crypto.dump_certificate(crypto.FILETYPE_ASN1, x509)
        }

        ca_certs = list()
        ca_certs.append(ca_cert)
        print("CA certs {0}".format(ca_certs))
        return ca_certs

    def update_sign_request_message(self, message=None, template=None):
        request_pattern = b':EnrollmentRequest '
        if message == None:
            return message
        try:
            add_ns = 'xsi:type="nsXXX:X509EnrollmentRequestType" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
            message_str = message.decode('ascii')
            message_list = re.split('\W+', message_str)
            idx = message_list.index('EnrollmentRequest')
            updated_ns = add_ns.replace('nsXXX', message_list[idx-1])
            idx = message.index(request_pattern) + len(request_pattern)
            message = message[0:idx] + updated_ns.encode('ascii') + message[idx:-1]
        except ValueError:
            return message
        return message

    def sign_certificate_request(self, pkcs10=None):
        if self.soap_client is None:
            raise PKIConnectionFailure("No connection to PKI Web service")

        req = crypto.load_certificate_request(crypto.FILETYPE_ASN1, pkcs10)
        if req is None:
            raise ValueError("Invalid X509 request data")
        req_pem =  crypto.dump_certificate_request(crypto.FILETYPE_PEM, req)
        req_pem = req_pem.decode('utf-8')

        subject = req.get_subject()
        print("Subject CN: {0}".format(subject.commonName))
        crypto_tools = ServerCryptographyEngine()
        subject_alt_name = crypto_tools.PKCS10_get_subjectAltName(req)
        print("Subject Alt Name: {0}".format(subject_alt_name))

        profile_items = self.profile_fields
        props = self.enroll_profile_properties()

        req_pem_bis = req_pem.replace("-----BEGIN CERTIFICATE REQUEST-----", "").replace("-----END CERTIFICATE REQUEST-----","")
        req_pem_bis = req_pem_bis.replace("\n", '')
        enroll_input = {
            'certificateProfile': props['qName'],
            'certificateData' : {
                'param' : [
                    {
                        'name': 'dnsName',
                        'value': subject.commonName
                    },
                    {
                        'name': 'csr',
                        'value': req_pem_bis
                    }
                ]
            },
        }

        self.soap_client.transport.update_message = self.update_sign_request_message
        response = self.soap_client.service.enroll(enroll_input)
        self.soap_client.transport.update_message = None
        print("Response: {0}".format(response))

        x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, response['certificate'])
        print("Serail {0}".format('%x' % x509.get_serial_number()))
        return {
            'subject commonName': x509.get_subject().commonName,
            'issuer commonName': x509.get_issuer().commonName,
            'issuer': x509.get_issuer(),
            'serial number': '%x' % x509.get_serial_number(),
            'value': crypto.dump_certificate(crypto.FILETYPE_ASN1, x509)
        }
