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

import logging
import logging.config
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

class PKIEngine(api.PKIEngine):
    """
    A PKI engine
    """

    def __init__(self, connector_api=None,
                 keyfile=None, certfile=None, ca_bundle=None,
                 enroll_profile=None,
                 profile_fields=None):
        """
        Construct a PKIEngine.
        """
        self.logger = logging.getLogger('kmip.server.pki')
        self.soap_client = None
        self.profile_fields = {}

        self.conf = ConfigHelper()
        self.connector_api = self.conf.get_valid_value(
                    connector_api,
                    'pki',
                    'connector_api',
                    'otpkieeconnector-2.2.wsdl')
        self.keyfile = self.conf.get_valid_value(
                    keyfile,
                    'pki',
                    'keyfile',
                    None)
        self.certfile = self.conf.get_valid_value(
                    certfile,
                    'pki',
                    'certfile',
                    None)
        self.ca_bundle = self.conf.get_valid_value(
                    ca_bundle,
                    'pki',
                    'ca_bundle',
                    None)
        self.enroll_profile = self.conf.get_valid_value(
                    enroll_profile,
                    'pki',
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

        version = self.soap_client.service.version('')
        if version is None:
            raise PKIServiceError("'Get version' service failed")

        profile_exists = False
        profiles = self.soap_client.service.list_profiles('')
        for item in profiles['Message']['Array']['Item']:
            if item['Value'] == self.enroll_profile:
                profile_exists = True
                break
        if not profile_exists:
            raise PKIServiceError("Profile '{0}' do not configured".format(self.enroll_profile))

    def connect(self):
        transport = Transport(verify=True)
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

        profile_properties_input = {
            'Message': {
                'Array': {
                    'Item': [
                        {
                            'key': '0',
                            'Value': profile
                        }
                    ]
                }
            }
        }

        profile_properties = self.soap_client.service.profile_properties(profile_properties_input)
        return profile_properties

    def retrieve_cert_authorities(self, certificate=None):
        if self.soap_client is None:
            raise PKIConnectionFailure("No connection to PKI Web service")

        response = self.soap_client.service.retrieve_cert_authorities({ 'Message': {} })
        ca_certs = list()

        for item in response['Message']['HashTable']['Item']:
            ca_cert = {
                'name': item['key']
            }
            for hash_item in item['HashTable']['Item']:
                if hash_item['key'] == 'certificate':
                    ca_cert['value'] = crypto.dump_certificate(crypto.FILETYPE_ASN1,
                        crypto.load_certificate(crypto.FILETYPE_PEM, hash_item['Value']))
                if hash_item['key'] == 'dn':
                    ca_cert['subject'] = hash_item['Value']

            ca_certs.append(ca_cert)

        return ca_certs

    def sign_certificate_request(self, pkcs10=None):
        if self.soap_client is None:
            raise PKIConnectionFailure("No connection to PKI Web service")

        req = crypto.load_certificate_request(crypto.FILETYPE_ASN1, pkcs10)
        if req is None:
            raise ValueError("Invalid X509 request data")
        req_pem =  crypto.dump_certificate_request(crypto.FILETYPE_PEM, req)
        req_pem = req_pem.decode('utf-8')

        subject = req.get_subject()
        crypto_tools = ServerCryptographyEngine()
        subject_alt_name = crypto_tools.PKCS10_get_subjectAltName(req)

        profile_items = self.profile_fields
        props = self.enroll_profile_properties()
        items = props['Message']['HashTable']['Item']
        for item in items:
            if item['key'] == 'fields':
                fields = item['Array']['Item']
                break;
        for field in fields:
            field_items = field['HashTable']['Item']
            field_mandatory = True
            field_id = None
            for field_item in field_items:
                if field_item['key'] == 'optional':
                    field_mandatory = field_item['Value'] == '0'
                if field_item['key'] == 'id':
                    field_id = field_item['Value'][:-1]

            if field_id.find('subjectAltName') == 0:
                alt_name_type = field_id[len('subjectAltName'):]
                crypto_tools = ServerCryptographyEngine()
                subject_alt_name = crypto_tools.PKCS10_get_subjectAltName(req, alt_name_type)
                if subject_alt_name is not None:
                    profile_items[field_id] = subject_alt_name

            if field_mandatory and field_id is not None:
                if not field_id in profile_items:
                    profile_items[field_id] = getattr(subject, field_id)

        soap_items = list()
        for key in profile_items:
            soap_items.append({
                'key': key + '1',
                'Value': profile_items[key]
            })
        soap_items.append({
            'key': 'pkcs10',
            'Value': req_pem
        })

        enroll_input= {
            'Message': {
                'Array': {
                    'Item': [
                        {
                            'key': '0',
                            'Value': self.enroll_profile
                        },
                        {
                            'key': '1',
                            'HashTable': { 'Item': soap_items }
                        }
                    ]
                }
            }
        }

        response = self.soap_client.service.enroll(enroll_input)
        cert_items = response['Message']['Array']['Item']
        for item in cert_items:
            if item['Value'] is not None:
                x509 = crypto.load_certificate(crypto.FILETYPE_PEM, item['Value'])
                return {
                    'subject commonName': x509.get_subject().commonName,
                    'issuer commonName': x509.get_issuer().commonName,
                    'value': crypto.dump_certificate(crypto.FILETYPE_ASN1, x509)
                }
