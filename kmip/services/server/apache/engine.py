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

import io
import os
import binascii
import logging
import logging.config
from zeep import Client
from zeep.transports import Transport

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_der_private_key

from kmip.core import enums
from kmip.core.config_helper import ConfigHelper
from kmip import services
from kmip.services.server.apache import api
from kmip.services.server.crypto.engine import CryptographyEngine as ServerCryptographyEngine

class ApacheServerEngine(api.ApacheServerEngine):
    """
    Apache Server Config engine
    """

    def __init__(self, apachectl=None, config_path=None, ssl_link=None, contact_information=None, logstream=None):
        """
        Construct a ApacheServerEngine.
        """
        self.logger = logging.getLogger('kmip.server.apache.engine')
        if logstream is not None:
            self.logger.handlers = [logstream]
            self.logger.setLevel(logstream.level)

        self.dir_path = None
        self.conf = ConfigHelper()

        self.apachectl = self.conf.get_valid_value(
            apachectl,
            'apache',
            'apachectl',
            None)

        self.config_path = self.conf.get_valid_value(
            config_path,
            'apache',
            'config_path',
            None)

        self.ssl_link = self.conf.get_valid_value(
            ssl_link,
            'apache',
            'ssl_link',
            None)

        if contact_information is None:
            apache_client_host = self.conf.get_valid_value(
                None,
                'apache_client',
                'host',
                None)
            apache_client_port = self.conf.get_valid_value(
                None,
                'apache_client',
                'port',
                None)
            self.contact_information = "{0}:{1}".format(apache_client_host, apache_client_port)
        else:
            self.contact_information = contact_information

        self.crypto_engine = ServerCryptographyEngine()

        self.logger.info("ApacheServerEngine:\n\tapachectl {0}\n\tconfig_path {1}\n\tssl-link {2}\n\tcontact-information {3}".format(
            self.apachectl, self.config_path, self.ssl_link, self.contact_information))

    def _create_conf_dir_path(self, transaction_id):
        if transaction_id is None:
           raise exceptions.InvalidField("Transaction ID not defined")

        dir_path = self.config_path
        if not dir_path.endswith('/'):
            dir_path += '/'
        dir_path += 'ssl-' + str(transaction_id)

        if not os.path.exists(dir_path):
            os.makedirs(dir_path)

        self.dir_path = dir_path

    def _get_current_ssl_certificate(self):
        cert_filename = "{0}/server-cert.pem".format(self.ssl_link)
        fh = open(cert_filename, 'rb')
        cert_pem = fh.read()
        fh.close()
        cert = x509.load_pem_x509_certificate(cert_pem, default_backend())

        cert_fingerprint = binascii.hexlify(
            cert.fingerprint(hashes.SHA256())
        ).decode('utf-8').upper()

        return {
            'x509': cert,
            'fingerprint': cert_fingerprint
        }

    def _str_from_X509Name(self, x509_name):
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

    def set_certificate_file(self, transaction_id=None, certificate=None, role=None):
        self.logger.info("tr-{0}: set Certificate({1}) serial:{2}".format(
            transaction_id,
            role,
            self.crypto_engine.X509_get_serial(certificate)))

        self._create_conf_dir_path(transaction_id)
        cert = x509.load_der_x509_certificate(certificate, default_backend())
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        filename = "{0}/{1}.pem".format(self.dir_path, role)
        fh = open(filename, 'wb')
        fh.write(cert_pem)
        fh.close()

    def set_private_key_file(self, transaction_id=None, private_key=None):
        self.logger.info("tr-{0}: set PrivateKey {1}".format(
            transaction_id,
            private_key.cryptographic_algorithm))

        self._create_conf_dir_path(transaction_id)
        key = load_der_private_key(
            private_key.key_value.key_material.value,
            password=None,
            backend=default_backend())
        key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        filename = self.dir_path + '/server-prvkey.pem'
        fh = open(filename, 'wb')
        fh.write(key_pem)
        fh.close()

    def restart_server(self, transaction_id=None):
        self.logger.info("tr-{0}: Restart server".format(transaction_id))
        self.logger.info("tr-{0}: dir-path {1}, config-path {2}".format(
            transaction_id, self.dir_path, self.config_path))

        tmp_link = self.ssl_link + '-tmp'
        try:
            os.symlink(self.dir_path, tmp_link)
            os.rename(tmp_link, self.ssl_link)
            os.system("{0} -k graceful".format(self.apachectl))
        except OSError as e:
            self.logger.error("{0}: restart server exception {1}".format(transaction_id, e))

    def rekey_key_pair(self, fingerprint, prvkey_uid):
        cert_data = self._get_current_ssl_certificate()

        if fingerprint != cert_data['fingerprint']:
            self.logger.error("Fingerprint {0} do not corresponds to current SSL sertificate".format(
                fingerprint))
            return None

        self.logger.info("ReKey {0} for certificate {1}".format(prvkey_uid, fingerprint))
        from kmip.pie import client as apache_client
        config = "client"
        result = {}
        with apache_client.ProxyKmipClient(config=config) as proxy_client:
            try:
                public_uid, private_uid = proxy_client.rekey_key_pair(str(prvkey_uid))
                self.logger.info("Successfull re-key\n\tPublicKey(uid={0})\n\tPrivateKey(uid={0})".format(
                    public_uid, private_uid))
                result['public key uid'] = str(public_uid)
                result['private key uid'] = str(private_uid)
            except Exception as e:
                self.logger.error(e)
        del apache_client

        return result

    def certify(self, fingerprint, pubkey_uid):
        self.logger.info("Certify pubkey {0}, replace cert {1}".format(pubkey_uid, fingerprint))
        cert_data = self._get_current_ssl_certificate()

        if fingerprint != cert_data['fingerprint']:
            return None

        ext = cert_data['x509'].extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        uri_value = ext.value.get_values_for_type(x509.UniformResourceIdentifier)
        subject_alt_name = "URI:{0}".format(uri_value[0])

        subject = self._str_from_X509Name(cert_data['x509'].subject)

        cn = cert_data['x509'].subject.get_attributes_for_oid(
            x509.oid.NameOID.COMMON_NAME)
        common_name = cn[0].value

        from kmip.pie import client as apache_client
        result = {}
        with apache_client.ProxyKmipClient(config='client') as proxy_client:
            try:
                result = proxy_client.certify(
                    str(pubkey_uid),
                    None, None,
                    subject,
                    subject_alt_name,
                    common_name,
                    self.contact_information
                )
                self.logger.info("Certify result {0}".format(result))
            except Exception as e:
                self.logger.error(e)
        del apache_client

        return result
