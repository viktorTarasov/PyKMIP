# Copyright (c) 2014 The Johns Hopkins University/Applied Physics Laboratory
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
import optparse
import os
import sys
import time
import datetime
import binascii
from six.moves.configparser import SafeConfigParser

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

from sqlalchemy import desc

from kmip.core.enums import LinkType as EnumLinkType
from kmip.core.enums import AttributeType as EnumAttributeType
from kmip.core.enums import PutFunction as EnumPutFunction
from kmip.core.enums import CertificateTypeEnum
from kmip.core.attributes import Link, CertificateType, CryptographicAlgorithm, CryptographicLength

from kmip.core.config_helper import ConfigHelper

from kmip.demos import utils

from kmip.services.server.engine import KmipEngine

from kmip.pie.objects import ManagedObject, X509Certificate, PublicKey, PrivateKey
from kmip.pie.client import ProxyKmipClient
from kmip.pie import factory

from kmip.core.misc import PutFunctionType, CertificateValue, KeyFormatType

from kmip.core.secrets import Certificate as SecretCertificate
from kmip.core.secrets import PrivateKey as SecretPrivateKey

from kmip.core.objects import KeyBlock, KeyValue, KeyMaterial



FILE_PATH = os.path.dirname(os.path.abspath(__file__))


def build_cli_parser(conf, section):
    parser = optparse.OptionParser(usage="%prog [options]",
                                   description="Run KMIP Server")
    defaults = {
            'host': '127.0.0.1',
            'port': 5696,
            'keyfile': os.path.normpath(os.path.join(FILE_PATH,
                                        '../utils/certs/server.key')),
            'certfile': os.path.normpath(os.path.join(FILE_PATH,
                                         '../utils/certs/server.crt')),
            'cert_reqs': 'CERT_NONE',
            'ssl_version': 'PROTOCOL_SSLv23',
            'ca_certs': ConfigHelper.NONE_VALUE,
            'do_handshake_on_connect': "True",
            'suppress_ragged_eofs': "True"
    }
    if (section and isinstance(conf, SafeConfigParser)):
        for key in defaults:
            if conf.has_option(section, key):
                defaults[key] = conf.get(section, key)

    parser.add_option("-n", "--host", action="store", default=defaults['host'],
                      dest="host",
                      help="Hostname/IP address of platform running the KMIP "
                      "server (e.g., localhost, 127.0.0.1)")
    parser.add_option("-p", "--port", action="store", default=defaults['port'],
                      dest="port", help="Port number for KMIP services")
    parser.add_option("-k", "--keyfile", action="store",
                      default=defaults['keyfile'], dest="keyfile")
    parser.add_option("-c", "--certfile", action="store",
                      default=defaults['certfile'], dest="certfile")
    parser.add_option("-r", "--cert_reqs", action="store",
                      default=defaults['cert_reqs'], dest="cert_reqs")
    parser.add_option("-s", "--ssl_version", action="store",
                      default=defaults['ssl_version'], dest="ssl_version")
    parser.add_option("-a", "--ca_certs", action="store",
                      default=defaults['ca_certs'], dest="ca_certs")
    parser.add_option("-d", "--do_handshake_on_connect", action="store",
                      default=defaults['do_handshake_on_connect'],
                      dest="do_handshake_on_connect")
    parser.add_option("-e", "--suppress_ragged_eofs", action="store",
                      default=defaults['suppress_ragged_eofs'],
                      dest="suppress_ragged_eofs")

    parser.add_option("", "--config-file", action="store",
                      default=None, dest="conf_file")
    parser.add_option("", "--config-section", action="store",
                      default=None, dest="conf_section")
    parser.add_option("", "--db-url", action="store",
                      default=None, dest="db_url")

    return parser


def scan_db(opts, session):
    print("{0}: scan DB".format(time.ctime()))
    link_type_certificate = Link.LinkType(EnumLinkType.CERTIFICATE_LINK)
    link_type_pubkey = Link.LinkType(EnumLinkType.PUBLIC_KEY_LINK)
    link_type_prvkey = Link.LinkType(EnumLinkType.PRIVATE_KEY_LINK)
    link_type_replaced_obj = Link.LinkType(EnumLinkType.REPLACED_OBJECT_LINK)

    sql_order = desc(X509Certificate.unique_identifier)
    for cert_obj in session.query(X509Certificate).order_by(sql_order):
        if cert_obj.contact_information is None:
            continue
        if cert_obj.fresh == False:
            continue

        linked_pubkey_uid = None
        linked_prvkey_uid = None
        replaced_pubkey_uid = None
        replaced_prvkey_uid = None
        replaced_cert_uid = None
        for clink in cert_obj.links:
            if clink.link_type == link_type_certificate:
                ca_cert_obj = session.query(X509Certificate).filter(
                    ManagedObject.unique_identifier == clink.linked_oid.value
                ).one()
            elif clink.link_type == link_type_pubkey:
                pubkey_obj = session.query(PublicKey).filter(
                    ManagedObject.unique_identifier == clink.linked_oid.value
                ).one()
                linked_pubkey_uid = str(pubkey_obj.unique_identifier)

                for ln in pubkey_obj.links:
                    if ln.link_type == link_type_prvkey:
                        linked_prvkey_uid = str(ln.linked_oid.value)

                    if ln.link_type == link_type_replaced_obj:
                        replaced_pubkey_uid = str(ln.linked_oid.value)
                        replaced_pubkey_obj = session.query(PublicKey).filter(
                            ManagedObject.unique_identifier == ln.linked_oid.value
                        ).one()

                        for rln in replaced_pubkey_obj.links:
                            if rln.link_type == link_type_certificate:
                                replaced_cert_uid = str(rln.linked_oid.value)
                            if rln.link_type == link_type_prvkey:
                                replaced_prvkey_uid = str(rln.linked_oid.value)

        if linked_pubkey_uid is None or linked_prvkey_uid is None:
            continue

        contact_information = cert_obj.contact_information
        prvkey_obj = session.query(PrivateKey).filter(
            ManagedObject.unique_identifier == linked_prvkey_uid
        ).one()

        if replaced_pubkey_uid is not None:
                replaced_pubkey_obj = session.query(PublicKey).filter(
                    ManagedObject.unique_identifier == replaced_pubkey_uid
                ).one()
                for ln in replaced_pubkey_obj.links:
                    if ln.link_type == link_type_prvkey:
                        replaced_prvkey_oid = str(ln.linked_oid.value)
                    if ln.link_type == link_type_certificate:
                        replaced_certificate_oid = str(ln.linked_oid.value)

        cert_x509 = x509.load_der_x509_certificate(cert_obj.value, default_backend())
        cert_fingerprint = binascii.hexlify(
            cert_x509.fingerprint(hashes.SHA1())).decode('utf-8').lower()
        cert_fingerprint = cert_fingerprint[0:8]

        attribute_factory = factory.AttributeFactory()
        fingerprint_attr = attribute_factory.create_attribute(
            "x-certificate-fingerprint",
            cert_fingerprint)

        cert_data = {
            'data': SecretCertificate(
                certificate_type=CertificateTypeEnum.X_509,
                certificate_value=cert_obj.value
            ),
            'put function': PutFunctionType(EnumPutFunction.NEW),
            'uid': cert_obj.unique_identifier,
            'replaced uid': replaced_cert_uid,
            'attributes': [
                fingerprint_attr,
                attribute_factory.create_attribute(
                    "x-certificate-role",
                    "server-cert")
            ]
        }
        prvkey_data = {
            'data': SecretPrivateKey(
                KeyBlock(
                    key_format_type = KeyFormatType(prvkey_obj.key_format_type),
                    key_value = KeyValue(
                        key_material = KeyMaterial(
                            prvkey_obj.value
                        )
                    ),
                    cryptographic_algorithm = CryptographicAlgorithm(
                        prvkey_obj.cryptographic_algorithm),
                    cryptographic_length = CryptographicLength(
                        prvkey_obj.cryptographic_length)
                )
            ),
            'put function': PutFunctionType(EnumPutFunction.NEW),
            'uid': prvkey_obj.unique_identifier,
            'replaced uid': replaced_prvkey_uid,
            'attributes': [
                fingerprint_attr
            ]
        }
        ca_cert_data = {
            'data': SecretCertificate(
                certificate_type=CertificateTypeEnum.X_509,
                certificate_value=ca_cert_obj.value
            ),
            'put function': PutFunctionType(EnumPutFunction.NEW),
            'uid': ca_cert_obj.unique_identifier,
            'replaced uid': None,
            'attributes': [
                fingerprint_attr,
                attribute_factory.create_attribute(
                    "x-certificate-role",
                    "server-cacert")
            ]
        }

        with ProxyKmipClient(config=opts.conf_section) as client:
            try:
                client.put(contact_information, [cert_data, prvkey_data, ca_cert_data])
            except Exception as e:
                logger.error(e)

        cert_obj.fresh = False
        prvkey_obj.fresh = False
        pubkey_obj.fresh = False
        session.commit()


if __name__ == '__main__':
    conf = SafeConfigParser()
    parser = build_cli_parser(conf, None)
    opts, args = parser.parse_args(sys.argv[1:])

    if opts.conf_file is not None and opts.conf_section is not None:
        if conf.read(opts.conf_file):
            print("Read conf file {0}, section {1}".format(opts.conf_file, opts.conf_section))
            parser = build_cli_parser(conf, opts.conf_section)
            opts, args = parser.parse_args(sys.argv[1:])

    logger = utils.build_console_logger(logging.DEBUG)
    logstream = logging.StreamHandler()
    logstream.setLevel(logging.DEBUG)
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    logstream.setFormatter(formatter)

    if opts.db_url is None:
        opts.db_url = 'sqlite:////tmp/kmip-sql.db'

    engine = KmipEngine(db_url=opts.db_url, logstream=logstream)
    session = engine._data_store_session_factory()

    while True:
        scan_db(opts, session)
        time.sleep(5)
