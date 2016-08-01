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
import datetime
from six.moves.configparser import SafeConfigParser

from cryptography import x509
from cryptography.hazmat.backends import default_backend

from sqlalchemy import desc

from kmip.core.enums import LinkType as EnumLinkType
from kmip.core.enums import AttributeType as EnumAttributeType
from kmip.core.attributes import Link
from kmip.core.config_helper import ConfigHelper

from kmip.demos import utils

from kmip.services.server.engine import KmipEngine

from kmip.pie.objects import ManagedObject, X509Certificate, PublicKey
from kmip.pie.client import ProxyKmipClient


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

    return parser


def notify_expires(contact_information,
                   delta,
                   logger=None,
                   certificate_oid=None,
                   private_key_oid=None,
                   public_key_oid=None):
    if logger is None:
        logger = utils.build_console_logger(logging.DEBUG)

    last_change_date = {
        'attribute_type': EnumAttributeType.LAST_CHANGE_DATE,
        'attribute_value': int(datetime.datetime.now().timestamp())
    }
    custom_expires_in = {
        'attribute_type': "x-expires-in",
        'attribute_value': str(delta)
    }
    attributes = (last_change_date, custom_expires_in)
    oids = [certificate_oid, private_key_oid, public_key_oid]

    with ProxyKmipClient() as client:
        try:
            client.notify("expiration",
                          contact_information,
                          oids,
                          attributes)
        except Exception as e:
            logger.error(e)

if __name__ == '__main__':
    conf = SafeConfigParser()
    parser = build_cli_parser(conf, None)
    opts, args = parser.parse_args(sys.argv[1:])

    if opts.conf_file is not None and opts.conf_section is not None:
        if conf.read(opts.conf_file):
            parser = build_cli_parser(conf, opts.conf_section)
            opts, args = parser.parse_args(sys.argv[1:])

    logstream = logging.StreamHandler()
    logstream.setLevel(logging.DEBUG)
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    logstream.setFormatter(formatter)

    # engine = KmipEngine(db_url='sqlite:///:memory:', logstream=logstream)
    engine = KmipEngine(db_url='sqlite:////tmp/kmip-sql.db',
                        logstream=logstream)

    session = engine._data_store_session_factory()

    link_type_pubkey = Link.LinkType(EnumLinkType.PUBLIC_KEY_LINK)
    link_type_prvkey = Link.LinkType(EnumLinkType.PRIVATE_KEY_LINK)

    order = desc(X509Certificate.unique_identifier)
    for cert_obj in session.query(X509Certificate).order_by(order):
        certificate_oid = str(cert_obj.unique_identifier)
        cert = x509.load_der_x509_certificate(cert_obj.value,
                                              default_backend())
        delta = cert.not_valid_after - datetime.datetime.now()

        log_string = "Cert {0}; ".format(cert_obj.unique_identifier)
        if delta.days > 0:
            log_string += "expires in {0} days".format(delta.days)
        else:
            log_string += "expired"
        engine._logger.warning(log_string)

        linked_pubkey_oid = None
        linked_prvkey_oid = None
        for clink in cert_obj.links:
            if clink.link_type == link_type_pubkey:
                pubkey_obj = session.query(PublicKey).filter(
                    ManagedObject.unique_identifier == clink.linked_oid.value
                ).one()
                linked_pubkey_oid = str(pubkey_obj.unique_identifier)

                for pubkey_link in pubkey_obj.links:
                    if pubkey_link.link_type == link_type_prvkey:
                        linked_prvkey_oid = str(pubkey_link.linked_oid.value)

        if linked_pubkey_oid is None or linked_prvkey_oid is None:
            continue
        contact_information = cert_obj.contact_information.value

        notify_expires(contact_information,
                       delta.days,
                       certificate_oid=certificate_oid,
                       private_key_oid=linked_prvkey_oid,
                       public_key_oid=linked_pubkey_oid)
