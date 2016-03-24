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

from six.moves.configparser import SafeConfigParser

from kmip.core.config_helper import ConfigHelper

from kmip.services.server.kmip_threading_server import KMIPThreadingServer

FILE_PATH = os.path.dirname(os.path.abspath(__file__))


def run_server(host, port, certfile, keyfile, cert_reqs, ssl_version,
               ca_certs, do_handshake_on_connect, suppress_ragged_eofs):
    logger = logging.getLogger(__name__)

    server = KMIPThreadingServer(host=host, port=port, keyfile=keyfile,
                        certfile=certfile, cert_reqs=cert_reqs,
                        ssl_version=ssl_version, ca_certs=ca_certs,
                        do_handshake_on_connect=do_handshake_on_connect,
                        suppress_ragged_eofs=suppress_ragged_eofs)

    logger.info('Starting the KMIP Threading server')
    logger.info('host ' + (host if host is not None else 'None'))
    logger.info('port {0}'.format((port if port is not None else 'None')))
    logger.info('keyfile ' + (keyfile if keyfile is not None else 'None'))
    logger.info('certfile ' + (certfile if certfile is not None else 'None'))

    try:
        server.serve()
    except KeyboardInterrupt:
        logger.info('KeyboardInterrupt received while serving')
    except Exception as e:
        logger.info('Exception received while serving: {0}'.format(e))
    finally:
        server.close()

    logger.info('Shutting down KMIP server')


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

if __name__ == '__main__':
    conf = SafeConfigParser()
    parser = build_cli_parser(conf, None)
    opts, args = parser.parse_args(sys.argv[1:])

    if opts.conf_file is not None and opts.conf_section is not None:
        if conf.read(opts.conf_file):
            parser = build_cli_parser(conf, opts.conf_section)
            opts, args = parser.parse_args(sys.argv[1:])

    run_server(host=opts.host,
               port=opts.port,
               certfile=opts.certfile,
               keyfile=opts.keyfile,
               cert_reqs=opts.cert_reqs,
               ssl_version=opts.ssl_version,
               ca_certs=opts.ca_certs,
               do_handshake_on_connect=opts.do_handshake_on_connect,
               suppress_ragged_eofs=opts.suppress_ragged_eofs)
