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
import threading
import socketserver
import ssl

from kmip.core.config_helper import ConfigHelper
from kmip.services.server.engine import KmipEngine
from kmip.services.server.session import KmipSession


class KMIPServerRequestHandler(socketserver.BaseRequestHandler):

    def handle(self):
        logstream = logging.StreamHandler()
        logstream.setLevel(logging.DEBUG)
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        logstream.setFormatter(formatter)

        title = threading.current_thread().name
        # engine = KmipEngine(db_url='sqlite:///:memory:')
        engine = KmipEngine(db_url='sqlite:////tmp/kmip-sql.db', 
			    logstream=logstream)
        session = KmipSession(engine,
                              self.request,
                              name="{} {}".format(title, self.client_address),
                              logstream=logstream)
        session.run()


class KMIPThreadingServer(object):

    class SSLTCPServer(socketserver.TCPServer):
        def __init__(self,
                     server_address,
                     RequestHandlerClass,
                     certfile,
                     keyfile,
                     ssl_version=ssl.PROTOCOL_TLSv1,
                     bind_and_activate=True):
            socketserver.TCPServer.__init__(self,
                                            server_address,
                                            RequestHandlerClass,
                                            bind_and_activate)
            self.certfile = certfile
            self.keyfile = keyfile
            self.ssl_version = ssl_version

        def get_request(self):
            socket, fromaddr = self.socket.accept()
            connection = ssl.wrap_socket(socket,
                                         server_side=True,
                                         certfile=self.certfile,
                                         keyfile=self.keyfile,
                                         ssl_version=self.ssl_version)
            return connection, fromaddr

    class ThreadingTCPServer(socketserver.ThreadingMixIn, SSLTCPServer):
        pass

    def __init__(self, host=None, port=None, keyfile=None, certfile=None,
                 cert_reqs=None, ssl_version=None, ca_certs=None,
                 do_handshake_on_connect=None, suppress_ragged_eofs=None):
        self.logger = logging.getLogger(__name__)

        print("KMIPServerAsync() open")
        self._set_variables(host, port, keyfile, certfile, cert_reqs,
                            ssl_version, ca_certs, do_handshake_on_connect,
                            suppress_ragged_eofs)

        self.server = KMIPThreadingServer.ThreadingTCPServer(
            (self.host, self.port),
            KMIPServerRequestHandler,
            self.certfile,
            self.keyfile)

    def close(self):
        print("KMIPServerAsync() close")
        self.server.shutdown()
        self.server.server_close()

    def serve(self):
        self.server.serve_forever()

    def _set_variables(self, host, port, keyfile, certfile, cert_reqs,
                       ssl_version, ca_certs, do_handshake_on_connect,
                       suppress_ragged_eofs):
        conf = ConfigHelper()
        self.host = conf.get_valid_value(host, 'server',
                                         'host', conf.DEFAULT_HOST)
        self.port = int(conf.get_valid_value(port, 'server',
                                             'port', conf.DEFAULT_PORT))
        self.keyfile = conf.get_valid_value(
            keyfile, 'server', 'keyfile', conf.DEFAULT_KEYFILE)

        self.certfile = conf.get_valid_value(
            certfile, 'server', 'certfile', conf.DEFAULT_CERTFILE)

        self.cert_reqs = getattr(ssl, conf.get_valid_value(
            cert_reqs, 'server', 'cert_reqs', 'CERT_NONE'))

        self.ssl_version = getattr(ssl, conf.get_valid_value(
            ssl_version, 'server', 'ssl_version', conf.DEFAULT_SSL_VERSION))

        self.ca_certs = conf.get_valid_value(
            ca_certs, 'server', 'ca_certs', None)

        if conf.get_valid_value(
                do_handshake_on_connect, 'server',
                'do_handshake_on_connect', 'True') == 'True':
            self.do_handshake_on_connect = True
        else:
            self.do_handshake_on_connect = False

        if conf.get_valid_value(
                suppress_ragged_eofs, 'server',
                'suppress_ragged_eofs', 'True') == 'True':
            self.suppress_ragged_eofs = True
        else:
            self.suppress_ragged_eofs = False
