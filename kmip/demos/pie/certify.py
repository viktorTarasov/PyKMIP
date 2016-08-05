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
import sys
import io

from kmip.core import enums
from kmip.demos import utils
from kmip.pie import client

if __name__ == '__main__':
    logger = utils.build_console_logger(logging.INFO)

    # Build and parse arguments
    parser = utils.build_cli_parser(enums.Operation.CERTIFY)
    opts, args = parser.parse_args(sys.argv[1:])

    config = opts.config
    uid = opts.uuid
    pkcs10_file = opts.pkcs10_file
    in_format = opts.in_format
    subject_an = opts.subject_alternative_name
    subject_dn = opts.subject_distinguished_name
    object_name = opts.object_name
    contact_information = opts.contact_information

    request_type = None
    request = None

    if pkcs10_file is not None:
        if in_format == 'PEM':
            fd = io.open(pkcs10_file, 'r')
            request = fd.read()
            fd.close()
            request_type = enums.CertificateRequestType.PEM
        elif in_format == 'DER':
            fd = io.open(pkcs10_file, 'rb')
            request = fd.read()
            fd.close()
            request_type = enums.CertificateRequestType.PKCS10
        else:
            logger.error("Input format is undefined or not 'PEM' or 'DER'")
            sys.exit()

    # Exit early if the UUID is not specified
    if uid is None and pkcs10_file is None:
        logger.error(
            'Neither UID nor PKCS#10 file has been provided, '
            'exiting early from demo')
        sys.exit()

    # Build the client and connect to the server
    with client.ProxyKmipClient(config=config) as client:
        try:
            result_uid = client.certify(
                uid,
                request_type,
                request,
                subject_dn,
                subject_an,
                object_name,
                contact_information)
            logger.info(
                'Successfully created Certificate(uid={0}) for '
                'PublicKey(uid={1})'.format(result_uid, uid))
        except Exception as e:
            logger.error(e)
