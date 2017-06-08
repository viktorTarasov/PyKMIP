# Copyright (c) 2015 The Johns Hopkins University/Applied Physics Laboratory
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

from kmip.core.enums import AttributeType
from kmip.core.enums import CredentialType
from kmip.core.enums import CryptographicAlgorithm
from kmip.core.enums import CryptographicUsageMask
from kmip.core.enums import ObjectType
from kmip.core.enums import Operation
from kmip.core.enums import ResultStatus
from kmip.core.enums import NameType
from kmip.core.enums import KeyFormatType as KeyFormatTypeEnum


from kmip.core import attributes as attr

from kmip.core.messages.contents import ProtocolVersion

from kmip.core.factories.attributes import AttributeFactory
from kmip.core.factories.credentials import CredentialFactory

from kmip.core.attributes import Name

from kmip.core.objects import TemplateAttribute
from kmip.core.objects import Attribute

from kmip.services.kmip_client import KMIPProxy

from kmip.demos import utils

from kmip.core.misc import KeyFormatType

# from kmip.core.utils import bit_length
# from wsgiref.util import setup_testing_defaults


import logging
import os
import sys
import re

def create_aes_key(logger, client, credential, key_name):
    attribute_factory = AttributeFactory()
    # Build the different object attributes
    object_type = ObjectType.SYMMETRIC_KEY

    attribute_type = AttributeType.CRYPTOGRAPHIC_ALGORITHM
    algorithm_enum = getattr(CryptographicAlgorithm, 'AES', None)

    algorithm_obj = attribute_factory.create_attribute(attribute_type, algorithm_enum)

    mask_flags = [CryptographicUsageMask.ENCRYPT, CryptographicUsageMask.DECRYPT]
    attribute_type = AttributeType.CRYPTOGRAPHIC_USAGE_MASK
    usage_mask = attribute_factory.create_attribute(attribute_type, mask_flags)

    attribute_type = AttributeType.CRYPTOGRAPHIC_LENGTH
    length_obj = attribute_factory.create_attribute(attribute_type, 128)

    name = Attribute.AttributeName('Name')
    name_value = Name.NameValue(key_name)
    name_type = Name.NameType(NameType.UNINTERPRETED_TEXT_STRING)
    value = Name(name_value=name_value, name_type=name_type)
    name = Attribute(attribute_name=name, attribute_value=value)

    attributes = [algorithm_obj, usage_mask, length_obj, name]
    template_attribute = TemplateAttribute(attributes=attributes)

    # Create the SYMMETRIC_KEY object
    result_create = client.create(object_type, template_attribute, credential)
    # logger.info('create "{1}" key result: {0}'.format(result_create.result_status.value, key_name))

    # Retrieve the SYMMETRIC_KEY object
    format_type_enum = getattr(KeyFormatTypeEnum, 'RAW', None)
    key_format_type = KeyFormatType(format_type_enum)
    result_get = client.get(uuid=result_create.uuid.value, key_format_type=key_format_type, credential=credential)
    key_value = result_get.secret.key_block.key_value.key_material.value
    # logger.info('get "{0}" key result: {1}: value {2}'.format(key_name, result_get.result_status.value, ''.join('{:02x}'.format(x) for x in key_value)))

    return result_get

def get_aes_key(logger, client, credential, key_name):
    name = Attribute.AttributeName('Name')
    name_value = Name.NameValue(key_name)
    name_type = Name.NameType(NameType.UNINTERPRETED_TEXT_STRING)
    value = Name(name_value=name_value, name_type=name_type)
    name = Attribute(attribute_name=name, attribute_value=value)
    attributes = [name]

    # Locate UUID of specified SYMMETRIC_KEY object
    result = client.locate(attributes=attributes, credential=credential)
    if result.result_status.value != ResultStatus.SUCCESS:
        print ("LOCATE request failed")
        return None
    elif len(result.uuids) == 0:
        print("Key not found")
        return None
    elif len(result.uuids) != 1:
        print("Ambiguous 'LOCATE' result: there are {0} results".format(len(result.uuids)))
        return None

    # Retrieve the SYMMETRIC_KEY object
    format_type_enum = getattr(KeyFormatTypeEnum, 'RAW', None)
    key_format_type = KeyFormatType(format_type_enum)
    result_get = client.get(uuid=result.uuids[0].value, key_format_type=key_format_type, credential=credential)
    if result_get.result_status.value != ResultStatus.SUCCESS:
        print ("GET request failed")
        return None

    # key_value = result_get.secret.key_block.key_value.key_material.value
    # logger.info('get "{0}" key result: {1}: value {2}'.format(key_name, result_get.result_status.value, ''.join('{:02x}'.format(x) for x in key_value)))
    return result_get

def run_request(cmd='', key_name=''):
    # Build and parse arguments
    parser = utils.build_cli_parser(Operation.DISCOVER_VERSIONS)
    opts, args = parser.parse_args([])

    username = opts.username
    password = opts.password
    config = opts.config
    algorithm = 'AES'
    length = 128

    print ("\nCmd: {0}, key-name: {1}".format(cmd, key_name))
    protocol_versions = list()
    if opts.protocol_versions != None:
        for version in re.split(',| ', opts.protocol_versions) :
            mm = re.split('\.', version)
            protocol_versions.append(ProtocolVersion.create(int(mm[0]), int(mm[1])))

    # Build and setup logging
    f_log = '/home/vtarasov/projects/sc/github/KMIP/OpenKMIP/PyKMIP/kmip/pykmip.conf'
    logging.config.fileConfig(f_log)
    logger = logging.getLogger(__name__)

    # Build the client and connect to the server
    client = KMIPProxy(config=config)
    client.open()

    attribute_factory = AttributeFactory()
    credential_factory = CredentialFactory()

    # Build the KMIP server account credentials
    # TODO (peter-hamilton) Move up into KMIPProxy
    if (username is None) and (password is None):
        credential = None
    else:
        credential_type = CredentialType.USERNAME_AND_PASSWORD
        credential_value = {'Username': username, 'Password': password}
        credential = credential_factory.create_credential(credential_type, credential_value)

    aes_key_name = "aes-key {0}".format(key_name)
    hmac_key_name = "hmac-secret {0}".format(key_name)

    print ("\nnames '{0}', '{1}'".format(aes_key_name, hmac_key_name))

    aes_key_value = bytes()
    hmac_key_value = bytes()
    if cmd == 'create':
        result_aes = create_aes_key(logger, client, credential, aes_key_name)
        if result_aes != None and result_aes.result_status.value == ResultStatus.SUCCESS:
            aes_key_value = result_aes.secret.key_block.key_value.key_material.value
            logger.info('created key "{0}" -- {1}'.format(aes_key_name, ''.join('{:02x}'.format(x) for x in     aes_key_value)))
            result_hmac = create_aes_key(logger, client, credential, hmac_key_name)
            if result_hmac.result_status.value == ResultStatus.SUCCESS:
                hmac_key_value = result_hmac.secret.key_block.key_value.key_material.value
                logger.info('created key "{0}" -- {1}'.format(hmac_key_name, ''.join('{:02x}'.format(x) for x in hmac_key_value)))
    elif cmd == 'get':
        result_aes = get_aes_key(logger, client, credential, aes_key_name)
        if result_aes != None and result_aes.result_status.value == ResultStatus.SUCCESS:
            aes_key_value = result_aes.secret.key_block.key_value.key_material.value
            logger.info('have got key "{0}" -- {1}'.format(aes_key_name, ''.join('{:02x}'.format(x) for x in     aes_key_value)))

            result_hmac = get_aes_key(logger, client, credential, hmac_key_name)
            if result_hmac.result_status.value == ResultStatus.SUCCESS:
                hmac_key_value = result_hmac.secret.key_block.key_value.key_material.value
                logger.info('have got key "{0}" -- {1}'.format(hmac_key_name, ''.join('{:02x}'.format(x) for x in hmac_key_value)))

    client.close()

    return {'Cmd':cmd, 'Name':key_name, 'aes-key':aes_key_value, 'hmac-secret':hmac_key_value}

    # Display operation results

#    # Display operation results
#    if result.result_status.value == ResultStatus.SUCCESS:
#        logger.info('created object type: {0}'.format(result.object_type.value))
#        logger.info('created UUID: {0}'.format(result.uuid.value))
#        logger.info('created template attribute: {0}'.format(result.template_attribute))
#    else:
#        logger.info('create() result reason: {0}'.format(result.result_reason.value))
#        logger.info('create() result message: {0}'.format(result.result_message.value))

