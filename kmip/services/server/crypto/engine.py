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
import os
import six
import re
import binascii

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import algorithms

from OpenSSL import crypto

from kmip.core import enums
from kmip.core import exceptions
from kmip.services.server.crypto import api

from kmip.core.enums import AttributeType


class ASN1(object):

    class ASN1_Item(object):

        def __init__(self, data, level):
            tag = data[0]
            size = data[1]
            if size > 0x80:
                num_size_bytes = size & 0x7F
                size = 0
                for ii in range(2, 2 + num_size_bytes):
                    size = size * 0x100 + data[ii]
                offset = 2 + num_size_bytes
            else:
                offset = 2

            self.blob = data[:offset + size]
            self.data = data[offset:offset + size]
            self.offset = offset
            self.tag = tag
            self.size = size
            self.items = list()
            self.level = level

        def parse(self):
            if (self.tag & 0x20) != 0:
                offset_next = 0
                while offset_next < self.size:
                    item = ASN1.ASN1_Item(self.data[offset_next:],
                                          self.level + 1)
                    item.parse()
                    self.items.append(item)
                    offset_next += item.offset + item.size

        def __str__(self):
            return self.__repr__()

        def __repr__(self):
            msg = "{0}ASN1_Item(tag=0x{1}, size={2}, data={3})".format(
                '    '*self.level,
                format(self.tag, 'x'),
                self.size,
                binascii.hexlify(self.data))

            for item in self.items:
                msg += "\n"
                msg += item.__repr__()

            return msg

    def __init__(self, data=None):
        if isinstance(data, bytes):
            self.data = data
        else:
            raise TypeError("Expected byte array")

        self.items = list()
        self.parse()

    def parse(self):
        offset_next = 0
        while offset_next < len(self.data):
            item = ASN1.ASN1_Item(self.data[offset_next:], 0)
            item.parse()
            self.items.append(item)
            offset_next = item.offset + item.size

    def __str__(self):
        items_str = ''
        for item in self.items:
            items_str += str(item)
            items_str += ', '

        if len(items_str):
            items_str = items_str[:-2]

        return "ASN1(data={0})\n{1}".format(
            binascii.hexlify(self.data),
            items_str)

    def __repr__(self):
        return self.__str__()


class CryptographyEngine(api.CryptographicEngine):
    """
    A cryptographic engine that uses pyca/cryptography to generate
    cryptographic objects and conduct cryptographic operations.
    """

    def __init__(self):
        """
        Construct a CryptographyEngine.
        """
        self.logger = logging.getLogger('kmip.server.engine.cryptography')

        self._symmetric_key_algorithms = {
            enums.CryptographicAlgorithm.TRIPLE_DES: algorithms.TripleDES,
            enums.CryptographicAlgorithm.AES: algorithms.AES,
            enums.CryptographicAlgorithm.BLOWFISH: algorithms.Blowfish,
            enums.CryptographicAlgorithm.CAMELLIA: algorithms.Camellia,
            enums.CryptographicAlgorithm.CAST5: algorithms.CAST5,
            enums.CryptographicAlgorithm.IDEA: algorithms.IDEA,
            enums.CryptographicAlgorithm.RC4: algorithms.ARC4
        }
        self._asymetric_key_algorithms = {
            enums.CryptographicAlgorithm.RSA: self._create_rsa_key_pair
        }

    def create_symmetric_key(self, algorithm, length=None):
        """
        Create a symmetric key.

        Args:
            algorithm(CryptographicAlgorithm): An enumeration specifying the
                algorithm for which the created key will be compliant.
            length(int): The length of the key to be created. This value must
                be compliant with the constraints of the provided algorithm.

        Returns:
            dict: A dictionary containing the key data, with the following
                key/value fields:
                * value - the bytes of the key
                * format - a KeyFormatType enumeration for the bytes format

        Raises:
            InvalidField: Raised when the algorithm is unsupported or the
                length is incompatible with the algorithm.
            CryptographicFailure: Raised when the key generation process
                fails.

        Example:
            >>> engine = CryptographyEngine()
            >>> key = engine.create_symmetric_key(
            ...     CryptographicAlgorithm.AES, 256)
        """
        if algorithm not in self._symmetric_key_algorithms.keys():
            raise exceptions.InvalidField(
                "The cryptographic algorithm {0} is not a supported symmetric "
                "key algorithm.".format(algorithm)
            )

        cryptography_algorithm = self._symmetric_key_algorithms.get(algorithm)

        if length is None:
            # If cryptograohic length is not defined,
            #   the strongest allowed key size is used.
            sizes = list(cryptography_algorithm.key_sizes)
            sizes.sort()
            length = sizes[-1]
        elif length not in cryptography_algorithm.key_sizes:
            raise exceptions.InvalidField(
                "The cryptographic length ({0}) is not valid for "
                "the cryptographic algorithm ({1}).".format(
                    length, algorithm.name
                )
            )

        self.logger.info(
            "Generating a {0} symmetric key with length: {1}".format(
                algorithm.name, length
            )
        )

        key_bytes = os.urandom(length // 8)
        try:
            cryptography_algorithm(key_bytes)
        except Exception as e:
            self.logger.exception(e)
            raise exceptions.CryptographicFailure(
                "Invalid bytes for the provided cryptographic algorithm.")

        return {
            'value': key_bytes,
            'format': enums.KeyFormatType.RAW,
            'cryptographic_length': length}

    def create_asymmetric_key_pair(self, algorithm, length):
        """
        Create an asymmetric key pair.

        Args:
            algorithm(CryptographicAlgorithm): An enumeration specifying the
                algorithm for which the created keys will be compliant.
            length(int): The length of the keys to be created. This value must
                be compliant with the constraints of the provided algorithm.

        Returns:
            dict: A dictionary containing the public key data, with at least
                the following key/value fields:
                * value - the bytes of the key
                * format - a KeyFormatType enumeration for the bytes format
            dict: A dictionary containing the private key data, identical in
                structure to the one above.

        Raises:
            InvalidField: Raised when the algorithm is unsupported or the
                length is incompatible with the algorithm.
            CryptographicFailure: Raised when the key generation process
                fails.

        Example:
            >>> engine = CryptographyEngine()
            >>> key = engine.create_asymmetric_key(
            ...     CryptographicAlgorithm.RSA, 2048)
        """
        if algorithm not in self._asymetric_key_algorithms.keys():
            raise exceptions.InvalidField(
                "The cryptographic algorithm ({0}) is not a supported "
                "asymmetric key algorithm.".format(algorithm)
            )

        engine_method = self._asymetric_key_algorithms.get(algorithm)
        return engine_method(length)

    def _create_rsa_key_pair(self, length, public_exponent=65537):
        """
        Create an RSA key pair.

        Args:
            length(int): The length of the keys to be created. This value must
                be compliant with the constraints of the provided algorithm.
            public_exponent(int): The value of the public exponent needed to
                generate the keys. Usually a small Fermat prime number.
                Optional, defaults to 65537.

        Returns:
            dict: A dictionary containing the public key data, with the
                following key/value fields:
                * value - the bytes of the key
                * format - a KeyFormatType enumeration for the bytes format
                * public_exponent - the public exponent integer
            dict: A dictionary containing the private key data, identical in
                structure to the one above.

        Raises:
            CryptographicFailure: Raised when the key generation process
                fails.
        """
        self.logger.info(
            "Generating an RSA key pair with length: {0}, and "
            "public_exponent: {1}".format(
                length, public_exponent
            )
        )
        try:
            private_key = rsa.generate_private_key(
                public_exponent=public_exponent,
                key_size=length,
                backend=default_backend())
            public_key = private_key.public_key()

            private_bytes = private_key.private_bytes(
                serialization.Encoding.DER,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption())
            public_bytes = public_key.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.PKCS1)
        except Exception as e:
            self.logger.exception(e)
            raise exceptions.CryptographicFailure(
                "An error occurred while generating the RSA key pair. "
                "See the server log for more information."
            )

        public_key = {
            'value': public_bytes,
            'format': enums.KeyFormatType.PKCS_1,
            'public_exponent': public_exponent
        }
        private_key = {
            'value': private_bytes,
            'format': enums.KeyFormatType.PKCS_8,
            'public_exponent': public_exponent
        }

        return public_key, private_key

    def X509_get_public_key(self, value, encoding=serialization.Encoding.DER):
        # from certificate get blob of public key
        cert = x509.load_der_x509_certificate(value, default_backend())
        pub_key_blob = cert.public_key().public_bytes(
            encoding=encoding,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)
        return pub_key_blob

    def X509_extension_blob(self, type_name, critical, value):
        if isinstance(type_name, six.string_types):
            type_name = bytes(type_name, 'ascii')
        elif not isinstance(type_name, bytes):
            TypeError("Extention type name has to be 'str' or 'bytes'")

        if isinstance(value, six.string_types):
            value = bytes(value, 'ascii')
        elif not isinstance(value, bytes):
            TypeError("Extention value has to be 'str' or 'bytes'")

        ext = crypto.X509Extension(type_name, critical, value)
        return ext.get_data()

    def X509_DN_blob_from_str(self, dn_str):
        rdns = re.findall('(C|O|CN|OU|DC)=([ \w-]+),?', dn_str)
        x509_name = crypto.X509Name(crypto.X509().get_subject())
        for name, value in rdns:
            setattr(x509_name, name, value)

        return x509_name.der()

    RDN_names = {
        b'55040a': 'O',
        b'55040b': 'OU',
        b'550403': 'CN'
    }

    GeneralNames = {
        0: 'othername',
        1: 'email',
        2: 'DNS',
        3: 'X400Name',
        4: 'DirName',
        5: 'EdiPartyName',
        6: 'URI',
        7: 'IP Address',
        8: 'Registered ID',
    }

    def PKCS10_set_subject(self, req, asn1):
        subject = req.get_subject()
        for rdn in asn1.items[0].items:
            for item in rdn.items[0].items:
                if item.tag == 0x06:
                    oid = binascii.hexlify(item.data)
                if item.tag == 0x0C:
                    value = item.data.decode("utf-8")

            if oid in self.RDN_names:
                setattr(subject, self.RDN_names[oid], value)
            else:
                raise TypeError("RDN OID not found in the dictionary")

    def PKCS10_set_subjectAltName(self, req, asn1):
        alt_names = list()
        for item in asn1.items[0].items:
            tag = item.tag & 0x1F
            if tag in self.GeneralNames:
                alt_name = "{0}:{1}".format(
                    self.GeneralNames[tag],
                    item.data.decode("utf-8"))
                alt_names.append(alt_name)
            else:
                raise TypeError("Invalid General Name tag: {0}".format(tag))

        if len(alt_names):
            ext_value = ",".join(alt_names)
            ext_value = ext_value.encode("utf-8")
            req.add_extensions([
                crypto.X509Extension(b'subjectAltName', False, ext_value)])

    def PKCS10_create(self, private_key, attributes):
        prvkey = crypto.load_privatekey(crypto.FILETYPE_ASN1, private_key)
        req = crypto.X509Req()
        req.set_pubkey(prvkey)

        for attribute_name in attributes.keys():
            if attribute_name == AttributeType.X_509_CERTIFICATE_SUBJECT.value:
                subject = attributes[attribute_name]

                if len(subject.distinguished_name.value):
                    self.PKCS10_set_subject(
                        req,
                        ASN1(subject.distinguished_name.value))

                if subject.alternative_name is not None:
                    if len(subject.alternative_name.value):
                        self.PKCS10_set_subjectAltName(
                            req,
                            ASN1(subject.alternative_name.value))

        req.sign(prvkey, 'sha256')
        return crypto.dump_certificate_request(crypto.FILETYPE_ASN1, req)
