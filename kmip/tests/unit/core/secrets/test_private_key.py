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

import binascii
from testtools import TestCase

from kmip.core import enums
from kmip.core import attributes
from kmip.core.misc import KeyFormatType
from kmip.core.secrets import PrivateKey, KeyBlockKey
from kmip.core.utils import BytearrayStream
from kmip.core.objects import KeyBlock, KeyValue, KeyMaterial

class TestPrivateKey(TestCase):
    """
    A test suite for the PrivateKey class.
    """

    def setUp(self):
        super(TestPrivateKey, self).setUp()

        self.key_format_type_b = KeyFormatType(enums.KeyFormatType.PKCS_8)

        self.cryptographic_algorithm_b = attributes.CryptographicAlgorithm(
            enums.CryptographicAlgorithm.RSA)

        self.cryptographic_length_b = attributes.CryptographicLength(512)

        self.key_hex_blob_b = (
            '3082013B020100024100A54A78B4B9B146F3B24B3ED55DB557FA532507C583FC'
            'C65C11B93913AF7A50DD003661EE95FC81AAAD6B33F78C38494670914F5EA5DE'
            'F482D8EFDC73EA292A2702030100010241008A170D80EF220C04CC8FD08EB11B'
            '2FC512717D6CA6382800034E9B40B6F99953B13C82603E57427A65A3BE985CF3'
            'D4411F3132C3C95EC2CABD901AF305BE2401022100D622CC1FF8DD80AA6C6C69'
            '6AE2082F3098BC0CA96447D4059B3128DF61310E51022100C59B0C9EE1AFD514'
            '6A264567E10A9DCD7C545A8C93DE96A509D9D15709B63AF7022005C95CF0C43D'
            'E01B3AE0D71C6F4D3F5135DF670C30CC8C1B36AD66685AED0371022100B016E0'
            '234158701836138EABE8258EC3CB745C1083C0CA1B9DF0A594DB49B1B7022005'
            '806CBF28A63CEB6DD1A2FF83DE7CD672BA70D66B78EE4A88ED09883B68EDE0'
        )
        self.key_blob_b = binascii.unhexlify(self.key_hex_blob_b)
        self.key_value_b = KeyValue(
            key_material = KeyMaterial(
                self.key_blob_b
            )
        )

        self.encoding_hex_b = (
            '4200640100000188420040010000018042004205000000040000000400000000'
            '4200450100000148420043080000013f3082013b020100024100a54a78b4b9b1'
            '46f3b24b3ed55db557fa532507c583fcc65c11b93913af7a50dd003661ee95fc'
            '81aaad6b33f78c38494670914f5ea5def482d8efdc73ea292a27020301000102'
            '41008a170d80ef220c04cc8fd08eb11b2fc512717d6ca6382800034e9b40b6f9'
            '9953b13c82603e57427a65a3be985cf3d4411f3132c3c95ec2cabd901af305be'
            '2401022100d622cc1ff8dd80aa6c6c696ae2082f3098bc0ca96447d4059b3128'
            'df61310e51022100c59b0c9ee1afd5146a264567e10a9dcd7c545a8c93de96a5'
            '09d9d15709b63af7022005c95cf0c43de01b3ae0d71c6f4d3f5135df670c30cc'
            '8c1b36ad66685aed0371022100b016e0234158701836138eabe8258ec3cb745c'
            '1083c0ca1b9df0a594db49b1b7022005806cbf28a63ceb6dd1a2ff83de7cd672'
            'ba70d66b78ee4a88ed09883b68ede00042002805000000040000000400000000'
            '42002a02000000040000020000000000'
        )
        self.encoding_b = BytearrayStream(
            (binascii.unhexlify(self.encoding_hex_b)))

    def tearDown(self):
        super(TestPrivateKey, self).tearDown()

    def test_init(self):
        PrivateKey()

    def test_read_b(self):
        stream = self.encoding_b

        key = PrivateKey()
        key.read(stream)

        self.assertEqual(key.key_block.key_format_type, self.key_format_type_b)
        self.assertEqual(key.key_block.cryptographic_length, self.cryptographic_length_b)
        self.assertEqual(key.key_block.key_value.key_material.value, self.key_blob_b)

    def test_write_b(self):
        key_block = KeyBlock(
            key_format_type = self.key_format_type_b,
            key_value = self.key_value_b,
            cryptographic_algorithm = self.cryptographic_algorithm_b,
            cryptographic_length = self.cryptographic_length_b
        )
        key = PrivateKey(key_block)

        expected = self.encoding_b
        observed = BytearrayStream()

        key.write(observed)

        msg = "encoding mismatch;\nexpected:\n{0}\nobserved:\n{1}".format(
            expected, observed)
        self.assertEqual(expected, observed, msg)
