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
import datetime

from testtools import TestCase

from kmip.core import objects
from kmip.core import utils
from kmip.core.attributes import CryptographicAlgorithm, CryptographicLength
from kmip.core.attributes import ContactInformation, CertificateType

from kmip.core import enums
from kmip.core.factories.attributes import AttributeFactory
from kmip.core.messages.payloads import put
from kmip.core.primitives import DateTime

from kmip.core.misc import KeyFormatType, PutFunctionType, CertificateValue
from kmip.core.secrets import PrivateKey, KeyBlockKey, Certificate
from kmip.core.utils import BytearrayStream
from kmip.core.objects import KeyBlock, KeyValue, KeyMaterial


class TestPutRequestPayload(TestCase):

    def setUp(self):
        super(TestPutRequestPayload, self).setUp()

        self.attr_factory = AttributeFactory()

        self.uid = 'b4faee10-aa2a-4446-8ad4-0881f3422959'
        self.replaced_uid = '0dec4e90-c50e-4417-8939-4b29453be474'

        self.put_function_new = PutFunctionType(enums.PutFunction.NEW)

        self.key_format_type = KeyFormatType(enums.KeyFormatType.PKCS_8)

        self.cryptographic_algorithm = CryptographicAlgorithm(
            enums.CryptographicAlgorithm.RSA)

        self.cryptographic_length = CryptographicLength(512)

        self.key_hex_blob = (
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
        self.key_blob = binascii.unhexlify(self.key_hex_blob)
        self.key_value = KeyValue(
            key_material = KeyMaterial(
                self.key_blob
            )
        )

        self.encoding_hex = (
			'4200790100000288420094070000002462346661656531302d616132612d3434'
			'34362d386164342d303838316633343232393539000000004200700500000004'
			'0000000100000000420076070000002430646563346539302d633530652d3434'
			'31372d383933392d346232393435336265343734000000004200640100000188'
			'4200400100000180420042050000000400000004000000004200450100000148'
			'420043080000013f3082013b020100024100a54a78b4b9b146f3b24b3ed55db5'
			'57fa532507c583fcc65c11b93913af7a50dd003661ee95fc81aaad6b33f78c38'
			'494670914f5ea5def482d8efdc73ea292a2702030100010241008a170d80ef22'
			'0c04cc8fd08eb11b2fc512717d6ca6382800034e9b40b6f99953b13c82603e57'
			'427a65a3be985cf3d4411f3132c3c95ec2cabd901af305be2401022100d622cc'
			'1ff8dd80aa6c6c696ae2082f3098bc0ca96447d4059b3128df61310e51022100'
			'c59b0c9ee1afd5146a264567e10a9dcd7c545a8c93de96a509d9d15709b63af7'
			'022005c95cf0c43de01b3ae0d71c6f4d3f5135df670c30cc8c1b36ad66685aed'
			'0371022100b016e0234158701836138eabe8258ec3cb745c1083c0ca1b9df0a5'
			'94db49b1b7022005806cbf28a63ceb6dd1a2ff83de7cd672ba70d66b78ee4a88'
			'ed09883b68ede0004200280500000004000000040000000042002a0200000004'
			'0000020000000000420008010000002842000a07000000104c61737420436861'
			'6e6765204461746542000b0900000008000000005799bf334200080100000050'
			'42000a0700000013436f6e7461637420496e666f726d6174696f6e0000000000'
			'42000b070000002268747470733a2f2f6769746875622e636f6d2f4f70656e4b'
            '4d49502f50794b4d4950000000000000'
        )
        self.encoding = binascii.unhexlify(self.encoding_hex)

        self.private_key = PrivateKey(
            KeyBlock(
                key_format_type = self.key_format_type,
                key_value = self.key_value,
                cryptographic_algorithm = self.cryptographic_algorithm,
                cryptographic_length = self.cryptographic_length
            )
        )

        self.cert_blob_hex = (
			'3082039c30820284a003020102020c0a06e0034532e43383bdc879300d06092a'
			'864886f70d01010b05003045310b300906035504061302465231123010060355'
			'040a0c096f70656e7472757374310e300c060355040b0c05696e6e6f76311230'
			'1006035504030c094b4d4950204f704341301e170d3136303731343131323932'
			'345a170d3138303130313134343835345a302c31163014060355040a0c0d4f70'
			'656e547275737420504b493112301006035504030c0961646d696e2d706b6930'
			'820122300d06092a864886f70d01010105000382010f003082010a0282010100'
			'b485ad070a8c4816ec255f993f5875f4491bb8afb522e8554406262935abd6c9'
			'f59269be9bc9bcc3e7f9ded3d5f8be4183920f5710a1e166e6358adbff5c3ea7'
			'da54e30974a8d4a20a738932edc848d0be6535f153e10e0f8a0ad9eec4a1297f'
			'd63cd05b93ce1a4a93a89f10a63930dd5c0aa0392ee574314b6c45500dbf06b0'
			'c47b0d34e2aecf6e970e6346d0ac80cf2808a7acffc81c68b832ef46b1ce7003'
			'c935f07b3ad13eec60565cbfd781a37732b7a79cb980027846d41634a3125c46'
			'ab19791f7e6d781f75ea19a97c6962573761cd50b6d657b057febdb55de680ea'
			'eb03d3be6baffa0116c5e693d41fd650ee7f604a7a2631740b3eecb81b7fa9a3'
			'0203010001a381a43081a1301d0603551d0e04160414bf03373a6989a1a58a67'
			'8c4310dac620155910d8301f0603551d2304183016801421d10d7bc3a537cbe4'
			'081c23241101974118ca15301d0603551d250416301406082b06010505070302'
			'06082b06010505070304300e0603551d0f0101ff0404030205a030300603551d'
			'1104293027812576696b746f722e74617261736f762b6b6d69702d706b69406f'
			'70656e74727573742e636f6d300d06092a864886f70d01010b05000382010100'
			'42281a8a9240cb741d26ed330d5d52dd964afa512e547ac3e0c898b873b6d7d4'
			'e22ed316a26ede06d5bf962ddac3a6eff4a623b336de31e53a38e808b88e50d6'
			'c43de27699c4316d04fd1a66623d7cc4eaa292d5766c0351d7c93d4ada2f9d09'
			'8887e63cb486ba1cf747b972199628d15a57df5e2ed140c4df53f0574a982b44'
			'd5367f4fe71faa5884ea8132a1fde09e49d3fb334f8f128c850f8a7848fc3ecf'
			'04ccf90871c5482477a92bd3eb5cd47dd16d503745b5c0847a94b5dcd982c21c'
			'cccd3c15e6f9a1677c64c2af98571248daf83d6074010dfd16ed43d4fd99e809'
			'f9b5dfcd468cec83083f108de8c9aaa84ad2b8053625d14c3baaa60b41321231'
        )
        self.cert_blob = binascii.unhexlify(self.cert_blob_hex)

        self.certificate = Certificate(
            certificate_type=CertificateType(enums.CertificateTypeEnum.X_509),
            certificate_value=CertificateValue(self.cert_blob)
        )

        self.ci_value = 'https://github.com/OpenKMIP/PyKMIP'
        self.attr_contact_information = self.attr_factory.create_attribute(
            enums.AttributeType.CONTACT_INFORMATION,
            self.ci_value)

        self.datetime = datetime.datetime(2016, 7, 28, 10, 15, 47)
        self.last_change_date = int(self.datetime.timestamp())

        self.attr_last_change_date = self.attr_factory.create_attribute(
            enums.AttributeType.LAST_CHANGE_DATE,
            self.last_change_date)

        self.attributes = [self.attr_last_change_date,
                           self.attr_contact_information]

    def tearDown(self):
        super(TestPutRequestPayload, self).tearDown()

    def test_init_with_none(self):
        put.PutRequestPayload()

    def test_init_with_args(self):
        put.PutRequestPayload(
            uid = self.uid,
            replaced_uid = self.replaced_uid,
            put_function = self.put_function_new,
            attributes = self.attributes)

    def test_read(self):
        stream = utils.BytearrayStream((self.encoding))

        payload = put.PutRequestPayload()
        payload.read(stream)

        self.assertEqual(payload.uid, self.uid)

        self.assertIsInstance(payload.put_function, PutFunctionType)
        self.assertEqual(payload.put_function, self.put_function_new)

        self.assertEqual(payload.replaced_uid, self.replaced_uid)

        self.assertIsInstance(payload.object_data, PrivateKey)
        self.assertEqual(payload.object_data.key_block.key_format_type,
                         self.key_format_type)
        self.assertEqual(payload.object_data.key_block.cryptographic_algorithm,
                         self.cryptographic_algorithm)
        self.assertEqual(payload.object_data.key_block.cryptographic_length,
                         self.cryptographic_length)

        key_value = payload.object_data.key_block.key_value
        self.assertEqual(key_value.key_material, self.key_value.key_material)

        self.assertIsInstance(payload.attributes, list)
        for attribute in payload.attributes:
            self.assertIsInstance(attribute, objects.Attribute)

        self.assertEqual(payload.attributes[1].attribute_name.value,
            enums.AttributeType.CONTACT_INFORMATION.value)
        self.assertIsInstance(payload.attributes[1].attribute_value,
            ContactInformation)
        self.assertEqual(payload.attributes[1].attribute_value.value,
            self.ci_value)

        self.assertEqual(
            payload.attributes[0].attribute_name.value,
            enums.AttributeType.LAST_CHANGE_DATE.value)
        self.assertIsInstance(
            payload.attributes[0].attribute_value,
            DateTime)
        self.assertEqual(
            payload.attributes[0].attribute_value.value,
            self.last_change_date)

    def test_write(self):
        stream = utils.BytearrayStream()
        expected = self.encoding

        payload = put.PutRequestPayload(
            uid = self.uid,
            replaced_uid = self.replaced_uid,
            put_function = enums.PutFunction.NEW,
            object_data = self.private_key,
            attributes = self.attributes)

        payload.write(stream)

        length_expected = len(expected)
        length_received = len(stream)

        msg = "encoding lengths not equal"
        msg += "; expected {0}, received {1}".format(
            length_expected, length_received)
        self.assertEqual(length_expected, length_received, msg)

        msg = "encoding mismatch"
        msg += ";\nexpected:\n{0}\nreceived:\n{1}".format(expected, stream.buffer)
        self.assertEqual(expected, stream.buffer, msg)
