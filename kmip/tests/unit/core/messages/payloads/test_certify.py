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

from kmip.core.utils import BytearrayStream
from kmip.core.enums import CertificateRequestType as RequestType
from kmip.core.messages.payloads.certify import CertifyRequestPayload
from kmip.core.messages.payloads.certify import CertifyResponsePayload

pkcs10_pem = (
    '-----BEGIN CERTIFICATE REQUEST-----\n'
    'MIIBFjCBwQIBADBcMQswCQYDVQQGEwJGUjETMBEGA1UECAwKU29tZS1TdGF0ZTEP\n'
    'MA0GA1UECgwGR2l0SHViMQ0wCwYDVQQLDARLTUlQMRgwFgYDVQQDDA9UZXN0aW5n\n'
    'IENlcnRpZnkwXDANBgkqhkiG9w0BAQEFAANLADBIAkEAu1/KwXv+IDmtIfpSUhje\n'
    'MjkDydfyt+l0rySe122vy1479nxnAxn2dn2p3ZrsupjcsDGICsRc7u2kXk2/JQ9Z\n'
    'GwIDAQABoAAwDQYJKoZIhvcNAQELBQADQQC2Y3Yp3UjXWb60YpLjCfMEOX9y9FmW\n'
    'xu8C6f2DoW0vVg+qtwgE8kkq2Ib7PFVa6Vb9uZwEp4sz63S2hGTAadTJ\n'
    '-----END CERTIFICATE REQUEST-----'
).encode('ASCII')

pkcs10_hex = (
   '308201163081c1020100305c310b300906035504061302465231133011060355'
   '04080c0a536f6d652d5374617465310f300d060355040a0c0647697448756231'
   '0d300b060355040b0c044b4d49503118301606035504030c0f54657374696e67'
   '2043657274696679305c300d06092a864886f70d0101010500034b0030480241'
   '00bb5fcac17bfe2039ad21fa525218de323903c9d7f2b7e974af249ed76dafcb'
   '5e3bf67c670319f6767da9dd9aecba98dcb031880ac45ceeeda45e4dbf250f59'
   '1b0203010001a000300d06092a864886f70d01010b0500034100b6637629dd48'
   'd759beb46292e309f304397f72f45996c6ef02e9fd83a16d2f560faab70804f2'
   '492ad886fb3c555ae956fdb99c04a78b33eb74b68464c069d4c9'
)


class TestCertifyPayload(TestCase):

    def setUp(self):
        super(TestCertifyPayload, self).setUp()

        self.uid = 'b4faee10-aa2a-4446-8ad4-0881f3422959'
        self.other_uid = 'a4faee10-aa2a-4446-8ad4-0881f3422959'
        self.type_pem = CertifyRequestPayload.CertificateRequestType(
            RequestType.PEM)
        self.type_pkcs10 = CertifyRequestPayload.CertificateRequestType(
            RequestType.PKCS10)
        self.pkcs10_pem = pkcs10_pem

        self.pkcs10_der = binascii.unhexlify(pkcs10_hex)

        self.uid_invalid = 1234
        self.request_type_invalid = 1234
        self.attribute_invalid = 'invalid'

        '''
        <RequestPayload>
          <UniqueIdentifier type="TextString"
                            value="b4faee10-aa2a-4446-8ad4-0881f3422959"/>
        </RequestPayload>
        '''
        self.blob_request_with_uid = binascii.unhexlify(
            '4200790100000030420094070000002462346661656531302d616132612d3434'
            '34362d386164342d30383831663334323239353900000000'
        )

        '''
        <RequestPayload>
            <CertificateRequestType type="Enumeration" value="PKCS10"/>
            <CertificateRequest type="ByteString"  value="308201163081c102..."
        </RequestPayload>
        '''
        self.blob_request_with_pkcs10 = binascii.unhexlify(
            '420079010000013842001905000000040000000200000000420018080000011a'
        ) + self.pkcs10_der
        pad_len = (8 - len(self.blob_request_with_pkcs10) % 8) % 8
        self.blob_request_with_pkcs10 += b'\x00'*pad_len

        '''
        <ResponsePayload>
          <UniqueIdentifier type="TextString" \
                    value="b4faee10-aa2a-4446-8ad4-0881f3422959"/>
        </ResponsePayload>
        '''
        self.blob_response = binascii.unhexlify(
            '42007c0100000030420094070000002462346661656531302d616132612d3434'
            '34362d386164342d30383831663334323239353900000000'
        )


class TestCertifyRequestPayload(TestCertifyPayload):

    def setUp(self):
        super(TestCertifyRequestPayload, self).setUp()

    def tearDown(self):
        super(TestCertifyRequestPayload, self).tearDown()

    def test_init_without_args(self):
        CertifyRequestPayload()

    def test_init_with_args(self):
        CertifyRequestPayload(uid=self.uid)
        CertifyRequestPayload(
            certificate_request_type=self.type_pem,
            certificate_request=self.pkcs10_pem
        )

    def test_validate_with_invalid_uid(self):
        args = [self.uid_invalid]
        self.assertRaises(
            TypeError,
            CertifyRequestPayload,
            *args)

    def test_validate_with_invalid_request_type(self):
        kwargs = {
            'certificate_request': self.pkcs10_pem,
            'certificate_request_type': self.request_type_invalid
        }
        self.assertRaises(
            TypeError,
            CertifyRequestPayload,
            **kwargs)

    def test_read_request_with_uid(self):
        stream = BytearrayStream((self.blob_request_with_uid))

        payload = CertifyRequestPayload()
        payload.read(stream)

        self.assertEqual(payload.uid, self.uid)

    def test_read_request_with_pkcs10(self):
        stream = BytearrayStream((self.blob_request_with_pkcs10))

        payload = CertifyRequestPayload()
        payload.read(stream)

        self.assertEqual(payload.certificate_request_type, self.type_pkcs10)
        self.assertEqual(payload.certificate_request, self.pkcs10_der)

    def test_write_request_with_uid(self):
        stream = BytearrayStream()
        expected = self.blob_request_with_uid

        payload = CertifyRequestPayload(uid=self.uid)

        payload.write(stream)

        length_expected = len(expected)
        length_received = len(stream)

        msg = "encoding lengths not equal"
        msg += "; expected {0}, received {1}".format(
            length_expected, length_received)
        self.assertEqual(length_expected, length_received, msg)

        msg = "encoding mismatch"
        msg += ";\nexpected:\n{0}\nreceived:\n{1}".format(expected, stream)
        self.assertEqual(expected, stream.buffer, msg)

    def test_write_request_with_pkcs10(self):
        stream = BytearrayStream()
        expected = self.blob_request_with_pkcs10

        payload = CertifyRequestPayload(
            certificate_request_type=self.type_pkcs10,
            certificate_request=self.pkcs10_der
        )

        payload.write(stream)

        length_expected = len(expected)
        length_received = len(stream)

        msg = "encoding lengths not equal"
        msg += "; expected {0}, received {1}".format(
            length_expected, length_received)
        self.assertEqual(length_expected, length_received, msg)
        print("length_expected {0}; length_received {1}".format(
            length_expected, length_received))

        msg = "encoding mismatch"
        msg += ";\nexpected:\n{0}\nreceived:\n{1}".format(expected, stream)
        self.assertEqual(expected, stream.buffer, msg)

    def test_repr_str(self):
        payload = CertifyRequestPayload(uid=self.uid)

        value = "public_key_uid={0}, certificate_request({1})={2}".format(
            self.uid, None, None)
        expected = "CertifyRequestPayload({0}, template_attribute={1})".format(
                value, None)

        self.assertEqual(expected, repr(payload))
        self.assertEqual(expected, str(payload))

    def test__eq(self):
        payload = CertifyRequestPayload(uid=self.uid)
        payload_same = CertifyRequestPayload(uid=self.uid)
        payload_other_uid = CertifyRequestPayload(uid=self.other_uid)

        self.assertTrue(payload == payload_same)
        self.assertTrue(payload != payload_other_uid)
        self.assertTrue(payload != 'invalid')
        self.assertFalse(payload != payload_same)
        self.assertFalse(payload == payload_other_uid)
        self.assertFalse(payload == 'invalid')


class TestCertifyResponsePayload(TestCertifyPayload):

    def setUp(self):
        super(TestCertifyResponsePayload, self).setUp()

    def tearDown(self):
        super(TestCertifyResponsePayload, self).tearDown()

    def test_init_with_none(self):
        CertifyResponsePayload()

    def test_init_with_args(self):
        CertifyResponsePayload(self.uid)

    def test_validate_with_invalid_uid(self):
        args = [self.uid_invalid]
        self.assertRaises(
            TypeError,
            CertifyResponsePayload,
            *args)

    def test_validate_with_invalid_attribute(self):
        kwargs = {
            'uid': self.uid,
            'template_attribute': self.attribute_invalid}
        error_msg = "invalid template attribute; expected TemplateAttribute"
        error_msg += ", observed {0}".format(type(self.attribute_invalid))
        self.assertRaisesRegexp(
            TypeError,
            error_msg,
            CertifyResponsePayload,
            **kwargs)

    def test_read(self):
        stream = BytearrayStream((self.blob_response))

        payload = CertifyResponsePayload()
        payload.read(stream)

        self.assertEqual(payload.uid, self.uid)

    def test_write(self):
        stream = BytearrayStream()
        expected = self.blob_response

        payload = CertifyResponsePayload(uid=self.uid)

        payload.write(stream)

        length_expected = len(expected)
        length_received = len(stream)

        msg = "encoding lengths not equal"
        msg += "; expected {0}, received {1}".format(
            length_expected, length_received)
        self.assertEqual(length_expected, length_received, msg)
        print("length_expected {0}; length_received {1}".format(
            length_expected, length_received))

        msg = "encoding mismatch"
        msg += ";\nexpected:\n{0}\nreceived:\n{1}".format(expected, stream)
        self.assertEqual(expected, stream.buffer, msg)

    def test_repr_str(self):
        payload = CertifyResponsePayload(self.uid)

        data = "uid={0}, template-attribute={1}".format(
            self.uid, None)
        expected = "CertifyResponsePayload({0})".format(data)

        self.assertEqual(expected, repr(payload))
        self.assertEqual(expected, str(payload))

    def test__eq(self):
        payload = CertifyResponsePayload(uid=self.uid)
        payload_same = CertifyResponsePayload(uid=self.uid)
        payload_other_uid = CertifyResponsePayload(uid=self.other_uid)

        self.assertTrue(payload == payload_same)
        self.assertTrue(payload != payload_other_uid)
        self.assertTrue(payload != 'invalid')
        self.assertFalse(payload != payload_same)
        self.assertFalse(payload == payload_other_uid)
        self.assertFalse(payload == 'invalid')
