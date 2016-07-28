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
from kmip.core.attributes import ContactInformation
from kmip.core.enums import AttributeType
from kmip.core.factories.attributes import AttributeFactory
from kmip.core.messages.payloads import notify
from kmip.core.primitives import DateTime


class TestNotifyPayload(TestCase):

    def setUp(self):
        super(TestNotifyPayload, self).setUp()

        self.attr_factory = AttributeFactory()
        self.name_uid = 'b4faee10-aa2a-4446-8ad4-0881f3422959'
        self.ci_uid = '3'
        self.ci_label = AttributeType.CONTACT_INFORMATION.value
        self.ci_value = 'https://github.com/OpenKMIP/PyKMIP'
        self.ci_uid_bis = '4'
        self.ci_value_bis = 'https://github.com/OpenSC/OpenSC'

        self.datetime = datetime.datetime(2016, 7, 28, 10, 15, 47)
        self.last_change_date = int(self.datetime.timestamp())
        self.last_change_date_bis = self.last_change_date + 1

        self.uid_invalid = 1234
        self.attr_invalid = "invalid"

        self.attr_contact_information = self.attr_factory.create_attribute(
            AttributeType.CONTACT_INFORMATION,
            self.ci_value)
        self.attr_contact_information_bis = self.attr_factory.create_attribute(
            AttributeType.CONTACT_INFORMATION,
            self.ci_value_bis)

        self.attr_last_change_date = self.attr_factory.create_attribute(
            AttributeType.LAST_CHANGE_DATE,
            self.last_change_date)
        self.attr_last_change_date_bis = self.attr_factory.create_attribute(
            AttributeType.LAST_CHANGE_DATE,
            self.last_change_date_bis)

        self.attributes = [self.attr_last_change_date,
                           self.attr_contact_information]
        self.attributes_bis = [self.attr_last_change_date_bis,
                               self.attr_contact_information]
        self.attributes_ter = [self.attr_last_change_date,
                               self.attr_contact_information_bis]

        '''
        <RequestPayload>
          <UniqueIdentifier type="TextString" value="3"/>
          <Attribute>
            <AttributeName type="TextString" value="Last Change Date"/>
            <AttributeValue type="DateTime" value="2016-07-28T10:15:47+00:00"/>
          </Attribute>
          <Attribute>
            <AttributeName type="TextString" value="Contact Information"/>
            <AttributeValue type="TextString" value="https://github.com/Ope...
          </Attribute>
        </RequestPayload>
        '''
        self.blob_request = binascii.unhexlify(
            '4200790100000098420094070000000133000000000000004200080100000028'
            '42000a07000000104c617374204368616e6765204461746542000b0900000008'
            '000000005799bf33420008010000005042000a0700000013436f6e7461637420'
            '496e666f726d6174696f6e000000000042000b070000002268747470733a2f2f'
            '6769746875622e636f6d2f4f70656e4b4d49502f50794b4d4950000000000000'
        )


class TestNotifyRequestPayload(TestNotifyPayload):

    def setUp(self):
        super(TestNotifyRequestPayload, self).setUp()

    def tearDown(self):
        super(TestNotifyRequestPayload, self).tearDown()

    def test_init_with_none(self):
        notify.NotifyRequestPayload()

    def test_init_with_args(self):
        notify.NotifyRequestPayload(
            uid=self.ci_uid,
            attributes=self.attributes)

    def test_validate_with_invalid_uid(self):
        args = [self.uid_invalid, self.attributes]
        self.assertRaises(
            TypeError,
            notify.NotifyRequestPayload,
            *args)

    def test_validate_with_invalid_attribute(self):
        args = [self.name_uid, self.attr_invalid]
        error_msg = ("attributes must be a list, "
                     "observed: {0}").format(
                        type(self.attr_invalid))
        self.assertRaisesRegexp(
            TypeError,
            error_msg,
            notify.NotifyRequestPayload,
            *args)

    def test_read(self):
        stream = utils.BytearrayStream((self.blob_request))

        payload = notify.NotifyRequestPayload()
        payload.read(stream)
        self.assertIsInstance(payload.attributes, list)
        for attribute in payload.attributes:
            self.assertIsInstance(attribute, objects.Attribute)

        self.assertEqual(
            payload.attributes[1].attribute_name.value,
            self.ci_label)
        self.assertIsInstance(
            payload.attributes[1].attribute_value,
            ContactInformation)
        self.assertEqual(
            payload.attributes[1].attribute_value.value,
            self.ci_value)

        self.assertEqual(
            payload.attributes[0].attribute_name.value,
            AttributeType.LAST_CHANGE_DATE.value)
        self.assertIsInstance(
            payload.attributes[0].attribute_value,
            DateTime)
        self.assertEqual(
            payload.attributes[0].attribute_value.value,
            self.last_change_date)

    def test_write(self):
        stream = utils.BytearrayStream()
        expected = self.blob_request

        payload = notify.NotifyRequestPayload(
            uid=self.ci_uid,
            attributes=self.attributes)

        payload.write(stream)
        print("Received: {0}".format(stream))

        length_expected = len(expected)
        length_received = len(stream)

        msg = "encoding lengths not equal"
        msg += "; expected {0}, received {1}".format(
            length_expected, length_received)
        self.assertEqual(length_expected, length_received, msg)

        msg = "encoding mismatch"
        msg += ";\nexpected:\n{0}\nreceived:\n{1}".format(expected, stream)
        self.assertEqual(expected, stream.buffer, msg)

    def test_repr_str(self):
        payload = notify.NotifyRequestPayload(
            uid=self.ci_uid,
            attributes=self.attributes)

        expected = "NotifyRequestPayload(uid={0}, ".format(self.ci_uid)
        expected += "attributes=[({0}:{1}), ({2}:{3})])".format(
            self.attr_last_change_date.attribute_name,
            self.attr_last_change_date.attribute_value,
            self.attr_contact_information.attribute_name,
            self.attr_contact_information.attribute_value)

        self.assertEqual(expected, repr(payload))
        self.assertEqual(expected, str(payload))

    def test__eq(self):
        payload = notify.NotifyRequestPayload(
            uid=self.ci_uid,
            attributes=self.attributes)
        payload_same = notify.NotifyRequestPayload(
            uid=self.ci_uid,
            attributes=self.attributes)

        payload_other_uid = notify.NotifyRequestPayload(
            uid=self.ci_uid_bis,
            attributes=self.attributes)
        payload_other_attributes = notify.NotifyRequestPayload(
            uid=self.ci_uid,
            attributes=self.attributes_bis)
        payload_other_attributes_ter = notify.NotifyRequestPayload(
            uid=self.ci_uid,
            attributes=self.attributes_ter)

        self.assertTrue(payload == payload_same)
        self.assertTrue(payload != payload_other_uid)
        self.assertTrue(payload != payload_other_attributes)
        self.assertTrue(payload != payload_other_attributes_ter)
        self.assertTrue(payload != 'invalid')
        self.assertFalse(payload != payload_same)
        self.assertFalse(payload == payload_other_uid)
        self.assertFalse(payload == payload_other_attributes)
        self.assertFalse(payload == payload_other_attributes_ter)
        self.assertFalse(payload == 'invalid')
