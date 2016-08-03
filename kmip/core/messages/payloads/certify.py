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

import six

from kmip.core import exceptions
from kmip.core import objects
from kmip.core import primitives
from kmip.core import utils

from kmip.core.enums import Tags
from kmip.core.enums import CertificateRequestType
from kmip.core.primitives import ByteString
from kmip.core.primitives import TextString
from kmip.core.objects import TemplateAttribute


class CertifyRequestPayload(primitives.Struct):
    """
    A request payload for the Certify operation.

    The payload can contain
        the ID of the PublicKey being certified,
        Certificate Request together with Certificate Request Type,
    and template attribute;

    See Section 4.7 of the KMIP 1.1 specification for more information.
    """

    # 9.1.3.2.22 Certificate Request Type Enumeration
    class CertificateRequestType(primitives.Enumeration):
        def __init__(self, value=None):
            super(CertifyRequestPayload.CertificateRequestType, self).__init__(
                CertificateRequestType, value, Tags.CERTIFICATE_REQUEST_TYPE)

    def __init__(self, uid=None, certificate_request_type=None,
                 certificate_request=None, template_attribute=None):
        """
        Construct a Certify request payload.

        Args:
            uid (string): The unique ID of the Public Key to be certified
            certificate_request_type (enum): type of Certificate Request
            certificate_request (blob): blob of Certificate Request
            template_attribute: client defined attributes to be associated with
                                resulting Certificate object
        """
        super(CertifyRequestPayload, self).__init__(Tags.REQUEST_PAYLOAD)

        self.uid = uid

        if isinstance(certificate_request_type, CertificateRequestType):
            self.certificate_request_type = \
                CertifyRequestPayload.CertificateRequestType(
                    certificate_request_type)
        else:
            self.certificate_request_type = certificate_request_type

        self.certificate_request = certificate_request

        self.template_attribute = template_attribute

        self.validate()

    def read(self, istream):
        """
        Read the data encoding the Certify request payload and decode
        it into its constituent parts.

        Args:
            istream (stream): A data stream containing encoded object data,
                supporting a read method; usually a BytearrayStream object.
        """
        super(CertifyRequestPayload, self).read(istream)
        tstream = utils.BytearrayStream(istream.read(self.length))

        self.uid = None
        if self.is_tag_next(Tags.UNIQUE_IDENTIFIER, tstream):
            uid = TextString(tag=Tags.UNIQUE_IDENTIFIER)
            uid.read(tstream)
            self.uid = uid.value

        if self.is_tag_next(Tags.CERTIFICATE_REQUEST_TYPE, tstream):
            request_type = CertifyRequestPayload.CertificateRequestType()
            request_type.read(tstream)
            self.certificate_request_type = request_type

        if self.is_tag_next(Tags.CERTIFICATE_REQUEST, tstream):
            blob = ByteString(tag=Tags.CERTIFICATE_REQUEST)
            blob.read(tstream)
            self.certificate_request = blob.value

        if self.is_tag_next(Tags.TEMPLATE_ATTRIBUTE, tstream):
            self.template_attribute = TemplateAttribute()
            self.template_attribute.read(tstream)

        self.is_oversized(tstream)
        self.validate()

    def write(self, ostream):
        """
        Write the data encoding the Certify request payload to a
        stream.

        Args:
            ostream (stream): A data stream in which to encode object data,
                supporting a write method; usually a BytearrayStream object.
        """
        tstream = utils.BytearrayStream()

        if self.uid:
            uid = TextString(value=self.uid, tag=Tags.UNIQUE_IDENTIFIER)
            uid.write(tstream)

        if self.certificate_request_type:
            self.certificate_request_type.write(tstream)

        if self.certificate_request:
            request = ByteString(
                value=self.certificate_request,
                tag=Tags.CERTIFICATE_REQUEST)
            request.write(tstream)

        if self.template_attribute:
            self.template_attribute.write(tstream)

        self.length = tstream.length()
        super(CertifyRequestPayload, self).write(ostream)
        ostream.write(tstream.buffer)

    def validate(self):
        """
        Error check the attributes of the Certify request payload.
        """
        rtype = self.certificate_request_type
        rblob = self.certificate_request
        if self.uid is not None:
            if (rtype is not None) or (rblob is not None):
                msg = (
                    "ambiguous arguments: if PublicKey UID is defined "
                    "neither CertificateRequest nor CertificateRequestType "
                    "have to be present")
                raise TypeError(msg)
            if not isinstance(self.uid, six.string_types):
                raise TypeError(
                    "uid must be a string; "
                    "expected (one of): {0}, observed: {1}".format(
                        six.string_types, type(self.uid)))
        elif rtype is not None and rblob is not None:
            expected_data_type = CertifyRequestPayload.CertificateRequestType
            if not isinstance(rtype, expected_data_type):
                msg = (
                    "Certificate Request Type must be a enumeration; "
                    "expected: {0}, observed: {1}".format(
                        CertifyRequestPayload.CertificateRequestType,
                        type(rtype)))
                raise TypeError(msg)

            if not isinstance(rblob, bytes):
                msg = (
                    "Certificate Request must be a Byte String; "
                    "expected: {0}, observed: {1}".format(
                        bytes, type(rblob)))
                raise TypeError(msg)
        elif (rtype is None) != (rblob is None):
            msg = (
                "invalid arguments: CertificateRequest and "
                "CertificateRequestType have both to be defined or noone")
            raise TypeError(msg)

        if self.template_attribute is not None:
            if not isinstance(self.template_attribute, TemplateAttribute):
                msg = "invalid template attribute"
                msg += "; expected {0}, received {1}".format(
                    objects.TemplateAttribute,
                    self.template_attribute)
                raise TypeError(msg)

    def __repr__(self):
        value = "public_key_uid={0}, certificate_request({1})={2}".format(
            self.uid, self.certificate_request_type, self.certificate_request)
        return "CertifyRequestPayload({0}, template_attribute={1})".format(
            value,
            self.template_attribute)

    def __str__(self):
        return self.__repr__()

    def __eq__(self, other):
        if isinstance(other, CertifyRequestPayload):
            if self.uid != other.uid:
                return False
            elif self.certificate_request_type != \
                    other.certificate_request_type:
                return False
            elif self.certificate_request != other.certificate_request:
                return False
            elif self.template_attribute != other.template_attribute:
                return False
            else:
                return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, CertifyRequestPayload):
            return not self.__eq__(other)
        else:
            return NotImplemented


class CertifyResponsePayload(primitives.Struct):
    """
    A response payload for the Certify operation.

    The payload will contain the ID of newly created Certificate managed object

    See Section 4.7 of the KMIP 1.1 specification for more information.

    Attributes:
        uid: The unique ID of a new Certificate object
        template_attribute: supra attributes defined by server
    """
    def __init__(self, uid=None, template_attribute=None):
        """
        Construct a Certify response payload.

        Args:
            uid (string): required, the ID of the Certicicate
        """
        super(CertifyResponsePayload, self).__init__(Tags.RESPONSE_PAYLOAD)

        self.uid = uid
        self.template_attribute = template_attribute

        self.validate()

    def read(self, istream):
        """
        Read the data encoding the Certify response payload and decode
        it into its constituent parts.

        Args:
            istream (stream): A data stream containing encoded object data,
                supporting a read method; usually a BytearrayStream object.
        """
        super(CertifyResponsePayload, self).read(istream)
        tstream = utils.BytearrayStream(istream.read(self.length))

        if self.is_tag_next(Tags.UNIQUE_IDENTIFIER, tstream):
            uid = primitives.TextString(tag=Tags.UNIQUE_IDENTIFIER)
            uid.read(tstream)
            self.uid = uid.value
        else:
            raise exceptions.InvalidKmipEncoding(
                "expected uid encoding not found")

        if self.is_tag_next(Tags.TEMPLATE_ATTRIBUTE, tstream):
            self.template_attribute = TemplateAttribute()
            self.template_attribute.read(tstream)

        self.is_oversized(tstream)
        self.validate()

    def write(self, ostream):
        """
        Write the data encoding the Certify response payload to a
        stream.

        Args:
            ostream (stream): A data stream in which to encode object data,
                supporting a write method; usually a BytearrayStream object.
        """
        tstream = utils.BytearrayStream()

        uid = primitives.TextString(value=self.uid, tag=Tags.UNIQUE_IDENTIFIER)
        uid.write(tstream)

        if self.template_attribute:
            self.template_attribute.write(tstream)

        self.length = tstream.length()
        super(CertifyResponsePayload, self).write(ostream)
        ostream.write(tstream.buffer)

    def validate(self):
        """
        Error check the attributes of the Certify response payload.
        """
        if self.uid is not None:
            if not isinstance(self.uid, six.string_types):
                raise TypeError(
                    "uid must be a string; "
                    "expected (one of): {0}, observed: {1}".format(
                        six.string_types, type(self.uid)))
        if self.template_attribute is not None:
            if not isinstance(self.template_attribute, TemplateAttribute):
                msg = "invalid template attribute"
                msg += "; expected TemplateAttribute, observed {0}".format(
                    type(self.template_attribute))
                raise TypeError(msg)

    def __repr__(self):
        data = "uid={0}, template-attribute={1}".format(
            self.uid,
            self.template_attribute)
        return "CertifyResponsePayload({0})".format(data)

    def __str__(self):
        return self.__repr__()

    def __eq__(self, other):
        if isinstance(other, CertifyResponsePayload):
            if self.uid != other.uid:
                return False
            elif self.template_attribute != other.template_attribute:
                return False
            else:
                return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, CertifyResponsePayload):
            return not self.__eq__(other)
        else:
            return NotImplemented
