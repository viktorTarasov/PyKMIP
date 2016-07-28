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

from kmip.core import enums
from kmip.core import objects
from kmip.core import primitives
from kmip.core import utils


class NotifyRequestPayload(primitives.Struct):
    """
    A request payload for the Notify operation.

    The payload can contain the ID of the managed object the attributes
    that has been changed.
    See Section 5.1 of the KMIP 1.1 specification for more information.

    Attributes:
        uid: The unique ID of the managed object some of the attributes
            of which have been changed.
        attribute: Changed attribute associated with managed object
    """
    def __init__(self, uid=None, attributes=None):
        """
        Construct a Notify request payload.

        Args:
            uid (string): The ID of the managed object with which a new
                attribute should be associated. Optional, defaults to None.
            attributes (list of Attributes): required, changed attributes
                associated with managed object.
        """
        super(NotifyRequestPayload, self).__init__(
            enums.Tags.REQUEST_PAYLOAD)
        self.uid = uid
        if attributes is None:
            self.attributes = list()
        else:
            self.attributes = attributes

        self.validate()

    def read(self, istream):
        """
        Read the data encoding the Notify request payload and decode
        it into its constituent parts.

        Args:
            istream (stream): A data stream containing encoded object data,
                supporting a read method; usually a BytearrayStream object.
        """
        super(NotifyRequestPayload, self).read(istream)
        tstream = utils.BytearrayStream(istream.read(self.length))

        self.uid = None
        if self.is_tag_next(enums.Tags.UNIQUE_IDENTIFIER, tstream):
            uid = primitives.TextString(tag=enums.Tags.UNIQUE_IDENTIFIER)
            uid.read(tstream)
            self.uid = uid.value

        while self.is_tag_next(enums.Tags.ATTRIBUTE, tstream):
            attribute = objects.Attribute()
            attribute.read(tstream)
            self.attributes.append(attribute)

        self.is_oversized(tstream)
        self.validate()

    def write(self, ostream):
        """
        Write the data encoding the Notify request payload to a
        stream.

        Args:
            ostream (stream): A data stream in which to encode object data,
                supporting a write method; usually a BytearrayStream object.
        """
        tstream = utils.BytearrayStream()

        if self.uid:
            uid = primitives.TextString(
                value=self.uid, tag=enums.Tags.UNIQUE_IDENTIFIER)
            uid.write(tstream)

        for attribute in self.attributes:
            attribute.write(tstream)

        self.length = tstream.length()
        super(NotifyRequestPayload, self).write(ostream)
        ostream.write(tstream.buffer)

    def validate(self):
        """
        Error check the attributes of the Notify request payload.
        """
        if self.uid is not None:
            if not isinstance(self.uid, six.string_types):
                raise TypeError(
                    "uid must be a string; "
                    "expected (one of): {0}, observed: {1}".format(
                        six.string_types, type(self.uid)))
        if self.attributes is not None:
            if not isinstance(self.attributes, list):
                raise TypeError(
                    "attributes must be a list, "
                    "observed: {0}".format(type(self.attributes)))
            for attribute in self.attributes:
                if not isinstance(attribute, objects.Attribute):
                    raise TypeError(
                        "attributes must be list of Attribute objects, "
                        "observed: {0}".format(type(attribute)))

    def __repr__(self):
        uid = "uid={0}".format(self.uid)
        attributes = ""
        for attribute in self.attributes:
            str_attr = "({0}:{1})".format(
                attribute.attribute_name,
                attribute.attribute_value)
            attributes += (", " if len(attributes) else "") + str_attr
        return "NotifyRequestPayload({0}, attributes=[{1}])".format(
            uid,
            attributes)

    def __str__(self):
        return self.__repr__()

    def __eq__(self, other):
        if isinstance(other, NotifyRequestPayload):
            if self.uid != other.uid:
                return False
            elif self.attributes != other.attributes:
                return False
            else:
                return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, NotifyRequestPayload):
            return not self.__eq__(other)
        else:
            return NotImplemented


class NotifyResponsePayload(primitives.Struct):
    """
    A response payload for the Notify operation.
    """
    def __init__(self, uid=None, attribute=None):
        """
        Construct a Notify response payload.

        Args:
            uid (string): required, the ID of the managed object with which a
                new attribute has been associated.
            attribute (Attribute): required, the added attribute
                associated with the object
        """
        super(NotifyResponsePayload, self).__init__(
            enums.Tags.RESPONSE_PAYLOAD)

        self.validate()

    def read(self, istream):
        """
        Read the data encoding the Notify response payload and decode
        it into its constituent parts.

        Args:
            istream (stream): A data stream containing encoded object data,
                supporting a read method; usually a BytearrayStream object.
        """
        super(NotifyResponsePayload, self).read(istream)
        tstream = utils.BytearrayStream(istream.read(self.length))

        self.is_oversized(tstream)
        self.validate()

    def write(self, ostream):
        """
        Write the data encoding the Notify response payload to a
        stream.

        Args:
            ostream (stream): A data stream in which to encode object data,
                supporting a write method; usually a BytearrayStream object.
        """
        tstream = utils.BytearrayStream()

        self.length = tstream.length()
        super(NotifyResponsePayload, self).write(ostream)
        ostream.write(tstream.buffer)

    def validate(self):
        """
        Error check the attributes of the Notify response payload.
        """
        pass

    def __repr__(self):
        return "NotifyResponsePayload()"

    def __str__(self):
        return self.__repr__()

    def __eq__(self, other):
        if isinstance(other, NotifyResponsePayload):
            return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, NotifyResponsePayload):
            return not self.__eq__(other)
        else:
            return NotImplemented
