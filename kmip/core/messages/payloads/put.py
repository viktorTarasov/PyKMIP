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

from kmip.core.factories.secrets import SecretFactory

from kmip.core import enums
from kmip.core import objects
from kmip.core import primitives
from kmip.core import utils
from kmip.core import misc


class PutRequestPayload(primitives.Struct):
    """
    A request payload for the Put operation.

    The payload can contain the ID of the managed object the attributes
    that has been changed.
    See Section 5.1 of the KMIP 1.1 specification for more information.

    Attributes:
        uid: The unique ID of the managed object some of the attributes
            of which have been changed.
        attribute: Changed attribute associated with managed object
    """
    def __init__(self, uid=None, put_function=None, replaced_uid=None,
                 object_data=None, attributes=None):
        """
        Construct a Put request payload.

        Args:
            uid (string): The ID of the managed object with which a new
                attribute should be associated. Optional, defaults to None.
            put_function(enums.PutFunction): Indicates function for
                Put message.
            replaced_uid(string): ID of replaced managed object
            object_data(core.Secrets): managed object with 'value' attribute
            attributes (list of Attributes): required, changed attributes
                associated with managed object.
        """
        super(PutRequestPayload, self).__init__(enums.Tags.REQUEST_PAYLOAD)
        self.secret_factory = SecretFactory()

        if isinstance(uid, int):
            uid = str(uid)
        self.uid = uid

        if isinstance(put_function, six.string_types):
            if put_function.uppper() == 'NEW':
                put_function = misc.PutFunctionType(enums.PutFunction.NEW)
            elif put_function.uppper() == 'REPLACE':
                put_function = misc.PutFunctionType(enums.PutFunction.REPLACE)
        elif isinstance(put_function, enums.PutFunction):
            put_function = misc.PutFunctionType(put_function)
        self.put_function = put_function

        self.object_data = object_data

        if replaced_uid is None:
            self.replaced_uid = None
        else:
            self.replaced_uid = replaced_uid

        if attributes is None:
            self.attributes = list()
        else:
            self.attributes = attributes

        self.validate()

    def read(self, istream):
        """
        Read the data encoding the Put request payload and decode
        it into its constituent parts.

        Args:
            istream (stream): A data stream containing encoded object data,
                supporting a read method; usually a BytearrayStream object.
        """
        super(PutRequestPayload, self).read(istream)
        tstream = utils.BytearrayStream(istream.read(self.length))

        uid = primitives.TextString(tag=enums.Tags.UNIQUE_IDENTIFIER)
        uid.read(tstream)
        self.uid = uid.value

        self.put_function = misc.PutFunctionType()
        self.put_function.read(tstream)

        if self.is_tag_next(enums.Tags.REPLACED_UNIQUE_IDENTIFIER, tstream):
            replaced_uid = primitives.TextString(tag=enums.Tags.REPLACED_UNIQUE_IDENTIFIER)
            replaced_uid.read(tstream)
            self.replaced_uid = replaced_uid.value

        if self.is_tag_next(enums.Tags.PRIVATE_KEY, tstream):
            secret = self.secret_factory.create(enums.ObjectType.PRIVATE_KEY)
            secret.read(tstream)
            self.object_data = secret
        elif self.is_tag_next(enums.Tags.CERTIFICATE, tstream):
            secret = self.secret_factory.create(enums.ObjectType.CERTIFICATE)
            secret.read(tstream)
            self.object_data = secret


        while self.is_tag_next(enums.Tags.ATTRIBUTE, tstream):
            attribute = objects.Attribute()
            attribute.read(tstream)
            self.attributes.append(attribute)

        self.is_oversized(tstream)
        self.validate()

    def write(self, ostream):
        """
        Write the data encoding the Put request payload to a
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

        if self.put_function:
            self.put_function.write(tstream)

        if self.replaced_uid:
            replaced_uid = primitives.TextString(
                value=self.replaced_uid,
                tag=enums.Tags.REPLACED_UNIQUE_IDENTIFIER)
            replaced_uid.write(tstream)

        if self.object_data:
            self.object_data.write(tstream)

        for attribute in self.attributes:
            attribute.write(tstream)

        self.length = tstream.length()
        super(PutRequestPayload, self).write(ostream)
        ostream.write(tstream.buffer)

    def validate(self):
        """
        Error check the attributes of the Put request payload.
        """
        if self.uid is not None:
            if not isinstance(self.uid, six.string_types):
                raise TypeError(
                    "uid must be a string; "
                    "expected (one of): {0}, observed: {1}".format(
                        six.string_types, type(self.uid)))

        if self.replaced_uid is not None:
            if not isinstance(self.replaced_uid, six.string_types):
                raise TypeError(
                    "replaced uid must be a string; "
                    "expected (one of): {0}, observed: {1}".format(
                        six.string_types, type(self.replaced_uid)))

        if self.put_function is not None:
            if not isinstance(self.put_function, misc.PutFunctionType):
                raise TypeError(
                    "Invalid type of PutFunction "
                    "expected: {0}, observed: {1}".format(
                        misc.PutFunctionType.__class__.__name__,
                        type(self.replaced_uid)))

        if self.object_data is not None:
            if not isinstance(self.object_data, primitives.Struct):
                raise TypeError(
                    "Invalid type of object data"
                    "expected: {0}, observed: {1}".format(
                        primitives.Struct.__class__.__name__,
                        type(self.object_data)))

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
        replaced_uid = "replaced-uid={0}".format(self.replaced_uid)
        put_function = "put-function={0}".format(self.put_function)
        attributes = ""
        for attribute in self.attributes:
            str_attr = "({0}:{1})".format(
                attribute.attribute_name,
                attribute.attribute_value)
            attributes += (", " if len(attributes) else "") + str_attr
        return "PutRequestPayload({0}, {1}, {2}, attributes=[{3}])".format(
            uid, replaced_uid, put_function,
            attributes)

    def __str__(self):
        return self.__repr__()

    def __eq__(self, other):
        if isinstance(other, PutRequestPayload):
            if self.uid != other.uid:
                return False
            elif self.attributes != other.attributes:
                return False
            else:
                return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, PutRequestPayload):
            return not self.__eq__(other)
        else:
            return NotImplemented


class PutResponsePayload(primitives.Struct):
    """
    A response payload for the Put operation.
    """
    def __init__(self, uid=None, attribute=None):
        """
        Construct a Put response payload.

        Args:
            uid (string): required, the ID of the managed object with which a
                new attribute has been associated.
            attribute (Attribute): required, the added attribute
                associated with the object
        """
        super(PutResponsePayload, self).__init__(
            enums.Tags.RESPONSE_PAYLOAD)

        self.validate()

    def read(self, istream):
        """
        Read the data encoding the Put response payload and decode
        it into its constituent parts.

        Args:
            istream (stream): A data stream containing encoded object data,
                supporting a read method; usually a BytearrayStream object.
        """
        super(PutResponsePayload, self).read(istream)
        tstream = utils.BytearrayStream(istream.read(self.length))

        self.is_oversized(tstream)
        self.validate()

    def write(self, ostream):
        """
        Write the data encoding the Put response payload to a
        stream.

        Args:
            ostream (stream): A data stream in which to encode object data,
                supporting a write method; usually a BytearrayStream object.
        """
        tstream = utils.BytearrayStream()

        self.length = tstream.length()
        super(PutResponsePayload, self).write(ostream)
        ostream.write(tstream.buffer)

    def validate(self):
        """
        Error check the attributes of the Put response payload.
        """
        pass

    def __repr__(self):
        return "PutResponsePayload()"

    def __str__(self):
        return self.__repr__()

    def __eq__(self, other):
        if isinstance(other, PutResponsePayload):
            return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, PutResponsePayload):
            return not self.__eq__(other)
        else:
            return NotImplemented
