# Copyright (c) 2014 The Johns Hopkins University/Applied Physics Laboratory
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

from kmip.services.server.repo.repo import ManagedObjectRepo
from kmip.core.attributes import UniqueIdentifier
from kmip.core.enums import AttributeType
from kmip.core.enums import ObjectGroupMember
from kmip.core.enums import StorageStatusMask
from kmip.core.objects import Attribute

class MemRepo(ManagedObjectRepo):

    def __init__(self):
        self.repo = {}
        self.uuid = 1

    def save(self, managed_object, attributes):
        # TODO (nate) verify the parameters
        uuid = "{0}".format(self.uuid)
        self.repo[uuid] = (managed_object, attributes)
        self.uuid += 1

        return uuid

    def get(self, uuid):
        if uuid is None or uuid not in self.repo:
            return (None, None)
        return self.repo[uuid]

    def update(self, uuid, managed_object, attributes):
        if uuid is None:
            return False
        self.repo[uuid] = (managed_object, attributes)
        return True

    def delete(self, uuid):
        if uuid is None or uuid not in self.repo:
            return False
        del self.repo[uuid]
        return True

    def locate(self, maximum_items, storage_status_mask,
               object_group_member, attributes):
        result = list()

        if maximum_items != None and  maximum_items.value == 0:
                return result

        for idx in self.repo:
            (managed_object, obj_attributes) = self.repo[idx]

            matched_attrs = 0
            fresh = False
            have_archive_date = False

            for attr in obj_attributes:
                for lattr in attributes:
                    if (attr.attribute_name == lattr.attribute_name
                            and attr.attribute_value == lattr.attribute_value) :
                        matched_attrs += 1

                if attr.attribute_name.value == AttributeType.FRESH.value:
                    fresh = attr.attribute_value

                if attr.attribute_name.value == AttributeType.ARCHIVE_DATE.value:
                    have_archive_date = True

            if object_group_member != None:
                if object_group_member.value == ObjectGroupMember.GROUP_MEMBER_FRESH:
                     if not fresh :
                         continue
                else:
                     if fresh :
                         continue

            if storage_status_mask != None:
                if storage_status_mask.value == StorageStatusMask.ARCHIVAL_STORAGE:
                    if not have_archive_date:
                        continue
                if storage_status_mask.value == StorageStatusMask.ONLINE_STORAGE:
                    if have_archive_date:
                        continue

            if matched_attrs == len(attributes):
                result.append(UniqueIdentifier(idx))

            if maximum_items != None and maximum_items.value <= len(result):
                break

        return result

