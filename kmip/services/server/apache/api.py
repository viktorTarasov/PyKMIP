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

from abc import ABCMeta
from abc import abstractmethod

import six


@six.add_metaclass(ABCMeta)
class ApacheServerEngine(object):
    """
    The abstract base class of the Apache Server Config engine.
    """

    @abstractmethod
    def set_certificate_file(self, certificate=None):
        """
        Set certificate
        """
    def set_private_key_file(self, private_key=None):
        """
        Set private key
        """