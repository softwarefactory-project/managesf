# Copyright (C) 2017 Red Hat
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.


from unittest import TestCase

from managesf.api.v2 import base
from managesf.tests import dummy_conf


class TestAPIv2Service(TestCase):
    @classmethod
    def setupClass(cls):
        cls.conf = dummy_conf()

        class DummyService(base.BaseService):
            _config_section = "DummyService"
            service_name = "dummy service"

        cls.service = DummyService(cls.conf)

    @classmethod
    def tearDownClass(cls):
        pass

    def test_baseService(self):
        """Test loading configuration at service instantiation"""
        self.assertEqual(self.conf.DummyService['dummy_opt1'],
                         self.service.conf.get('dummy_opt1'))
