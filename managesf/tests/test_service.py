#!/usr/bin/env python
#
# Copyright (C) 2015  Red Hat <licensing@enovance.com>
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
import time

from managesf.services import exceptions as exc
from managesf.services import base
from managesf.tests import dummy_conf


class DummyHooksManager(base.BaseHooksManager):
    def patchset_created(self, *args, **kwargs):
        return 1

    def change_merged(self, *args, **kwargs):
        return 2


class BaseServiceForTest(base.BaseServicePlugin):
    def __init__(self, conf):
        super(BaseServiceForTest, self).__init__(conf)
        self.hooks = DummyHooksManager(self)

    def configure_plugin(self, conf):
        self.conf = conf

    def _get_client(self, cookie=None, **kwargs):
        if time.time() > 1000:
            return "client2"
        else:
            return "client1"


class TestService(TestCase):
    @classmethod
    def setupClass(cls):
        cls.conf = dummy_conf()
        cls.service = BaseServiceForTest(cls.conf)

    @classmethod
    def tearDownClass(cls):
        pass

    def test_is_admin(self):
        self.assertEqual(True,
                         self.service.role.is_admin(self.conf.admin['name']))
        self.assertEqual(False,
                         self.service.role.is_admin('YOLO LMAO'))

    def test_hooks(self):
        self.assertEqual(1,
                         self.service.hooks.patchset_created())
        self.assertEqual(2,
                         self.service.hooks.change_merged())
        self.assertRaises(exc.UnavailableActionError,
                          self.service.hooks.random_undefined_hook,
                          'dummy argument')
