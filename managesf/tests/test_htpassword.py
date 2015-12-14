#!/usr/bin/env python
#
# Copyright (C) 2015 Red Hat <licensing@enovance.com>
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
from managesf.controllers import htp
from managesf.tests import dummy_conf


class TestHtpasswd(TestCase):
    @classmethod
    def setupClass(cls):
        cls.conf = dummy_conf()
        cls.htp = htp.Htpasswd(cls.conf)

    def test_user_as_api_password(self):
        self.htp.delete('bob')
        self.assertTrue(not self.htp.user_has_api_password('bob'))
        self.htp.set_api_password('bob')
        self.assertTrue(self.htp.user_has_api_password('bob'))

    def test_set_api_password(self):
        self.assertEqual(12,
                         len(self.htp.set_api_password('alice')))
