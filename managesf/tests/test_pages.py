#
# Copyright (c) 2016 Red Hat, Inc.
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


from managesf.controllers import pages
from managesf.tests import dummy_conf


class TestLocaluserController(TestCase):
    @classmethod
    def setupClass(cls):
        cls.conf = dummy_conf()
        pages.conf = cls.conf

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_pages_internal(self):
        target1 = 'http://content.target1/'
        target2 = 'http://content.target2/'
        target3 = 'http://content.target3/'

        # Associate target to project
        new = pages.update_content_url('p1', {'url': target1})
        # Check the return code
        self.assertEqual(new, True)

        # Check we can retrieve the setting
        ret = pages.get_content_url('p1')
        self.assertEqual(ret, target1)

        # Associate target to project the same project and check return code
        new = pages.update_content_url('p1', {'url': target2})
        self.assertEqual(new, False)

        # Associate target to another procject and check return code
        new = pages.update_content_url('p2', {'url': target3})
        self.assertEqual(new, True)
        ret = pages.get_content_url('p2')
        self.assertEqual(ret, target3)

        # Associate a non valide target
        self.assertRaises(pages.InvalidInfosInput,
                          lambda: pages.update_content_url('p2',
                                                           {'url': 'invalid'}))

        # Check we can an error when getting a non existing entry
        self.assertRaises(pages.PageNotFound,
                          lambda: pages.get_content_url('p3'))

        # Check we can delete an entry
        ret = pages.delete_content_url('p2')
        self.assertEqual(ret, True)
        self.assertRaises(pages.PageNotFound,
                          lambda: pages.delete_content_url('p2'))
        ret = pages.delete_content_url('p1')
        self.assertEqual(ret, True)
        self.assertRaises(pages.PageNotFound,
                          lambda: pages.delete_content_url('p1'))
