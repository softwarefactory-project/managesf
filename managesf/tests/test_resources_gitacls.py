# -*- coding: utf-8 -*-
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

from managesf.model.yamlbkd.resources.gitacls import ACLOps


class TestACLOps(TestCase):

    def test_extra_validations(self):
        kwargs = {'file': 'invalid ACLs !',
                  'groups': []}
        o = ACLOps(None, None)
        logs = o.extra_validations(**kwargs)
        self.assertTrue(logs[0].startswith(
            "File contains no section headers."))
        self.assertEqual(len(logs), 1)

        kwargs = {'file': '',
                  'groups': []}
        o = ACLOps(None, None)
        logs = o.extra_validations(**kwargs)
        self.assertEqual(len(logs), 0)

        kwargs = {'file': """[project]
\tdescription = "My awesome project"
[access "refs/*"]
\tread = group coders
""",
                  'groups': ['mygid']}
        new = {
            'resources': {
                'groups': {
                    'mygid': {
                        'name': 'coders',
                        'namespace': '',
                        'members': ['body@sftests.com'],
                    }
                }
            }
        }
        o = ACLOps(None, new)
        logs = o.extra_validations(**kwargs)
        self.assertEqual(len(logs), 0)

        new = {
            'resources': {
                'groups': {
                    'mygid': {
                        'name': 'pchitt',
                        'namespace': '',
                        'members': ['body@sftests.com'],
                    }
                }
            }
        }
        o = ACLOps(None, new)
        logs = o.extra_validations(**kwargs)
        self.assertEqual(len(logs), 1)
        self.assertIn('ACLs file section (access "refs/*"), key '
                      '(read) relies on an unknown group name: coders',
                      logs)
