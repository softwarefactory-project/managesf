# -*- coding: utf-8 -*-
#
# Copyright (c) 2017 Red Hat, Inc.
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

from managesf.tests import dummy_conf
from managesf.model.yamlbkd.resources.project import ProjectOps


class ProjectOpsTest(TestCase):
    @classmethod
    def setupClass(cls):
        cls.conf = dummy_conf()

    def test_create(self):
        p = ProjectOps(self.conf, None)
        logs = p.create()
        self.assertEqual(len(logs), 0)

    def test_update(self):
        p = ProjectOps(self.conf, None)
        logs = p.update()
        self.assertEqual(len(logs), 0)

    def test_delete(self):
        p = ProjectOps(self.conf, None)
        logs = p.delete()
        self.assertEqual(len(logs), 0)

    def test_extra_validations(self):
        new = {
            'resources': {
                'projects': {
                    'p1': {
                        'source-repositories': []
                    }
                }
            }
        }
        p = ProjectOps(self.conf, new)
        kwargs = {'name': 'p1'}
        logs = p.extra_validations(**kwargs)
        self.assertEqual(len(logs), 0)
