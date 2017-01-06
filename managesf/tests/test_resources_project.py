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

from mock import patch

from managesf.tests import dummy_conf
from managesf.model.yamlbkd.resources.project import ProjectOps


class ProjectOpsTest(TestCase):
    @classmethod
    def setupClass(cls):
        cls.conf = dummy_conf()

    def test_create(self):
        p = ProjectOps(self.conf, None)
        with patch.object(p.stb_ops, 'is_activated') as is_activated:
            is_activated.return_value = True
            with patch.object(p.stb_ops, 'update_project_groups') as c:
                logs = p.create()
                self.assertTrue(c.called)
                self.assertEqual(len(logs), 0)
            is_activated.return_value = False
            with patch.object(p.stb_ops, 'update_project_groups') as c:
                logs = p.create()
                self.assertFalse(c.called)
                self.assertEqual(len(logs), 0)
            is_activated.return_value = True
            with patch.object(p.stb_ops, 'update_project_groups') as c:
                c.side_effect = Exception('xyz')
                logs = p.create()
                self.assertTrue(c.called)
                self.assertEqual(len(logs), 1)
                self.assertIn('xyz', logs[0])

    def test_update(self):
        p = ProjectOps(self.conf, None)
        with patch.object(p.stb_ops, 'is_activated') as is_activated:
            is_activated.return_value = True
            with patch.object(p.stb_ops, 'update_project_groups') as c:
                logs = p.update()
                self.assertTrue(c.called)
                self.assertEqual(len(logs), 0)
            is_activated.return_value = False
            with patch.object(p.stb_ops, 'update_project_groups') as c:
                logs = p.update()
                self.assertFalse(c.called)
                self.assertEqual(len(logs), 0)
            is_activated.return_value = True
            with patch.object(p.stb_ops, 'update_project_groups') as c:
                c.side_effect = Exception('xyz')
                logs = p.update()
                self.assertTrue(c.called)
                self.assertEqual(len(logs), 1)
                self.assertIn('xyz', logs[0])

    def test_delete(self):
        p = ProjectOps(self.conf, None)
        with patch.object(p.stb_ops, 'is_activated') as is_activated:
            is_activated.return_value = True
            with patch.object(p.stb_ops, 'delete_project_groups') as c:
                logs = p.delete()
                self.assertTrue(c.called)
                self.assertEqual(len(logs), 0)
            is_activated.return_value = False
            with patch.object(p.stb_ops, 'delete_project_groups') as c:
                logs = p.delete()
                self.assertFalse(c.called)
                self.assertEqual(len(logs), 0)
            is_activated.return_value = True
            with patch.object(p.stb_ops, 'delete_project_groups') as c:
                c.side_effect = Exception('xyz')
                logs = p.delete()
                self.assertTrue(c.called)
                self.assertEqual(len(logs), 1)
                self.assertIn('xyz', logs[0])

    def test_extra_validations(self):
        p = ProjectOps(self.conf, None)
        with patch.object(p.stb_ops, 'is_activated') as is_activated:
            is_activated.return_value = True
            with patch.object(p.stb_ops, 'extra_validations') as c:
                c.return_value = []
                logs = p.extra_validations()
                self.assertTrue(c.called)
                self.assertEqual(len(logs), 0)
            is_activated.return_value = False
            with patch.object(p.stb_ops, 'extra_validations') as c:
                logs = p.extra_validations()
                self.assertFalse(c.called)
                self.assertEqual(len(logs), 0)
