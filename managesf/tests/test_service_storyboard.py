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
from mock import patch
from contextlib import nested

from managesf.services import storyboard
from managesf.tests import dummy_conf


class BaseSFStoryboardService(TestCase):
    @classmethod
    def setupClass(cls):
        cls.conf = dummy_conf()
        cls.storyboard = storyboard.SoftwareFactoryStoryboard(cls.conf)


class TestSFStoryboardUserManager(BaseSFStoryboardService):
    def test_create(self):
        patches = [
            patch.object(self.storyboard.user, 'sql_execute'),
            patch.object(self.storyboard.user, 'get_user'),
            patch.object(self.storyboard.user.users, 'insert'),
            patch.object(self.storyboard.user.users, 'update'),
            patch.object(self.storyboard.user, 'create_update_user_token'),
        ]
        with nested(*patches) as (sql_exec, get_user, insert, update,
                                  create_update_user_token):
            get_user.return_value = None
            self.storyboard.user.create("jdoe", "jdoe@doe.com", "John Doe",
                                        cauth_id=42)
            create_update_user_token.assert_called_once_with(42, "jdoe")
            self.assertEquals(False, update.called)
            self.assertEquals(True, insert.called)

    def test_update(self):
        patches = [
            patch.object(self.storyboard.user, 'sql_execute'),
            patch.object(self.storyboard.user, 'get_user'),
            patch.object(self.storyboard.user.users, 'insert'),
            patch.object(self.storyboard.user.users, 'update'),
            patch.object(self.storyboard.user, 'create_update_user_token'),
        ]
        with nested(*patches) as (sql_exec, get_user, insert, update, token):
            get_user.return_value = 42
            self.storyboard.user.update(42, username="jdoe")
            self.assertEquals(True, update.called)
            self.assertEquals(False, insert.called)

    def test_get(self):
        patches = [patch.object(self.storyboard.user, 'get_user')]
        with nested(*patches) as (get_user,):
            self.storyboard.user.get("test")
            self.assertEquals(True, get_user.called)

    def test_delete(self):
        patches = [
            patch.object(self.storyboard.user, 'sql_execute'),
            patch.object(self.storyboard.user, 'get_user'),
        ]
        with nested(*patches) as (sql_exec, get_user):
            get_user.return_value = 42
            self.storyboard.user.delete(email="jdoe@doe.com")
            sql_exec.assert_called_once()
