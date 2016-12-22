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

from managesf.services import storyboard
from managesf.tests import dummy_conf
from managesf.controllers.SFuser import SFUserManager


class BaseSFStoryboardService(TestCase):
    @classmethod
    def setupClass(cls):
        cls.conf = dummy_conf()
        cls.storyboard = storyboard.SoftwareFactoryStoryboard(cls.conf)


class TestSFStoryboardUserManager(BaseSFStoryboardService):
    def test_create(self):
        with patch.object(self.storyboard.user, 'sql_execute'), \
                patch.object(self.storyboard.user, 'get_user') as get_user, \
                patch.object(self.storyboard.user.users, 'insert') as ins, \
                patch.object(self.storyboard.user.users, 'update') as upd, \
                patch.object(self.storyboard.user,
                             'create_update_user_token') as cu_user_token:
            get_user.return_value = None
            self.storyboard.user.create("jdoe", "jdoe@doe.com", "John Doe",
                                        cauth_id=42)
            cu_user_token.assert_called_once_with(42, "jdoe")
            self.assertEquals(False, upd.called)
            self.assertEquals(True, ins.called)

    def test_update(self):
        with patch.object(self.storyboard.user, 'sql_execute'), \
                patch.object(self.storyboard.user, 'get_user') as get_user, \
                patch.object(self.storyboard.user.users, 'insert') as ins, \
                patch.object(self.storyboard.user.users, 'update') as upd, \
                patch.object(SFUserManager, 'get') as get, \
                patch.object(self.storyboard.user,
                             'create_update_user_token') as token:
            get_user.return_value = 42
            get.return_value = {'username': "jdoe"}

            self.storyboard.user.update(42, username="jdoe")
            self.assertEquals(True, upd.called)
            self.assertEquals(False, ins.called)
            token.assert_called_with(42, 'jdoe')

            self.storyboard.user.update(42, email='something')
            self.assertEquals(True, upd.called)
            self.assertEquals(False, ins.called)
            token.assert_called_with(42, 'jdoe')

    def test_get(self):
        with patch.object(self.storyboard.user, 'get_user') as get_user:
            self.storyboard.user.get("test")
            self.assertEquals(True, get_user.called)

    def test_delete(self):
        with patch.object(self.storyboard.user, 'sql_execute') as sql_exec, \
                patch.object(self.storyboard.user, 'get_user') as get_user:
            get_user.return_value = 42
            self.storyboard.user.delete(email="jdoe@doe.com")
            sql_exec.assert_called_once()

    def test_hook(self):

        class FakeClient:
            class FakeTasks:
                status = "todo"

                def get(self, task):
                    return self

                def update(self, id, status):
                    self.status = status

            class FakeStories:
                comments_db = []

                def get(self, story):
                    self.comments = self
                    return self

                def list(self):
                    return self.comments_db

                def create(self, content):
                    class FakeComment:
                        def __init__(self, content):
                            self.content = content
                    self.comments_db.append(FakeComment(content))

            tasks = FakeTasks()
            stories = FakeStories()

        with patch.object(self.storyboard, 'get_client') as client:
            fake_client = FakeClient()
            client.return_value = fake_client
            hooks = self.storyboard.hooks

            # Test no issue referenced
            ret = hooks.patchset_created(project='config',
                                         commit_message="None")
            self.assertEquals(ret, "No issue found in the commit message, "
                                   "nothing to do.")

            # Test basic workflow (todo->inprogress->merged)
            ret = hooks.patchset_created(project='config',
                                         commit_message="Task: #42")
            self.assertEquals(ret, "Success")
            self.assertEquals(fake_client.tasks.status, "inprogress")

            ret = hooks.change_merged(project='config',
                                      commit_message="Task: #42")
            self.assertEquals(ret, "Success")
            self.assertEquals(fake_client.tasks.status, "merged")

            # Test related workflow
            ret = hooks.patchset_created(project='config',
                                         commit_message="Related-Task: #42")
            self.assertEquals(ret, "Success")
            self.assertEquals(fake_client.tasks.status, "inprogress")
            ret = hooks.change_merged(project='config',
                                      commit_message="Related-Task: #42")
            self.assertEquals(fake_client.tasks.status, "inprogress")

            # Test story hook
            ret = hooks.patchset_created(project='config',
                                         commit_message="Story: #42")
            comments = fake_client.stories.comments_db
            self.assertEquals(ret, "Success")
            self.assertEquals(len(comments), 1)
            self.assertIn("Fix proposed", comments[0].content)

            # Test comments doesn't get added
            ret = hooks.patchset_created(project='config',
                                         commit_message="Story: #42")
            comments = fake_client.stories.comments_db
            self.assertEquals(ret, "Success")
            self.assertEquals(len(comments), 1)

            # Test change merged coment get added
            ret = hooks.change_merged(project='config',
                                      commit_message="Story: #42")
            comments = fake_client.stories.comments_db
            self.assertEquals(ret, "Success")
            self.assertEquals(len(comments), 2)
