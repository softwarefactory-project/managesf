#!/usr/bin/env python
#
# Copyright (C) 2016 Red Hat
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

from storyboardclient.v1.client import Client as StoryboardClient

from managesf.services import base
from managesf.services.storyboard import user
from managesf.services.storyboard import hooks


class Storyboard(base.BaseServicePlugin):
    """Plugin managing the Storyboard issue tracker service."""

    _config_section = "storyboard"
    service_name = "storyboard"

    def get_client(self, cookie=None):
        return StoryboardClient(api_url="http://storyboard:20000/v1",
                                access_token=self.conf['service_token'])

    def get_open_issues(self):
        c = self.get_client()
        return c.stories.get_all()

    def get_active_users(self):
        c = self.get_client()
        return c.users.get_all()


class SoftwareFactoryStoryboard(Storyboard):
    """Plugin managing a Storyboard instance deployed with Software Factory,
    thus needing a cauth-issued cookie for authentication."""

    def __init__(self, conf):
        super(SoftwareFactoryStoryboard, self).__init__(conf)
        self.user = user.StoryboardUserManager(self)
        self.hooks = hooks.StoryboardHooksManager(self)
