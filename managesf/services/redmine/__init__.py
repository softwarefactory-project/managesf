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

from sqlalchemy import create_engine

from pysflib.sfredmine import RedmineUtils
from redmine import Redmine as RM

from managesf.services import base
from managesf.services.redmine import backup
from managesf.services.redmine import hooks
from managesf.services.redmine import membership
from managesf.services.redmine import project
from managesf.services.redmine import role
from managesf.services.redmine import user


class Redmine(base.BaseIssueTrackerServicePlugin):
    """Plugin managing the Redmine issue tracker service."""

    _config_section = "redmine"
    service_name = "redmine"

    def __init__(self, conf):
        super(base.BaseIssueTrackerServicePlugin, self).__init__(conf)
        self.project = project.RedmineProjectManager(self)
        self.user = user.UserManager(self)
        self.membership = membership.MembershipManager(self)
        self.role = role.RoleManager(self)
        self.backup = backup.RedmineBackupManager(self)
        self.hooks = hooks.RedmineHooksManager(self)

    def get_client(self, cookie=None):
        return RM(self.conf['url'],
                  key=self.conf['api_key'],
                  # TODO(mhu) should be in config
                  requests={'verify': False})

    def get_open_issues(self):
        c = self.get_client()
        return c.get_open_issues()

    def get_active_users(self):
        c = self.get_client()
        return c.active_users()


class SoftwareFactoryRedmine(Redmine):
    """Plugin managing a Redmine instance deployed with Software Factory,
    thus needing a cauth-issued cookie for authentication."""

    def __init__(self, conf):
        super(base.BaseIssueTrackerServicePlugin, self).__init__(conf)
        self.project = project.SFRedmineProjectManager(self)
        self.user = user.SFRedmineUserManager(self)
        self.membership = membership.SFRedmineMembershipManager(self)
        self.role = role.SFRedmineRoleManager(self)
        self.backup = base.BackupManager(self)
        self.backup.heartbeat_cmd = None
        self.hooks = hooks.RedmineHooksManager(self)

    def get_client(self, cookie=None):
        api_key = self._get_api_key()
        return RedmineUtils(self.conf['url'],
                            key=api_key)

    def _get_api_key(self):
        if self.conf.get('api_key'):
            return self.conf['api_key']
        if self.conf.get('db_url'):
            query = ("select value from tokens where action = 'api' and "
                     "user_id in (select id from users where login='admin')")
            e = create_engine(self.conf['db_url'])
            for row in e.execute(query):
                return dict(row)['value']
            del e
        raise Exception("Redmine API key not found")
