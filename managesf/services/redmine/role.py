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


import logging

from redmine.exceptions import ResourceNotFoundError

from managesf.services import base
from managesf.services import exceptions as exc

logger = logging.getLogger(__name__)


class RedmineRoleManager(base.RoleManager):

    def get_role_id(self, name):
        rm = self.plugin.get_client()
        for r in rm.role.all():
            if r.name == name:
                return r.id
        return None

    def get(self, username, project_name):
        rm = self.plugin.get_client()
        try:
            users = rm.user.filter(login=username)
            for user in users:
                if user.login == username:
                    user_id = user.id
                    break
        except ResourceNotFoundError:
            return []
        try:
            memb = rm.project_membership.filter(project_id=project_name)
        except ResourceNotFoundError:
            return []
        for m in memb:
            if m.user.id == user_id:
                membership_id = m.id
                break
        try:
            return [r['name'] for r in
                    rm.project_membership.get(membership_id).roles]
        except ResourceNotFoundError:
            return []
        return []

    def create(self, **kwargs):
        raise exc.UnavailableActionError

    def delete(self, **kwargs):
        raise exc.UnavailableActionError

    def update(self, **kwargs):
        raise exc.UnavailableActionError


class SFRedmineRoleManager(RedmineRoleManager):
    """specific role manager for Redmine as deployed with Software Factory,
    as the pysflib API differs a bit from the regular python-redmine one."""
    def get(self, username, project_name):
        rm = self.plugin.get_client()
        user_id = rm.get_user_id_by_username(username)
        return rm.get_project_roles_for_user(project_name,
                                             user_id)

    def get_role_id(self, name):
        rm = self.plugin.get_client()
        for r in rm.r.role.all():
            if r.name == name:
                return r.id
        return None
