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


class RedmineUserManager(base.MembershipManager):
    """User management"""
    def create(self, username, email, lastname):
        rm = self.plugin.get_client()
        return rm.user.create(login=username,
                              firstname=username,
                              mail=email,
                              lastname=lastname)

    def get(self, mail=None, username=None):
        """get user id by mail or username"""
        rm = self.plugin.get_client()
        if mail and not username:
            try:
                users = rm.user.filter(mail=mail)
                for user in users:
                    if user.mail == mail:
                        return user.id
            except ResourceNotFoundError:
                return None
            return None
        elif username and not mail:
            try:
                users = rm.user.filter(login=username)
                for user in users:
                    if user.login == username:
                        return user.id
            except ResourceNotFoundError:
                return None
            return None
        else:
            raise exc.UnavailableActionError('must specify mail OR username')

    # TODO(mhu) whenever
    def update(self, username, email, lastname):
        raise NotImplementedError

    def delete(self, mail=None, username=None):
        # we don't manage user removal yet
        raise NotImplementedError


class SFRedmineUserManager(RedmineUserManager):

    def create(self, username, email, lastname):
        rm = self.plugin.get_client()
        return rm.create_user(username, email, lastname)

    def get(self, mail=None, username=None):
        rm = self.plugin.get_client()
        if mail and not username:
            return rm.get_user_id(mail)
        elif username and not mail:
            return rm.get_user_id_by_username(username)
        else:
            raise exc.UnavailableActionError('must specify mail OR username')
