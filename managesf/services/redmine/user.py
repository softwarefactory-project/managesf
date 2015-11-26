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

from redmine.exceptions import ResourceNotFoundError, ValidationError
from managesf.services import base
from managesf.services import exceptions as exc


logger = logging.getLogger(__name__)


class RedmineUserManager(base.UserManager):
    """User management"""
    def create(self, username, email, lastname, **kwargs):
        rm = self.plugin.get_client()
        rm.user.create(login=username,
                       firstname=username,
                       mail=email,
                       lastname=lastname)
        logger.debug('[%s] user %s created' % (self.plugin.service_name,
                                               username))

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

    def delete(self, email=None, username=None):
        # we don't manage user removal yet
        raise NotImplementedError


class SFRedmineUserManager(RedmineUserManager):

    def create(self, username, email, full_name, **kwargs):
        rm = self.plugin.get_client()
        try:
            rm.create_user(username, email, full_name)
            logger.debug('[%s] user %s created' % (self.plugin.service_name,
                                                   username))
        except ValidationError as e:
            # not optimal but python-redmine does not differentiate this case
            if ('Resource already exists' in e.message) or\
               ('has already been taken' in e.message):
                msg = '[%s] user %s already exists, skipping creation'
                logger.info(msg % (self.plugin.service_name,
                                   username))
            else:
                # unknown error, raise it
                raise e

    def get(self, email=None, username=None):
        rm = self.plugin.get_client()
        if email and not username:
            return rm.get_user_id(email)
        elif username and not email:
            return rm.get_user_id_by_username(username)
        else:
            raise exc.UnavailableActionError('must specify mail OR username')

    def delete(self, email=None, username=None):
        if not (bool(email) != bool(username)):
            raise TypeError('mail OR username needed')
        rm = self.plugin.get_client()
        user_id = self.get(email, username)
        rm.r.user.delete(user_id)
