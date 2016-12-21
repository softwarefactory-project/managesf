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
        logger.debug(u'[%s] user %s created' % (self.plugin.service_name,
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

    def delete(self, email=None, username=None):
        # we don't manage user removal yet
        raise NotImplementedError


class SFRedmineUserManager(RedmineUserManager):

    def create(self, username, email, full_name, **kwargs):
        rm = self.plugin.get_client()
        try:
            u = rm.create_user(username, email, full_name)
            logger.debug(u'[%s] user %s created' % (self.plugin.service_name,
                                                    username))
            return u.id
        except ValidationError as e:
            # not optimal but python-redmine does not differentiate this case
            if ('Resource already exists' in unicode(e)) or\
               ('has already been taken' in unicode(e)):
                msg = u'[%s] user %s already exists, skipping creation'
                logger.info(msg % (self.plugin.service_name,
                                   username))
                return self.get(email=email) or self.get(username=username)
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

    def update(self, uid, full_name=None, username=None, email=None,
               **kwargs):
        rm = self.plugin.get_client()
        try:
            u = rm.r.user.get(uid)
        except ResourceNotFoundError:
            msg = '[%s] %s not found, cannot update'
            logger.debug(msg % (self.plugin.service_name,
                                uid))
            return False
        if u:
            if full_name:
                u.lastname = full_name
            if username:
                u.login = username
            if email:
                u.mail = email
            u.save()
            return True

    def delete(self, email=None, username=None):
        if not (bool(email) != bool(username)):
            raise TypeError('mail OR username needed')
        rm = self.plugin.get_client()
        user_id = self.get(email, username)
        if not user_id:
            msg = u'[%s] %s not found, skip deletion'
            logger.debug(msg % (self.plugin.service_name,
                                email or username))
        else:
            try:
                rm.r.user.delete(user_id)
            except ResourceNotFoundError:
                msg = u'[%s] %s not found, skip deletion'
                logger.debug(msg % (self.plugin.service_name,
                                    email or username))
            msg = u'[%s] %s (id %s) deleted'
            logger.debug(msg % (self.plugin.service_name,
                                email or username,
                                user_id))
