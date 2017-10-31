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

import sqlalchemy

from managesf.services import base
from managesf.services import exceptions as exc
from managesf.services.gerrit import utils


logger = logging.getLogger(__name__)


class SFGerritUserManager(base.UserManager):

    _immutable_fields_ = ['username', ]

    def __init__(self, plugin):
        super(SFGerritUserManager, self).__init__(plugin)
        db_uri = 'mysql://%s:%s@%s/%s?charset=utf8' % (
            self.plugin.conf['db_user'],
            self.plugin.conf['db_password'],
            self.plugin.conf['db_host'],
            self.plugin.conf['db_name'],
        )
        engine = sqlalchemy.create_engine(db_uri, echo=False,
                                          pool_recycle=600)
        Session = sqlalchemy.orm.sessionmaker(bind=engine)
        self.session = Session()

    def _add_sshkeys(self, username, keys):
        """add keys for username."""
        g_client = self.plugin.get_client()
        for key in keys:
            msg = u"[%s] Adding key %s for user %s"
            logger.debug(msg % (self.plugin.service_name,
                                key.get('key'),
                                username))
            try:
                g_client.add_pubkey(key.get('key'), user=username)
            except Exception as e:
                logger.debug('Could not add key: %s' % e)

    def _add_account_as_external(self, account_id, username):
        sql = (u"INSERT IGNORE INTO account_external_ids VALUES"
               u"(%d, NULL, NULL, 'gerrit:%s');" %
               (account_id, username))
        try:
            self.session.execute(sql)
            self.session.commit()
            return True
        except Exception as e:
            msg = u"[%s] Could not insert user %s in account_external_ids: %s"
            logger.debug(msg % (self.plugin.service_name,
                                username, unicode(e)))
            return False

    def create(self, username, email, full_name, ssh_keys=None, **kwargs):
        _user = {"name": unicode(full_name), "email": str(email)}
        g_client = self.plugin.get_client()
        if username is None:
            if "cauth_id" in kwargs and int(kwargs["cauth_id"]) == 1:
                # Special case for admin user already created
                msg = u"[%s] requested creation of admin, skipping"
                logger.debug(msg % self.plugin.service_name)
                return 1
            msg = u"[%s] can't create user %s without username (%s)"
            logger.error(msg % (self.plugin.service_name, email,
                                str(kwargs)))
            raise Exception(msg % (self.plugin.service_name, email,
                                   str(kwargs)))
        user = g_client.create_account(username, _user)
        try:
            account_id = user.get('_account_id')
        except Exception as e:
            account_id = None
            msg = u"[%s] could not create user %s, service returned: %s"
            logger.error(msg % (self.plugin.service_name,
                                username, e))
            raise Exception(msg % (self.plugin.service_name,
                                   username, e))

        fetch_ssh_keys = False
        if account_id:
            fetch_ssh_keys = self._add_account_as_external(account_id,
                                                           username)
        if ssh_keys and fetch_ssh_keys:
            self._add_sshkeys(username, ssh_keys)
        logger.debug(u'[%s] user %s created' % (self.plugin.service_name,
                                                username))
        return account_id

    def get(self, email=None, username=None):
        if not (bool(email) != bool(username)):
            raise TypeError('mail OR username needed')
        if username:
            query = username
        else:
            query = email
        g_client = self.plugin.get_client()
        try:
            account = g_client.get_account(query)
            if isinstance(account, dict):
                return account.get('_account_id')
            else:
                return account
        except Exception:
            return None
        return None

    def update(self, uid, **kwargs):
        f = self.check_forbidden_fields(**kwargs)
        if f:
            msg = u'[%s] fields %s cannot be updated'
            raise exc.UnavailableActionError(msg % (self.plugin.service_name,
                                                    ', '.join(f)))
        g_client = self.plugin.get_client()
        return g_client.update_account(id=uid, no_email_confirmation=True,
                                       **kwargs)

    def delete(self, email=None, username=None):
        if not (bool(email) != bool(username)):
            raise TypeError('mail OR username needed')
        account_id = self.get(email, username)
        if not account_id:
            msg = u'[%s] %s not found, skip deletion'
            logger.debug(msg % (self.plugin.service_name,
                                email or username))
            return
        # remove project memberships
        sql = ("DELETE FROM account_group_members "
               "WHERE account_id=%s;\n" % account_id)
        # remove from accounts table
        sql += ("DELETE FROM accounts "
                "WHERE account_id=%s;\n" % account_id)
        # remove from external ids
        sql += ("DELETE FROM account_external_ids "
                "WHERE account_id=%s;" % account_id)
        try:
            self.session.execute(sql)
            self.session.commit()
        except Exception as e:
            msg = u"[%s] Could not delete user %s in base: %s"
            logger.debug(msg % (self.plugin.service_name,
                                email or username, unicode(e)))
        # flush gerrit caches
        for cache in ('accounts', 'accounts_byemail', 'accounts_byname',
                      'groups_members'):
            utils._exec(
                "ssh -i %s -p 29418 %s@%s gerrit flush-caches --cache %s" % (
                    self.plugin.conf['sshkey_priv_path'],
                    self.plugin._full_conf.admin['name'],
                    self.plugin.conf['host'],
                    cache))
        logger.debug(u'[%s] %s (id %s) deleted' % (self.plugin.service_name,
                                                   email or username,
                                                   account_id))
