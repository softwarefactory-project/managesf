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


import json
import logging

import requests
import sqlalchemy

from managesf.services import base
from managesf.services import exceptions as exc


logger = logging.getLogger(__name__)


class SFGerritUserManager(base.UserManager):

    def __init__(self, plugin):
        super(SFGerritUserManager, self).__init__(plugin)
        db_uri = 'mysql://%s:%s@%s/%s' % (self.plugin.conf['db_user'],
                                          self.plugin.conf['db_password'],
                                          self.plugin.conf['db_host'],
                                          self.plugin.conf['db_name'],)
        engine = sqlalchemy.create_engine(db_uri, echo=False,
                                          pool_recycle=600)
        Session = sqlalchemy.orm.sessionmaker(bind=engine)
        self.session = Session()

    def _add_sshkeys(self, username, keys, cookie):
        """add keys for username."""
        url = "%s/r/a/accounts/%s/sshkeys" % (self.plugin.conf['url'],
                                              username)
        for key in keys:
            msg = "[%s] Adding key %s for user %s"
            logger.debug(msg % (self.plugin.service_name,
                                key.get('key'),
                                username))
            resp = requests.post(url, data=key.get('key'),
                                 cookies=cookie)
            if resp.status_code > 399:
                logger.debug('Could not add key: %s' % resp.content)

    def _add_account_as_external(self, account_id, username):
        sql = ("INSERT IGNORE INTO account_external_ids VALUES"
               "(%d, NULL, NULL, 'gerrit:%s');" %
               (account_id, username))
        try:
            self.session.execute(sql)
            self.session.commit()
            return True
        except Exception as e:
            msg = "[%s] Could not insert user %s in account_external_ids: %s"
            logger.debug(msg % (self.plugin.service_name,
                                username, e.message))
            return False

    def create(self, username, email, full_name, ssh_keys=None, **kwargs):
        _user = {"name": unicode(full_name), "email": str(email)}
        data = json.dumps(_user, default=lambda o: o.__dict__)
        # get our cookie from the gerrit client
        g_client = self.plugin.get_client()
        cookie = g_client.g.kwargs['cookies']
        headers = {"Content-type": "application/json"}
        url = "%s/r/a/accounts/%s" % (self.plugin.conf['url'],
                                      username)
        requests.put(url, data=data, headers=headers,
                     cookies=cookie)

        resp = requests.get(url, headers=headers,
                            cookies=cookie)
        data = resp.content[4:]  # there is some garbage at the beginning
        try:
            account_id = json.loads(data).get('_account_id')
        except:
            account_id = None
            msg = "[%s] could not create user %s, service returned: %s"
            logger.error(msg % (self.plugin.service_name,
                                username, resp.content))
            raise Exception(msg % (self.plugin.service_name,
                                   username, resp.content))

        fetch_ssh_keys = False
        if account_id:
            fetch_ssh_keys = self._add_account_as_external(account_id,
                                                           username)
        if ssh_keys and fetch_ssh_keys:
            self._add_sshkeys(username, ssh_keys, cookie)
        logger.debug('[%s] user %s created' % (self.plugin.service_name,
                                               username))

    def get(self, email=None, username=None):
        if not (bool(email) != bool(username)):
            raise TypeError('mail OR username needed')
        if username:
            query = username
        else:
            query = email
        g_client = self.plugin.get_client()
        cookie = g_client.g.kwargs['cookies']
        url = "%s/r/a/accounts/%s" % (self.plugin.conf['url'],
                                      query)
        headers = {"Content-type": "application/json"}
        resp = requests.get(url, headers=headers,
                            cookies=cookie)
        try:
            return json.loads(resp.content[4:])
        except:
            return None
        return None

    def delete(self, email=None, username=None):
        if not (bool(email) != bool(username)):
            raise TypeError('mail OR username needed')
        # it's ... complicated. Also removing users will screw up reviews they
        # contributed to
        msg = 'Gerrit does not support account deletion'
        raise exc.UnavailableActionError(msg)
