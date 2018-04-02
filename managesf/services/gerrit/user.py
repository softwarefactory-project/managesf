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
from managesf.services.gerrit import utils


class SFGerritUserManager(base.UserManager):

    log = logging.getLogger("managesf.GerritUserManager")

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

    def _add_account_as_external(self, account_id, username):
        """Inject username as external_ids.
           This will be replaced by All-Users ref update with gerrit-2.15
        """
        sql = (u"INSERT IGNORE INTO account_external_ids VALUES"
               u"(%d, NULL, NULL, 'gerrit:%s');" %
               (account_id, username))
        try:
            self.session.execute(sql)
            self.session.commit()
        except Exception:
            self.log.exception("Couldn't insert user %s external_ids %s",
                               account_id, username)
            raise

    def create(self, username, email, full_name, ssh_keys, cauth_id):
        self.log.debug(u"Creating account %s", username)
        # Special case for the admin user
        if cauth_id == 1:
            self.log.warning("Attempt to create the admin user. Skip.")
            return 1
        ssh_keys_valid = []
        # Need to clean ssh_keys as they start with incorrect data by default:
        #   e.g.: [{u'key': u'None'}]  or [u'key']
        if ssh_keys:
            for key in ssh_keys:
                if isinstance(key, unicode) and key != u"None":
                    ssh_keys_valid.append(key)
                elif key.get("key") and key.get('key') != u"None":
                    ssh_keys_valid.append(key.get("key"))
        client = self.plugin.get_client()
        data = {"name": unicode(full_name), "email": email}
        if ssh_keys_valid:
            data["ssh_key"] = ssh_keys_valid[0]
        try:
            user = client.create_account(username, data)
        except utils.GerritClientError as e:
            if e.status_code == 409:
                self.log.warning("Account %s already exists", username)
                # Convert create to update parameters...
                for o, n in (("name", "full_name"), ("ssh_key", "ssh_keys")):
                    data[n] = data.get(o)
                    try:
                        del data[o]
                    except Exception:
                        pass
                return self.update(id=username, **data).get('_account_id')
            raise

        try:
            account_id = user.get('_account_id')
        except Exception:
            self.log.exception(u"Could not create user %s", user)
            raise

        self._add_account_as_external(account_id, username)
        # Add extra ssh keys
        if len(ssh_keys_valid) > 1:
            for key in ssh_keys_valid[1:]:
                client.add_pubkey(key, username)
        self.log.info(u'User %s created', username)
        return account_id

    def get(self, username):
        self.log.debug(u"Getting account %s", username)
        if not self.plugin.conf.get("new_gerrit_client"):
            g_client = self.plugin.get_client()
            try:
                account = g_client.get_account(username)
                if isinstance(account, dict):
                    return account.get('_account_id')
                else:
                    return account
            except Exception:
                pass
            return None
        try:
            client = self.plugin.get_client()
            return client.get_account(username).get('_account_id')
        except utils.NotFound:
            return None

    def update(self, uid, username=None, full_name=None, email=None,
               ssh_keys=None, external_id=None):
        self.log.debug(u"Updating account %s", uid)
        if not self.plugin.conf.get("new_gerrit_client"):
            g_client = self.plugin.get_client()
            return g_client.update_account(
                id=uid, no_email_confirmation=True, username=username,
                full_name=full_name, email=email, ssh_keys=ssh_keys,
                external_id=external_id)
        client = self.plugin.get_client()
        user = client.get_account(uid, details=True)
        if full_name is not None and user.get("name") != full_name:
            client.update_account_name(uid, full_name)
        if email is not None and user.get("email") != email:
            if user.get("email"):
                client.delete_account_email(uid, user["email"])
            if email in user.get("secondary_emails", []):
                client.update_account_preferred_email(uid, email)
            else:
                client.add_account_email(uid, email)
        if ssh_keys is not None and ssh_keys != u'None':
            if not isinstance(ssh_keys, list):
                ssh_keys = [{"key": ssh_keys}]
            keys = []
            for key in ssh_keys:
                if key.get('key') and key.get('key') != u'None':
                    keys.append(key['key'])
            if keys:
                existing_keys = client.get_pubkeys(uid)
                for key in keys:
                    if [True for existing_key in existing_keys
                            if existing_key["encoded_key"].split()[0] in key]:
                        continue
                    client.add_pubkey(key, uid)
        return user

    def delete(self, username):
        self.log.debug("Deleting account %s", username)
        client = self.plugin.get_client()
        account_id = None
        try:
            account = client.get_account(username)
            if account:
                account_id = account.get('_account_id')
        except utils.NotFound:
            pass
        except Exception:
            self.log.exception(u"Account %s not found, skip deletion",
                               username)
            return
        if self.plugin.conf.get("new_gerrit_client"):
            self.log.warning(
                "Couldn't delete the user, need manual intervention")
            return
        if not account_id:
            self.log.error(
                u"Account %s not found, skip deletion", username)
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
        except Exception:
            self.log.exception(u"Could not delete user %s", username)
        # flush gerrit caches
        for cache in ('accounts', 'accounts_byemail', 'accounts_byname',
                      'groups_members'):
            utils._exec(
                "ssh -i %s -p 29418 %s@%s gerrit flush-caches --cache %s" % (
                    self.plugin.conf['sshkey_priv_path'],
                    self.plugin._full_conf.admin['name'],
                    self.plugin.conf['host'],
                    cache))
        self.log.info(u'Account %s (id %s) deleted', username, account_id)
