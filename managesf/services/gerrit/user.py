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
import pynotedb
import threading

from managesf.services import base
from managesf.services.gerrit import utils


class SFGerritUserManager(base.UserManager):

    log = logging.getLogger("managesf.GerritUserManager")

    def __init__(self, plugin):
        super(SFGerritUserManager, self).__init__(plugin)
        self.repo = None
        self.repo_lock = threading.Lock()

    def _add_account_as_external(self, account_id, username):
        """Inject username as external_ids.
        """
        with self.repo_lock:
            if 'keycloak' in self.plugin._full_conf['services']:
                scheme = pynotedb.scheme_keycloak
            else:
                # This is the scheme used by REMOTE_USER
                scheme = pynotedb.scheme_gerrit
            if self.repo is None:
                self.repo = pynotedb.mk_clone("ssh://gerrit/All-Users")
            try:
                pynotedb.add_account_external_id(
                    self.repo, username, str(account_id),
                    scheme)
            except Exception as e:
                self.log.exception(
                    "Couldn't insert user %s external_ids %s: %s",
                    account_id, username, e)
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
                if isinstance(key, str) and key != u"None":
                    ssh_keys_valid.append(key)
                elif key.get("key") and key.get('key') != u"None":
                    ssh_keys_valid.append(key.get("key"))
        client = self.plugin.get_client()
        data = {"name": str(full_name), "email": email}
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
                return self.update(uid=username, **data).get('_account_id')
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
        try:
            client = self.plugin.get_client()
            return client.get_account(username).get('_account_id')
        except utils.NotFound:
            return None

    def update(self, uid, username=None, full_name=None, email=None,
               ssh_keys=None, external_id=None, **infos):
        self.log.debug(u"Updating account %s", uid)
        client = self.plugin.get_client()
        user = client.get_account(uid, details=True)
        if email and isinstance(email, bytes):
            email = email.decode('utf-8')
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
        self.log.warning("Can't delete the user %s, need manual intervention",
                         username)
        return
