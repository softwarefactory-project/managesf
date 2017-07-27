#
# Copyright (C) 2017 Red Hat
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


from managesf.api.v2 import base


class BaseUserManager(base.BaseCRUDManager):
    pass


class BaseUserEmailsManager(base.BaseCRUDManager):
    pass


class BaseUserSSHKeysManager(base.BaseCRUDManager):
    pass


class User(base.Data):
    """User info"""
    def __init__(self, id, cauth_id, username,
                 full_name=None, emails=None, ssh_keys=None,
                 services_mapping=None, idp_sync=False, **kwargs):
        """User descriptor."""
        self.id = id
        self.cauth_id = cauth_id
        self.username = username
        self.full_name = full_name
        self.emails = emails
        self.ssh_keys = ssh_keys
        self.idp_sync = idp_sync
        self.services_mapping = services_mapping or {}

    def to_dict(self):
        d = {'id': self.id,
             'cauth_id': self.cauth_id,
             'username': self.username,
             'full_name': self.full_name,
             'emails': None,
             'ssh_keys': None,
             'idp_sync': self.idp_sync,
             'services_mapping': self.services_mapping}
        if self.emails:
            d['emails'] = self.emails.to_dict()
        if self.ssh_keys:
            d['ssh_keys'] = [k.to_dict() for k in self.ssh_keys]
        return d


class SSHKey(base.Data):
    """SSH key info"""
    def __init__(self, id, contents=None, **kwargs):
        """SSH Key descriptor."""
        self.id = id
        self.contents = contents

    def to_dict(self):
        d = {'id': self.id,
             'contents': self.contents}
        return d


class Email(base.Data):
    """email info"""
    def __init__(self, id, email=None, **kwargs):
        """Email descriptor."""
        self.id = id
        self.email = email

    def to_dict(self):
        d = {'id': self.id,
             'email': self.email}
        return d


class EmailsList(base.Data):
    """emails list info"""
    def __init__(self, primary_id, emails=None, **kwargs):
        """User descriptor."""
        self.primary_id = primary_id
        self.emails = emails or []

    def to_dict(self):
        d = {'primary_id': self.primary_id,
             'emails': [e.to_dict() for e in self.emails]}
        return d


class UsersServiceManager(base.BaseService):
    # placeholders
    users = BaseUserManager()
    emails = BaseUserEmailsManager()
    ssh_keys = BaseUserSSHKeysManager()
