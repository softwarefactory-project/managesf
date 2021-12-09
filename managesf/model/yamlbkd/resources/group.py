# Copyright (c) 2016 Red Hat, Inc.
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

from managesf.services.gerrit import SoftwareFactoryGerrit
from managesf.services.gerrit import utils
from managesf.model.yamlbkd.resource import BaseResource

# ## DEBUG statements to ease run that standalone ###
# import logging
# logging.basicConfig()
# logging.getLogger().setLevel(logging.DEBUG)
# requests_log = logging.getLogger("requests.packages.urllib3")
# requests_log.setLevel(logging.DEBUG)
# requests_log.propagate = True
#
# from pecan import configuration
# from managesf.model.yamlbkd.resources.group import GroupOps
# conf = configuration.conf_from_file('/var/www/managesf/config.py')
# g = GroupOps(conf, {})
# g._set_client()
# ###


logger = logging.getLogger(__name__)
UNMANAGED_GERRIT_GROUPS = ('Administrators',
                           'Service Users')
DELETED_GROUP_RENAME_PATTERN = "_deleted_group_%s"


class GroupOps(object):

    def __init__(self, conf, new):
        self.conf = conf
        self.new = new

    def _set_client(self):
        gerrit = SoftwareFactoryGerrit(self.conf)
        self.client = gerrit.get_client()

    def group_update_description(self, name, description):
        data = {"description": description}
        return self.client.put("groups/%s/description" % name, data)

    def get_all(self):
        logs = []
        groups = {}

        self._set_client()

        try:
            all_groups = self.client.get_groups()
        except Exception as e:
            logger.exception("get_groups failed")
            logs.append("Group list: err API returned %s" % e)
            return logs, groups
        groups = {}
        for gname, data in all_groups.items():
            if gname in UNMANAGED_GERRIT_GROUPS:
                continue
            groups[gname] = {}
            groups[gname]['name'] = gname
            groups[gname]['description'] = data.get('description', '')
            groups[gname]['members'] = []
            try:
                members = self.client.get_group_members(str(data['group_id']))
                groups[gname]['members'] = [
                    m['email'] for m in members if 'email' in m.keys()]
            except Exception as e:
                logger.exception("get_group_members failed")
                logs.append(
                    "Group list members [%s]: err API "
                    "returned %s" % (gname, e))
        return logs, {'groups': groups}

    def create(self, **kwargs):
        logs = []
        name = kwargs['name']
        members = kwargs['members']
        description = kwargs['description']

        self._set_client()

        try:
            self.client.create_group(name, description)
        except Exception as e:
            logger.exception("create_group failed")
            logs.append("Group create: err API returned %s" % e)

        # Remove auto added admin
        try:
            self.client.delete_group_member(name, "admin")
        except utils.NotFound:
            pass
        except Exception as e:
            logger.exception("delete_group_member failed")
            logs.append("Group create [del member: admin]: "
                        "err API returned %s" % e)

        if members:
            for member in members:
                try:
                    self.client.add_group_member(member, name)
                except Exception as e:
                    logger.exception("add_group_member failed")
                    logs.append("Group create [add member: %s]: "
                                "err API returned %s" % (member, e))

        return logs

    def delete(self, **kwargs):
        logs = []
        name = kwargs['name']

        self._set_client()

        # Remove all group members to avoid left overs in the DB
        gid = self.client.get_group_id(name)
        current_members = [u['email'] for u in
                           self.client.get_group_members(gid)
                           if 'email' in u.keys()]
        for member in current_members:
            try:
                self.client.delete_group_member(name, member)
            except Exception as e:
                logger.exception("delete_group_member failed")
                logs.append("Group delete [del member: %s]: "
                            "err API returned %s" % (member, e))

        # Remove all included groups members to avoid left overs in the DB
        grps = [g['name'] for
                g in self.client.get_group_group_members(gid)]
        for grp in grps:
            try:
                self.client.delete_group_group_member(gid, grp)
            except Exception as e:
                logger.exception("delete_group_group_member failed")
                logs.append("Group delete [del included group %s]: "
                            "err API returned %s" % (grp, e))

        # Rename the group / Gerrit does not provide an API to delete a
        # group. Instead we rename it.
        try:
            self.client.rename_group(
                gid, DELETED_GROUP_RENAME_PATTERN % name)
        except Exception as e:
            logger.exception("rename_group failed")
            logs.append("Group delete [rename deleted group: %s]: "
                        "err API returned %s" % (name, e))

        return logs

    def update(self, **kwargs):
        logs = []
        name = kwargs['name']
        members = kwargs['members']
        description = kwargs['description']

        self._set_client()

        gid = self.client.get_group_id(name)
        current_members = [u['email'] for u in
                           self.client.get_group_members(gid) if
                           'email' in u.keys()]
        to_add = set(members) - set(current_members)
        to_del = set(current_members) - set(members)

        for mb in to_del:
            try:
                self.client.delete_group_member(name, mb)
            except Exception as e:
                logger.exception("delete_group_member failed")
                logs.append("Group update [del member: %s]: "
                            "err API returned %s" % (mb, e))

        for mb in to_add:
            try:
                self.client.add_group_member(mb, name)
            except Exception as e:
                logger.exception("add_group_member failed")
                logs.append("Group update [add member: %s]: "
                            "err API returned %s" % (mb, e))

        try:
            self.group_update_description(name, description)
        except Exception as e:
            logger.exception("group_update_description failed")
            logs.append("Group update [update description]: "
                        "err API returned %s" % e)

        # Remove included groups if exist ! We are not supporting that
        grps = [g['name'] for
                g in self.client.get_group_group_members(gid)]
        for grp in grps:
            try:
                self.client.delete_group_group_member(gid, grp)
            except Exception as e:
                logger.exception("delete_group_group_member failed")
                logs.append("Group update [del included group %s]: "
                            "err API returned %s" % (grp, e))

        return logs

    def check_account_members(self, members):
        logs = []

        self._set_client()

        for member in members:
            try:
                self.client.get_account(member)
            except utils.NotFound:
                logs.append("Check group members [%s does not exists]: "
                            "err API unable to find the member" % member)
        return logs

    def extra_validations(self, **kwargs):
        """ This checks that requested members exists
        inside the backend.
        """
        logs = []
        members = kwargs['members']
        name = kwargs['name']

        # Return log msgs making the validation fail in the engine
        if name in UNMANAGED_GERRIT_GROUPS:
            logs.append("Check group name [%s in not managed by this API]" % (
                        name))

        logs.extend(self.check_account_members(members))

        return logs


class Group(BaseResource):

    MODEL_TYPE = 'group'
    DESCRIPTION = ("The group resource is used to define a group of "
                   "known user on the platform. Users must be referenced "
                   "by their email address. A group can be share between "
                   "multiple acls.")
    MODEL = {
        'name': (
            str,
            r'^([a-zA-Z0-9\-_\./])+$',
            False,
            "",
            False,
            "The group name",
        ),
        'description': (
            str,
            '.*',
            False,
            "",
            True,
            "The group description",
        ),
        'members': (
            list,
            '.+@.+',
            False,
            [],
            True,
            "The group members list",
        ),
    }
    PRIORITY = 40
    PRIMARY_KEY = 'name'
    CALLBACKS = {
        'update': lambda conf, new, kwargs:
            GroupOps(conf, new).update(**kwargs),
        'create': lambda conf, new, kwargs:
            GroupOps(conf, new).create(**kwargs),
        'delete': lambda conf, new, kwargs:
            GroupOps(conf, new).delete(**kwargs),
        'extra_validations': lambda conf, new, kwargs:
            GroupOps(conf, new).extra_validations(**kwargs),
        'get_all': lambda conf, new:
            GroupOps(conf, new).get_all(),
    }
