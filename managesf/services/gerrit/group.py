# Copyright (C) 2016 Red Hat
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

from managesf.services import base
from managesf.services import exceptions as exc

logger = logging.getLogger(__name__)


class SFGerritGroupManager(base.GroupManager):

    def get(self, groupname=None):
        client = self.plugin.get_client()
        logger.info("[%s] Get group %s" % (self.plugin.service_name,
                                           groupname or "All groups"))
        ret = {}

        # We want to be sure the group is not a project group
        # referenced in refs.meta.config
        project_groups = client.get_project_groups_id(client.get_projects())
        project_groups_ids = []
        for groups in project_groups.values():
            project_groups_ids.extend(groups['owners'])
            project_groups_ids.extend(groups['others'])

        if groupname:
            gid = client.get_group_id(groupname)
            if not gid or gid in project_groups_ids:
                raise exc.GroupNotFoundException("Unable to find group %s"
                                                 % groupname)
            ret[groupname] = client.get_group_members(gid)
        else:
            for groupname, details in client.get_groups().items():
                if details['id'] not in project_groups_ids:
                    ret[groupname] = {
                        'description': details['description'],
                        'members': client.get_group_members(details['id'])}
            for private in ("Administrators", "Non-Interactive Users"):
                if private in ret:
                    del ret[private]

        return ret

    def create(self, groupname, initial, description=None):
        client = self.plugin.get_client()
        logger.info("[%s] create group %s" % (self.plugin.service_name,
                                              groupname))

        msg = "Unable to create a group due to %s"
        try:
            st = client.create_group(groupname, description)
        except Exception, e:
            logger.info(msg % e)
            raise exc.CreateGroupException(msg % e)
        if not st:
            logger.info("[%s] " % self.plugin.service_name +
                        msg % " a conflict")
            raise exc.CreateGroupException(msg % " a conflict")
        if initial.split('@')[0] != 'admin':
            # Remove auto added admin user
            client.delete_group_member(groupname, "admin")
            # Add requestor in group
            client.add_group_member(initial, groupname)

    def update(self, groupname, members):
        client = self.plugin.get_client()
        logger.info("[%s] Update group %s with members %s" % (
            self.plugin.service_name, groupname, str(members)))
        # We want to be sure the group is not a project group
        # referenced in refs.meta.config
        project_groups = client.get_project_groups_id(client.get_projects())
        project_groups_ids = []
        for groups in project_groups.values():
            project_groups_ids.extend(groups['owners'])
            project_groups_ids.extend(groups['others'])

        gid = client.get_group_id(groupname)
        if not gid:
            raise exc.GroupNotFoundException()
        if gid in project_groups_ids:
            logger.info("[%s] " % self.plugin.service_name +
                        "Attempted to update a project group.")
            raise exc.UpdateGroupException("Unable to update a project group")
        else:
            current_members = [u['email'] for u in
                               client.get_group_members(gid)]
            to_add = set(members) - set(current_members)
            to_del = set(current_members) - set(members)
            for mb in to_add:
                # Workaround SF is initialized with two users
                # with the same email admin@domain
                if mb.split('@')[0] == 'admin':
                    mb = 'admin'
                client.add_group_member(mb, groupname)
            for mb in to_del:
                # Workaround SF is initialized with two users
                # with the same email admin@domain
                if mb.split('@')[0] == 'admin':
                    mb = 'admin'
                client.delete_group_member(groupname, mb)
