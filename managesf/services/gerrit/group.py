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

    def get_project_group_ids(self, client):
        project_groups = client.get_project_groups_id(client.get_projects())
        project_groups_ids = []
        for groups in project_groups.values():
            project_groups_ids.extend(groups['owners'])
            project_groups_ids.extend(groups['others'])
        return project_groups_ids

    def get(self, groupname=None, discard_pgroups=True):
        client = self.plugin.get_client()
        logger.info("[%s] Get group %s" % (self.plugin.service_name,
                                           groupname or "All groups"))
        ret = {}

        if groupname:
            gid = client.get_group_id(groupname)
            if not gid:
                raise exc.GroupNotFoundException("Unable to find group %s"
                                                 % groupname)
            if discard_pgroups:
                # We want to be sure the group is not a project group
                # referenced in refs.meta.config
                project_groups_ids = self.get_project_group_ids(client)
                if gid in project_groups_ids:
                    raise exc.GroupNotFoundException("Unable to find group %s"
                                                     % groupname)
            ret[groupname] = client.get_group_members(gid)
        else:
            project_groups_ids = self.get_project_group_ids(client)
            for groupname, details in client.get_groups().items():
                if details['id'] not in project_groups_ids:
                    ret[groupname] = {
                        'description': details['description'],
                        'members': client.get_group_members(details['id'])}
            for private in ("Administrators", "Service Users"):
                if private in ret:
                    del ret[private]

        return ret
