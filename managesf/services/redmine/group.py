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


class RedmineGroupManager(base.GroupManager):

    def get(self, *args, **kwargs):
        # Gerrit is the sole authority when it comes to groups so this
        # method is not needed per se
        raise NotImplementedError(
            'the gerrit service must be used to list groups')

    def create(self, groupname, initial, description=None):
        # Redmine does not support group description
        client = self.plugin.get_client()
        logger.info("[%s] create group %s" % (self.plugin.service_name,
                                              groupname))
        if not client.create_group(groupname):
            raise exc.CreateGroupException("Unable to create group due "
                                           "to a conflict")
        # Add the requestor as inital user
        gid = client.get_group_id(groupname)
        uid = client.get_user_id(initial)
        client.set_group_members(gid, [uid, ])

    def update(self, groupname, members):
        client = self.plugin.get_client()
        logger.info("[%s] Update group %s with members %s" % (
            self.plugin.service_name,
            groupname,
            members))
        gid = client.get_group_id(groupname)
        if not gid:
            raise exc.GroupNotFoundException()

        member_ids = []
        for email in members:
            uid = client.get_user_id(email)
            if uid:
                member_ids.append(uid)
            else:
                logger.info("[%s] " % self.plugin.service_name +
                            "Unable to add %s in %s" % (uid, groupname))
        client.set_group_members(gid, member_ids)

    def delete(self, groupname):
        client = self.plugin.get_client()
        logger.info("[%s] Delete project %s" % (self.plugin.service_name,
                                                groupname))
        gid = client.get_group_id(groupname)
        if not gid:
            raise exc.GroupNotFoundException()
        client.delete_group(gid)
