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

from managesf.services import base
from managesf.services import exceptions as exc


logger = logging.getLogger(__name__)


class SFGerritProjectManager(base.ProjectManager):

    def get(self, requestor=None, user=None, project_name=None, by_user=False,
            *args, **kwargs):
        client = self.plugin.get_client()
        if project_name:
            result = client.get_project(project_name)
        else:
            result = client.get_projects()
        if by_user:
            if self.plugin.role.is_admin(requestor):
                return result
            else:
                names = []
                if requestor:
                    groups_id = client.get_user_groups_id(requestor)
                else:
                    groups_id = client.get_my_groups()
                for p in result:
                    owner = client.get_project_owner(p)
                    if owner in groups_id:
                        names.append(p)
                return names
        else:
            return result

    def get_groups(self, project):
        client = self.plugin.get_client()
        groups = client.get_project_groups(project)
        if isinstance(groups, bool):
            logger.info("[%s] Could not find project %s: %s" % (
                self.plugin.service_name, project, str(groups)))
            groups = []
        return groups

    def create(self, project_name, username, project_data=None):
        if not project_data:
            project_data = {}
        msg = "[%s] Init project: %s"
        logger.info(msg % (self.plugin.service_name, project_name))
        upstream = (None if 'upstream' not in project_data
                    else project_data['upstream'])
        ssh_key = (False if 'upstream-ssh-key' not in project_data
                   else project_data['upstream-ssh-key'])
        description = ("" if 'description' not in project_data
                       else project_data['description'])
        private = (False if 'private' not in project_data
                   else project_data['private'])
        client = self.plugin.get_client()
        core = "%s-core" % project_name
        core_desc = "Core developers for project " + project_name
        self.plugin.role.create(username, core, core_desc)
        if 'core-group-members' in project_data:
            for m in project_data['core-group-members']:
                self.plugin.membership.create(username,
                                              m,
                                              project_name,
                                              ["core-group"])

        ptl = "%s-ptl" % project_name
        ptl_desc = "Project team lead for project " + project_name
        self.plugin.role.create(username, ptl, ptl_desc)
        if 'ptl-group-members' in project_data:
            for m in project_data['ptl-group-members']:
                self.plugin.membership.create(username,
                                              m,
                                              project_name,
                                              ["ptl-group"])

        if private:
            dev = "%s-dev" % project_name
            dev_desc = "Developers for project " + project_name
            self.plugin.role.create(username, dev, dev_desc)
            if 'dev-group-members' in project_data:
                for m in project_data['dev-group-members']:
                    if m != username:
                        self.plugin.membership.create(username,
                                                      m,
                                                      project_name,
                                                      ["dev-group"])

        owner = [ptl]
        client.create_project(project_name, description, owner)
        self.plugin.repository.create(project_name,
                                      description,
                                      upstream,
                                      private,
                                      ssh_key)

    def delete(self, project_name, requestor, *args, **kwargs):
        logger.info("[%s] Delete project %s" % (self.plugin.service_name,
                                                project_name))
        client = self.plugin.get_client()
        user_owns_project = (client.get_project_owner(project_name)
                             in client.get_user_groups_id(requestor))
        if not user_owns_project and not self.plugin.role.is_admin(requestor):
            msg = ("[%s] User is neither an Administrator "
                   "nor project %s's owner")
            logger.debug(msg % (self.plugin.service_name, project_name))
            raise exc.Unauthorized(msg % (self.plugin.service_name,
                                          project_name))

        # user owns the project, so delete it now
        self.plugin.role.delete("%s-core" % project_name)
        self.plugin.role.delete("%s-ptl" % project_name)
        try:
            # if dev group exists, no exception will be thrown
            self.plugin.role.delete("%s-dev" % project_name)
        # TODO(mhu) catch a less generic exception, this is too lazy
        except Exception:
            pass
        client.delete_project(project_name, force=True)
