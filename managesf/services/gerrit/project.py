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

    def user_owns_project(self, requestor, project_name):
        client = self.plugin.get_client()
        return (client.get_project_owner(project_name)
                in client.get_user_groups_id(requestor))

    def get_groups(self, project):
        client = self.plugin.get_client()
        groups = client.get_project_groups(project)
        if isinstance(groups, bool):
            logger.info("[%s] Could not find project %s: %s" % (
                self.plugin.service_name, project, str(groups)))
            groups = []
        return groups

    def get_groups_details(self, groups):
        client = self.plugin.get_client()
        groups = client.get_groups_details(groups)
        if isinstance(groups, bool):
            logger.info("[%s] Could not find groups %s" % (
                self.plugin.service_name, groups))
            groups = {}
        return groups

    def get_user_groups(self, user):
        client = self.plugin.get_client()
        groups = client.get_user_groups(user)
        if isinstance(groups, bool):
            logger.info(u"[%s] Could not find user groups %s: %s" % (
                self.plugin.service_name, user, str(groups)))
            groups = []
        return groups

    def get_projects_groups_id(self, projects):
        """ Return list of groups (id) for requested projects.
        The groups ids are in categories owners or others
        """
        client = self.plugin.get_client()
        projects_groups = client.get_project_groups_id(projects)
        if isinstance(projects_groups, bool):
            logger.info("[%s] Could not find projects owners for prjs %s" % (
                self.plugin.service_name, projects))
            projects_groups = {}
        return projects_groups

    def create(self, project_name, username, project_data=None):
        if not project_data:
            project_data = {}

        data = {'upstream': None,
                'upstream-ssh-key': False,
                'private': False,
                'description': '',
                'add-branches': False,
                'readonly': False}
        data.update(project_data)

        msg = "[%s] Init project: %s"
        logger.info(msg % (self.plugin.service_name, project_name))
        client = self.plugin.get_client()
        core = "%s-core" % project_name
        core_desc = "Core developers for project " + project_name
        self.plugin.role.create(username, core, core_desc)
        ptl = "%s-ptl" % project_name
        ptl_desc = "Project team lead for project " + project_name
        self.plugin.role.create(username, ptl, ptl_desc)

        if data['private']:
            dev = "%s-dev" % project_name
            dev_desc = "Developers for project " + project_name
            self.plugin.role.create(username, dev, dev_desc)

        owner = [ptl]
        if client.project_exists(project_name):
            msg = "[%s] project %s already exists"
            logger.info(msg % (self.plugin.service_name, project_name))
        else:
            client.create_project(project_name, data['description'], owner)
            self.plugin.repository.create(project_name,
                                          data['description'],
                                          data['upstream'],
                                          data['private'],
                                          data['upstream-ssh-key'],
                                          data['add-branches'],
                                          data['readonly'])
            msg = "[%s] project %s created"
            logger.info(msg % (self.plugin.service_name, project_name))

    def delete(self, project_name, requestor, *args, **kwargs):
        logger.info("[%s] Delete project %s" % (self.plugin.service_name,
                                                project_name))
        client = self.plugin.get_client()
        user_owns_project = self.user_owns_project(requestor, project_name)
        if not user_owns_project and not self.plugin.role.is_admin(requestor):
            msg = (u"[%s] User is neither an Administrator "
                   u"nor project %s's owner")
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
