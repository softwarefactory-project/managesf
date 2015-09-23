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

from redmine.exceptions import ResourceNotFoundError

from managesf.services import base
from managesf.services import exceptions as exc

logger = logging.getLogger(__name__)


class RedmineProjectManager(base.ProjectManager):

    def _create(self, project_name, description, private):
        rm = self.plugin.get_client()
        rm.project.create(name=project_name,
                          identifier=project_name,
                          description=description,
                          is_public='false' if private else 'true')

    def create(self, project_name, username, project_data=None):
        debug_args = (self.plugin.service_name,
                      project_name,
                      username)
        logger.debug('[%s] creating project %s for %s' % debug_args)

        if not project_data:
            project_data = {}
        description = ('' if 'description' not in project_data
                       else project_data['description'])
        ptl = ([] if 'ptl-group-members' not in project_data
               else project_data['ptl-group-members'])
        private = (False if 'private' not in project_data
                   else project_data['private'])
        core = ([] if 'core-group-members' not in project_data
                else project_data['core-group-members'])
        dev = ([] if 'dev-group-members' not in project_data
               else project_data['dev-group-members'])
        # create the project
        self._create(project_name, description, private)
        # set memberships
        self.plugin.membership.create(requestor=username,
                                      username=username,
                                      project=project_name,
                                      groups=['ptl-group'],
                                      user_is_owner=True)
        self.plugin.membership.create(requestor=username,
                                      username=username,
                                      project=project_name,
                                      groups=['dev-group'],)
        for m in ptl:
            self.plugin.membership.create(requestor=username,
                                          username=m,
                                          project=project_name,
                                          groups=['ptl-group'],)
        for m in core:
            self.plugin.membership.create(requestor=username,
                                          username=m,
                                          project=project_name,
                                          groups=['core-group'],)
        for m in dev:
            self.plugin.membership.create(requestor=username,
                                          username=m,
                                          project=project_name,
                                          groups=['dev-group'],)

        logger.info('[%s] project %s created' % (self.plugin.service_name,
                                                 project_name))

    def _delete(self, project_name):
        rm = self.plugin.get_client()
        try:
            rm.project.delete(project_name)
        except ResourceNotFoundError:
            return None

    def delete(self, project_name, username):
        if (not self.plugin.role.is_admin(username) and
            'Manager' not in self.plugin.role.get(username,
                                                  project_name=project_name)):
            msg = '%s must be admin or project manager on project %s'
            raise exc.Unauthorized(msg % (username, project_name))
        self._delete(project_name)

    def get(self, requestor, user=None, project_name=None):
        rm = self.plugin.get_client()
        if project_name:
            return rm.project.get(project_name)
        else:
            return rm.project.all()

    def update(self, **kwargs):
        # TODO(mhu) but not used/exposed yet in managesf
        raise NotImplementedError


class SFRedmineProjectManager(RedmineProjectManager):
    """specific project manager for Redmine as deployed with Software Factory,
    as the pysflib API differs a bit from the regular python-redmine one."""
    def _create(self, project_name, description, private):
        rm = self.plugin.get_client()
        rm.create_project(project_name, description, private)

    def _delete(self, project_name):
        rm = self.plugin.get_client()
        rm.delete_project(project_name)

    def get(self, project_name=None):
        rm = self.plugin.get_client()
        if project_name:
            return rm.r.project.get(project_name)
        else:
            return rm.r.project.all()
