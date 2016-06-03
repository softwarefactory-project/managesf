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

from redmine.exceptions import ResourceNotFoundError, ValidationError

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
        project_name = self._clean_name(project_name)
        debug_args = (self.plugin.service_name,
                      project_name,
                      username)
        logger.debug(u'[%s] creating project %s for %s' % debug_args)

        if not project_data:
            project_data = {}
        description = ('' if 'description' not in project_data
                       else project_data['description'])
        private = (False if 'private' not in project_data
                   else project_data['private'])
        try:
            # create the project
            self._create(project_name, description, private)
        except ValidationError as e:
            if e.message == 'Identifier has already been taken':
                # the project already exists, we assume it is normal
                msg = '[%s] project %s exists already'
                logger.debug(msg % (self.plugin.service_name,
                                    project_name))
            else:
                # reraise, we don't know what's happening
                logger.debug('[%s] %s' % (self.plugin.service_name, e))
                raise e
        # set memberships
        try:
            self.plugin.membership.create(requestor=username,
                                          username=username,
                                          project=project_name,
                                          groups=['ptl-group'],
                                          user_is_owner=True)
        except ValidationError as e:
            if e.message == 'Identifier has already been taken':
                msg = u'[%s] %s is already PTL for %s'
                logger.debug(msg % (self.plugin.service_name,
                                    username,
                                    project_name))
            else:
                # reraise, we don't know what's happening
                logger.debug(u'[%s] %s' % (self.plugin.service_name, e))
                raise e
        try:
            self.plugin.membership.create(requestor=username,
                                          username=username,
                                          project=project_name,
                                          groups=['dev-group'],)
        except ValidationError as e:
            if e.message == 'Identifier has already been taken':
                msg = u'[%s] %s is already dev for %s'
                logger.debug(msg % (self.plugin.service_name,
                                    username,
                                    project_name))
            else:
                # reraise, we don't know what's happening
                logger.debug(u'[%s] %s' % (self.plugin.service_name, e))
                raise e

        logger.info('[%s] project %s created' % (self.plugin.service_name,
                                                 project_name))

    def _delete(self, project_name):
        rm = self.plugin.get_client()
        try:
            rm.project.delete(project_name)
        except ResourceNotFoundError:
            return None

    def delete(self, project_name, username):
        project_name = self._clean_name(project_name)
        if (not self.plugin.role.is_admin(username) and
            'Manager' not in self.plugin.role.get(username,
                                                  project_name=project_name)):
            msg = u'%s must be admin or project manager on project %s'
            raise exc.Unauthorized(msg % (username, project_name))
        self._delete(project_name)

    def get(self, requestor, user=None, project_name=None):
        rm = self.plugin.get_client()
        project_name = self._clean_name(project_name)
        if project_name:
            return rm.project.get(project_name)
        else:
            return rm.project.all()

    def update(self, **kwargs):
        # TODO(mhu) but not used/exposed yet in managesf
        raise NotImplementedError

    @staticmethod
    def _clean_name(name):
        return name.replace('/', '_')


class SFRedmineProjectManager(RedmineProjectManager):
    """specific project manager for Redmine as deployed with Software Factory,
    as the pysflib API differs a bit from the regular python-redmine one."""
    def _create(self, project_name, description, private):
        rm = self.plugin.get_client()
        name = self._clean_name(project_name)
        rm.create_project(name, description, private)

    def _delete(self, project_name):
        rm = self.plugin.get_client()
        name = self._clean_name(project_name)
        rm.delete_project(name)

    def get(self, project_name=None):
        rm = self.plugin.get_client()
        if project_name:
            name = self._clean_name(project_name)
            return rm.r.project.get(name)
        else:
            return rm.r.project.all()
