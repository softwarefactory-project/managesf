#!/usr/bin/env python
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

import os.path

# from managesf.api.v2 import base
from managesf.api.v2 import resources
from managesf.model.yamlbkd.engine import SFResourceBackendEngine


"""While not exactly a 'Gerrit' service, the current resources engine can
only interact with Gerrit to propagate changes to the YAML backend."""


class ProjectManager(resources.ProjectManager):
    pass


class ACLManager(resources.ACLManager):
    pass


class GroupManager(resources.GroupManager):
    pass


class RepositoryManager(resources.RepositoryManager):
    pass


class ResourcesManager(resources.ResourcesManager):
    def get(self, **kwargs):
        engine = self.manager.get_engine('read')
        if kwargs.get('get_missing_resources'):
            return engine.get_missing_resources(self.manager.master_repo,
                                                'master')
        else:
            return engine.get(self.manager.master_repo, 'master')

    def update(self, **kwargs):
        engine = self.manager.get_engine('apply')
        if kwargs.get('COMMIT') or\
           all(kwargs.get(c) is None for c in ['COMMIT', 'prev', 'new']):
            commit = kwargs.get('COMMIT', 'master')
            status, logs = engine.apply(self.manager.master_repo,
                                        '%s^1' % commit,
                                        self.manager.master_repo,
                                        commit)
        elif (kwargs.get('COMMIT') is None and
              kwargs.get('prev') is not None and
              kwargs.get('new') is not None):
            status, logs = engine.direct_apply(kwargs['prev'], kwargs['new'])
        else:
            raise ValueError(
                'Invalid arguments: either provide a "COMMIT" or the '
                '"new" and "prev" arguments')
        return status, logs

    def create(self, **kwargs):
        if kwargs.get('zuul_url') is None:
            raise ValueError('Invalid request: missing "zuul_url"')
        zuul_url = kwargs['zuul_url']
        if kwargs.get('zuul_ref') is None:
            raise ValueError('Invalid request: missing "zuul_ref"')
        zuul_ref = kwargs['zuul_ref']
        engine = self.manager.get_engine('validate')
        status, logs = engine.validate(self.manager.master_repo,
                                       'master', zuul_url, zuul_ref)
        return status, logs


class GerritResourcesManager(resources.JobServiceManager):

    _config_section = "resources"
    service_name = "gerrit"

    def __init__(self, conf):
        super(resources.ResourcesServiceManager, self).__init__(conf)
        self.subdir = conf['subdir']
        self.workdir = conf['workdir']
        self.master_repo = conf['master_repo']
        self.projects = ProjectManager(self)
        self.acls = ACLManager(self)
        self.groups = GroupManager(self)
        self.repositories = RepositoryManager(self)
        self.resources = ResourcesManager(self)

    def get_engine(self, operation):
        """Returns a resource engine for the right operation.
        Valid operations: read, validate, apply"""
        if operation not in ['read', 'validate', 'apply']:
            raise ValueError('Unknown operation "%s"' % operation)
        engine = SFResourceBackendEngine(
            os.path.join(self.workdir, operation),
            self.subdir)
        return engine
