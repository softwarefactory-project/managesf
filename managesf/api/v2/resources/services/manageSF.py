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

# import logging
import os.path

from managesf.api.v2 import resources
from managesf.model.yamlbkd.engine import SFResourceBackendEngine


"""Resources service plugin using manageSF's built-in resource engine."""


# logger = logging.getLogger(__name__)

class ResourcesManager(resources.ResourcesManager):
    def __init__(self, manager):
        super(ResourcesManager, self).__init__()
        self.manager = manager

    def get(self, **kwargs):
        engine = self.manager.get_engine('read')
        if kwargs.get('get_missing_resources'):
            return engine.get_missing_resources(self.manager.master_repo,
                                                'master')
        else:
            return engine.get(self.manager.master_repo, 'master')

    def create(self, **kwargs):
        if kwargs.get('data') is None:
            raise ValueError('Invalid request: missing "data"')
        data = kwargs['data']
        prev_ref = kwargs.get('prev_ref', 'master')
        engine = self.manager.get_engine('validate')
        status, logs = engine.validate_from_structured_data(
            self.manager.master_repo, prev_ref, data)
        return status, logs


class SFResourcesManager(resources.ResourcesServiceManager):

    _config_section = "resources"
    service_name = "manageSF"

    def __init__(self, conf):
        super(SFResourcesManager, self).__init__(conf)
        self.subdir = self.conf['subdir']
        self.workdir = self.conf['workdir']
        self.master_repo = self.conf['master_repo']
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
