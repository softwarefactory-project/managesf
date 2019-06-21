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


from managesf.api.v2 import base


class ResourcesManager(base.BaseCRUDManager):
    """Resource tree-related CRUD operations."""

    def __init__(self):
        super(ResourcesManager, self).__init__()

    def get(self, **kwargs):
        """get the full tree.
        get_missing_resources: (boolean) if True, returns existing projects
            that are missing from the resources descriptor.
        """
        raise NotImplementedError

    def create(self, **kwargs):
        raise NotImplementedError


class ResourcesServiceManager(base.BaseService):
    resources = ResourcesManager()
