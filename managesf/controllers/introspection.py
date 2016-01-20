#!/usr/bin/env python
#
# Copyright (C) 2014 eNovance SAS <licensing@enovance.com>
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

from pecan import conf
from pecan import expose
from pecan.rest import RestController
import pkg_resources


class IntrospectionController(RestController):
    """A controller that allows a client to know more about the server."""

    def get_managesf_version(self):
        managesf = pkg_resources.get_distribution('managesf')
        return managesf.version

    @expose(template='json')
    def index(self, **kwargs):
        return_value = {'service': {
            'name': 'managesf',
            'version': self.get_managesf_version(),
            # TODO(mhu) this should not be hardcoded. Wait for plugins!
            'services': conf.services, }}
        return return_value
