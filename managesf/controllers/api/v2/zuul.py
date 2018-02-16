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


from managesf.controllers.api.v2 import base
from managesf.api.v2.managers import zuul_proxy, zuul_admin_proxy


ZUUL_PREFIX = '.+/zuul/(?P<tenant>.+)/'
GET_PREFIX = 'get ' + ZUUL_PREFIX
GET_CHANGE_STATUS = 'get .+/zuul/status/change/(?P<change>.+),(?P<revision>.+)'
GET_PROJECT_KEY = 'get .+/zuul/keys/(?P<source>.+)/(?P<repository>.+)\.pub$'
ZUUL_ADM = '.+/zuul/admin/(?P<tenant>.+)/'
POST_PREFIX = 'post ' + ZUUL_ADM
ENQUEUE = POST_PREFIX + '(?P<repository>.+?)/(?P<pipeline>.+)/enqueue(_ref)?'
AUTOHOLD = POST_PREFIX + '(?P<repository>.+?)/(?P<job>.+)/autohold'


class ZuulController(base.APIv2RestProxyController):
    manager = zuul_proxy
    # This needs to be updated as zuul's API evolves.
    policies_map = {
        'get .+/zuul/tenants(.json)?': 'zuul.tenants:get',
        GET_PREFIX + 'status(.json)?': 'zuul.tenant.status:get',
        GET_PREFIX + 'jobs(.json)?': 'zuul.tenant.jobs:get',
        GET_PREFIX + 'console-stream': 'zuul.tenant.console-stream:get',
        'get .+/zuul/status(.json)?$': 'zuul.status:get',
        GET_PREFIX + 'builds(.json)?': 'zuul.tenant.builds:get',
        GET_CHANGE_STATUS: 'zuul.status.change:get',
        GET_PROJECT_KEY: 'zuul.project.public_key:get',
        GET_PREFIX + 'autohold.json': 'zuul.autohold:list',
    }

    def _policy_target(self, verb, target_elements, *args, **kwargs):
        target = dict((k, v) for k, v in kwargs.items())
        if 'tenant' in target_elements:
            target['tenant'] = target_elements['tenant']
        if 'change' in target_elements:
            target['change'] = target_elements['change']
        if 'revision' in target_elements:
            target['revision'] = target_elements['revision']
        if 'source' in target_elements:
            target['source'] = target_elements['source']
        if 'repository' in target_elements:
            target['repository'] = target_elements['repository']
        return target


class ZuulAdminController(ZuulController):
    manager = zuul_admin_proxy
    # This needs to be updated as zuul's API evolves.
    policies_map = {
        ENQUEUE: 'zuul.buildset:enqueue',
        AUTOHOLD: 'zuul.autohold:add',
    }

    def _policy_target(self, verb, target_elements, *args, **kwargs):
        target = super(ZuulAdminController, self)._policy_target(
            verb, target_elements, *args, **kwargs)
        if 'pipeline' in target_elements:
            target['pipeline'] = target_elements['pipeline']
        if 'job' in target_elements:
            target['job'] = target_elements['job']
        if 'trigger' in kwargs:
            target['trigger'] = kwargs['trigger']
        if 'change' in kwargs:
            if ',' in kwargs['change']:
                change, revision = kwargs['change'].split(',', 1)
            else:
                change, revision = kwargs['change'], ''
            target['change'] = change
            target['revision'] = revision
        if 'ref' in kwargs:
            target['ref'] = kwargs['ref']
        if 'oldrev' in kwargs:
            target['oldrev'] = kwargs['oldrev']
        if 'newrev' in kwargs:
            target['newrev'] = kwargs['newrev']
        return target
