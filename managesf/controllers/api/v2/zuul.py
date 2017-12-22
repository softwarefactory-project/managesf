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
from managesf.api.v2.managers import zuul_proxy


GET_PREFIX = 'get .?zuul/(?P<tenant>.+)/'


class ZuulController(base.APIv2RestProxyController):
    manager = zuul_proxy
    policies_map = {
        'get .?zuul/tenants(.json)?': 'zuul.tenants:get',
        GET_PREFIX + 'status(.json)?': 'zuul.tenant.status:get',
        GET_PREFIX + 'jobs(.json)?': 'zuul.tenant.jobs:get',
        GET_PREFIX + 'console-stream': 'zuul.tenant.console-stream:get',
        'get .?zuul/status(.json)?': 'zuul.status:get',
        GET_PREFIX + 'builds(.json)?': 'zuul.tenant.builds:get',
    }

    def _policy_target(self, verb, target_elements, *args, **kwargs):
        target = dict((k, v) for k, v in kwargs.items())
        if 'tenant' in target_elements:
            target['tenant'] = target_elements['tenant']
        return target
