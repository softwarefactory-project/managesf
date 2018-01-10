#
# Copyright (C) 2018 Red Hat
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
from managesf.api.v2.managers import nodepool_proxy, nodepool_admin_proxy


NP_ = ' .+/nodepool/'
NP_ADM_ = NP_ + 'admin/'


class NodepoolController(base.APIv2RestProxyController):
    manager = nodepool_proxy
    # This needs to be updated as nodepool's API evolves.
    policies_map = {
        'get' + NP_ + 'image-list.json': 'nodepool.image:list',
        'get' + NP_ + 'dib-image-list.json': 'nodepool.dib-image:list',
        'get' + NP_ + 'node-list.json': 'nodepool.node:list',
        'get' + NP_ + 'label-list.json': 'nodepool.label:list',
        'get' + NP_ + 'request-list.json': 'nodepool.request:list',
    }

    def _policy_target(self, verb, target_elements, *args, **kwargs):
        target = dict((k, v) for k, v in kwargs.items())
        return target


class NodepoolAdminController(base.APIv2RestProxyController):
    manager = nodepool_admin_proxy
    # This needs to be updated as nodepool's API evolves.
    dib_image_base = NP_ADM_ + 'dib-image/(?P<image>[^/]+)'
    image_base = (NP_ADM_ + 'image/(?P<provider>[^/]+)/'
                  '(?P<image>[^/]+)/(?P<build_id>[^/]+)/'
                  '(?P<upload_id>[^/]+)')
    policies_map = {
        'get' + NP_ADM_ + 'node/(?P<node_id>[^/]+)': 'nodepool.node:list',
        'put' + NP_ADM_ + 'node/(?P<node_id>[^/]+)': 'nodepool.node:hold',
        'delete' + NP_ADM_ + 'node/(?P<node_id>[^/]+)': 'nodepool.node:delete',
        'delete' + dib_image_base: 'nodepool.dib-image:delete',
        'post' + dib_image_base: 'nodepool.dib-image:build',
        'delete' + image_base: 'nodepool.image:delete',
    }

    def _policy_target(self, verb, target_elements, *args, **kwargs):
        target = dict((k, v) for k, v in kwargs.items())
        if 'node_id' in target_elements:
            target['node_id'] = target_elements['node_id']
        if 'image' in target_elements:
            target['image'] = target_elements['image']
        # build_id, upload_id are probably overkill
        return target
