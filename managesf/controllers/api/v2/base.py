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


import logging
import os.path

from pecan import conf
from pecan import request
from pecan.rest import RestController

from managesf.model.yamlbkd.engine import SFResourceBackendEngine
from managesf import policy


logger = logging.getLogger(__name__)


# TODO move to managesf.api once users API is started
def get_user_groups(user_id):
    # TODO convert user_ids into emails
    user_email = user_id
    resources_engine = SFResourceBackendEngine(
        os.path.join(conf.resources['workdir'], 'read'),
        conf.resources['subdir'])
    resources = resources_engine.get(conf.resources['master_repo'],
                                     'master')
    groups = resources['resources']['groups']
    return [g for g in groups if user_email in groups[g]['members']]


def authorize(rule_name, target):
    if not request.remote_user:
        request.remote_user = request.headers.get('X-Remote-User')
    credentials = {'username': request.remote_user, 'groups': []}
    if request.remote_user:
        credentials['groups'] = get_user_groups(request.remote_user)
    return policy.authorize(rule_name, target, credentials)


class APIv2RestController(RestController):
    def __init__(self, *args, **kwargs):
        super(APIv2RestController, self).__init__(*args, **kwargs)
        self._logger = logging.getLogger(
            'managesf.v2.controllers.%s' % self.__class__.__name__)
