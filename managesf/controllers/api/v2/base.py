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
import re

from pecan import conf
from pecan import request, response, abort
from pecan.rest import RestController

from managesf.model.yamlbkd.engine import SFResourceBackendEngine
from managesf import policy
# TODO do it with v2
from managesf.model import SFUserCRUD


logger = logging.getLogger(__name__)


# TODO move to managesf.api once users API is started
def get_user_groups(username):
    user_email = SFUserCRUD().get(username=username).get('email')
    logger.info('Found email %s for username %s' % (username, user_email))
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


class APIv2RestProxyController(APIv2RestController):
    manager = None
    policies_map = {'get .+/path/to/(?P<x>.+)/command': 'managesf.policy.name'}

    def _find_policy(self):
        """Find policy according to REST path."""
        verb = request.method.lower()
        path = request.path
        lookup = "%s %s" % (verb, path)
        for expr in self.policies_map:
            regex = re.compile(expr)
            if regex.search(lookup):
                target_elements = regex.search(lookup).groupdict()
                return {'policy': self.policies_map[expr],
                        'target_elements': target_elements}
        return {}

    def _policy_target(verb, target_elements, *args, **kwargs):
        # override me
        target = {}
        return target

    def __getattr__(self, verb):

        def action(*args, **kwargs):
            pol_scan = self._find_policy()
            pol, target_elements = None, {}
            if pol_scan:
                pol = pol_scan['policy']
                target_elements = pol_scan['target_elements']
            if not kwargs:
                kwargs = request.json if request.content_length else {}
            target = self._policy_target(verb, target_elements,
                                         *args, **kwargs)
            if not authorize(policy,
                             target=target):
                return abort(401,
                             detail='Failure to comply with policy %s' % pol)

            if request.content_length:
                proxied_response = getattr(self.manager, verb)(
                    *args, json=kwargs)
            elif kwargs:
                proxied_response = getattr(self.manager, verb)(
                    *args, data=kwargs)
            else:
                proxied_response = getattr(self.manager, verb)(*args)
            response.status = proxied_response.status_code
            return proxied_response.json()

        return action
