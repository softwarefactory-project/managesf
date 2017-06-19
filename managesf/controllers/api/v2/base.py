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

from stevedore import driver
import mock

from managesf.model.yamlbkd.engine import SFResourceBackendEngine
from managesf import policy


logger = logging.getLogger(__name__)


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


def load_manager(namespace, service):
    logger.info('loading %s:%s manager' % (namespace, service))
    # hard-coded Dummy service for testing. What could go wrong?
    if service == 'DummyService':
        return mock.MagicMock()
    try:
        manager = driver.DriverManager(namespace=namespace,
                                       name=service,
                                       invoke_on_load=True,
                                       invoke_args=(conf,)).driver
        logger.info('%s:%s manager loaded successfully' % (namespace,
                                                           service))
        return manager
    except Exception as e:
        msg = 'Could not load manager %s:%s: %s' % (namespace,
                                                    service, e)
        logger.error(msg)
        return None


def authorize(rule_name, target):
    if not request.remote_user:
        request.remote_user = request.headers.get('X-Remote-User')
    credentials = {'username': request.remote_user, 'groups': []}
    if request.remote_user:
        credentials['groups'] = get_user_groups(request.remote_user)
    return policy.authorize(rule_name, target, credentials)
