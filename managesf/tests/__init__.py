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

import os
import tempfile

from pecan.configuration import conf_from_dict


class dummy_conf():
    services = ['SFGerrit',
                ]
    gerrit = {
        'url': 'http://gerrit.tests.dom',
        'password': 'admin_password',
        'host': 'gerrit.test.dom',
        'top_domain': 'tests.dom',
        'ssh_port': 2929,
        'sshkey_priv_path': tempfile.mkstemp()[1],
    }
    managesf = {
        'host': 'managesf.tests.dom',
        'sshkey_priv_path': '/tmp/id_rsa',
    }
    resources = {
        'workdir': tempfile.mkdtemp(),
        'subdir': 'resources',
        'master_repo': 'http://sftests.com/r/config',
        'public_url': 'http://sftests.com/manage',
    }
    admin = {
        'name': 'user1',
        'email': 'user1@tests.dom',
    }
    app = {
        'root': 'managesf.controllers.root.RootController',
        'template_path': os.path.join(os.path.dirname(__file__),
                                      '../templates'),
        'modules': ['managesf'],
        'debug': True,
    }
    sqlalchemy = {
        'url': 'sqlite:///%s' % tempfile.mkstemp()[1],
        'encoding': 'utf-8',
    }
    logging = {
        'loggers': {
            'root': {'level': 'INFO', 'handlers': ['console']},
            'managesf': {'level': 'DEBUG', 'handlers': ['console']},
            'py.warnings': {'handlers': ['console']},
            '__force_dict__': True},
        'handlers': {
            'console': {
                'level': 'DEBUG',
                'class': 'logging.StreamHandler',
                'formatter': 'simple'}},
        'formatters': {
            'simple': {
                'format': ('%(asctime)s %(levelname)-5.5s [%(name)s]'
                           '[%(threadName)s] %(message)s')}}
    }
    policy = {}
    DummyService = {
        'dummy_opt1': 'value1',
        'dummy_opt2': 'value2'
    }
    api = conf_from_dict({
        'v2': {
            'resources': ['DummyService', ],
        },
    })
