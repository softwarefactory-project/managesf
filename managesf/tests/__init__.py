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


class dummy_conf():
    auth = {
        'host': 'auth.tests.dom',
    }
    services = ['SFGerrit',
                'SFRedmine',
                'SFStoryboard',
                'SFJenkins',
                'SFNodepool',
                ]
    gerrit = {
        'user': 'gerrit',
        'host': 'gerrit.test.dom',
        'url': 'http://gerrit.tests.dom',
        'top_domain': 'tests.dom',
        'ssh_port': 2929,
        'sshkey_priv_path': tempfile.mkstemp()[1],
        'replication_config_path': tempfile.mkstemp()[1],
        'db_host': 'db.tests.dom',
        'db_name': 'gerrit_db',
        'db_user': 'gerrit_db_user',
        'db_password': 'gerrit_db_password',
    }
    storyboard = {
        'base_url': 'http://sftests.com/r/',
        'host': 'storyboard',
        'url': 'http://storyboard:20000/v1/',
        'service_token': 'SECRET',
        'db_host': 'db.tests.dom',
        'db_name': 'gerrit_db',
        'db_user': 'gerrit_db_user',
        'db_password': 'gerrit_db_password',
    }
    redmine = {
        'api_key': 'XXX',
        'host': 'redmine.tests.dom',
        'url': 'http://redmine.tests.dom',
    }
    jenkins = {
        'api_url': 'http://jenkins.tests.dom:8080/jenkins/',
        'user': 'jenkins',
        'password': 'jenkins_password_or_api_token',
    }
    nodepool = {
        'host': 'nodepool.tests.dom',
        'user': 'nodepool',
        'key': '/path/to/key',
    }
    managesf = {
        'host': 'managesf.tests.dom',
        'sshkey_priv_path': '/tmp/id_rsa',
        'sshkey_update_path': '/tmp/id_rsa',
        'backup_dir': '/tmp',
    }
    resources = {
        'workdir': '/tmp/workspace',
        'subdir': 'resources',
        'master_repo': 'http://sftests.com/r/config',
    }
    mysql = {
        'host': 'mysql.test.dom',
    }
    admin = {
        'name': 'user1',
        'email': 'user1@tests.dom',
        'http_password': 'userpass',
        'cookiejar': None
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
    htpasswd = {
        'filename': tempfile.mkstemp()[1]
    }
    policy = {}
