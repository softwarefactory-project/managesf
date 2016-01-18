#!/usr/bin/env python
#
# Copyright (C) 2015 Red Hat <licensing@enovance.com>
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
import os
import stat
import yaml

from managesf.services import base
# from managesf.services import exceptions as exc
from managesf.services.gerrit import utils


logger = logging.getLogger(__name__)


class SFGerritReviewManager(base.CodeReviewManager):
    def get(self, **kwargs):
        client = self.plugin.get_client()
        return client.get_open_changes()

    def propose_test_definition(self, project_name, requester):
        config_git = utils.GerritRepo('config', self.plugin._full_conf)
        config_git.clone()
        job_file = os.path.join(config_git.infos['localcopy_path'],
                                'jobs', 'projects.yaml')
        zuul_file = os.path.join(config_git.infos['localcopy_path'],
                                 'zuul', 'projects.yaml')
        unit_test = '%s-unit-tests' % project_name

        with open(job_file, 'r') as fd:
            job_yaml = yaml.load(fd)
            projects = [x['project']['name'] for x in job_yaml
                        if x.get('project')]
        if project_name not in projects:
            msg = '[%s] Adding project %s to the jobs definition file'
            logger.debug(msg % (self.plugin.service_name, project_name))
            with open(job_file, 'w') as fd:
                project = {'project':
                           {'name': project_name,
                            'jobs': ['{name}-unit-tests', ],
                            'node': 'master'}}
                job_yaml.append(project)
                fd.write(yaml.safe_dump(job_yaml))

        with open(zuul_file, 'r') as fd:
            zuul_yaml = yaml.load(fd)
            projects = [x['name'] for x in zuul_yaml['projects']]

        if project_name not in projects:
            msg = '[%s] Adding project %s to the zuul pipeline file'
            logger.debug(msg % (self.plugin.service_name, project_name))
            with open(zuul_file, 'w') as fd:
                project = {'name': project_name,
                           'check': [unit_test, ],
                           'gate': [unit_test, ]}
                zuul_yaml['projects'].append(project)
                fd.write(yaml.safe_dump(zuul_yaml))
        config_git.review_changes(
            '%s proposes initial test definition for project %s' %
            (requester, project_name))

    def propose_test_scripts(self, project_name, requester):
        test_script_template = '''#!/bin/bash

echo "Modify this script to run your project's unit tests."
exit 0;'''
        project_git = utils.GerritRepo(project_name, self.plugin._full_conf)
        project_git.clone()
        project_git.add_file('run_tests.sh', test_script_template)
        os.chmod(os.path.join(project_git.infos['localcopy_path'],
                              'run_tests.sh'), stat.S_IRWXU)
        msg = '[%s] submitting template test review on %s on behalf of %s'
        logger.debug(msg % (self.plugin.service_name, project_name, requester))
        project_git.review_changes(
            '%s proposes initial test scripts for project %s' %
            (requester, project_name))
