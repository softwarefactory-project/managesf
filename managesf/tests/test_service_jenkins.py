#!/usr/bin/env python
#
# Copyright (C) 2016  Red Hat <licensing@enovance.com>
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

import json
from urllib import quote_plus
from unittest import TestCase
from mock import patch

from jenkins import Jenkins as SFJenkins

from managesf.services import jenkins
from managesf.tests import dummy_conf


SAMPLE_JENKINS_JOB_DESC = json.dumps(
    {u'actions': [{},
                  {u'parameters': [{u'name': u'first_arg',
                                    u'value': u'BonScott'},
                                   {u'name': u'second_arg',
                                    u'value': u'AngusYoung'}]},
                  {u'causes': [{u'shortDescription': u'Thunderstruck',
                                u'userId': None,
                                u'userName': u'anonymous'}]}],
     u'artifacts': [],
     u'building': False,
     u'builtOn': u'sfstack-centos-7-rcip-dev-89230',
     u'changeSet': {u'items': [], u'kind': None},
     u'culprits': [],
     u'description': u'Dirty deeds done dirt cheap',
     u'displayName': u'#3700',
     u'duration': 35915,
     u'estimatedDuration': 19078,
     u'executor': None,
     u'fullDisplayName': u'sample-unit-tests #3700',
     u'id': u'3700',
     u'keepLog': False,
     u'number': 3700,
     u'queueId': 9006,
     u'result': u'SUCCESS',
     u'timestamp': 1479820746633,
     u'url': u'https://sftests.com/jenkins/sample-unit-tests/3700/'})


class BaseSFJenkinsService(TestCase):
    @classmethod
    def setupClass(cls):
        cls.conf = dummy_conf()
        cls.jenkins = jenkins.SoftwareFactoryJenkins(cls.conf)
#        cls.auth_patch = patch('managesf.services.jenkins.get_cookie')
#        cls.auth_patch.start()

#    @classmethod
#    def tearDownClass(cls):
#        cls.auth_patch.stop()


class TestSFJenkinsManager(BaseSFJenkinsService):
    def test_get_job(self):
        with patch.object(SFJenkins, 'jenkins_open') as jenkins_open:
            jenkins_open.return_value = SAMPLE_JENKINS_JOB_DESC
            self.assertRaisesRegexp(ValueError,
                                    "Please specify a job name",
                                    self.jenkins.job.get_job,
                                    None)
            self.assertRaisesRegexp(ValueError,
                                    "Please specify either job or change",
                                    self.jenkins.job.get_job,
                                    job_name='myjob', job_id='1234',
                                    change='5466')
            self.assertRaisesRegexp(ValueError,
                                    "Please specify a change number",
                                    self.jenkins.job.get_job,
                                    job_name='myjob', patchset='12')
            jobs = self.jenkins.job.get_job('myjob', 1234)
            self.assertEqual(1, len(jobs))
            self.assertEqual('myjob',
                             jobs[0]['job_name'])
            self.assertEqual(1234,
                             jobs[0]['job_id'])
            self.assertEqual('SUCCESS',
                             jobs[0]['status'])
        with patch.object(SFJenkins, 'jenkins_open') as jenkins_open, \
                patch.object(SFJenkins, 'run_script') as run_script:
            jenkins_open.return_value = SAMPLE_JENKINS_JOB_DESC
            expected_filter = {'JOB_NAME': 'myjob',
                               'FILTER_CONDITION': None}
            filter = 'change == "5423"'
            expected_filter['FILTER_CONDITION'] = filter
            run_script.return_value = "Result: 1 2 3 4\n"
            jobs = self.jenkins.job.get_job('myjob', change=5423)
            expected_script = quote_plus(
                jenkins.job.GROOVY_JOB_FILTER % expected_filter)
            run_script.assert_called_with(expected_script)
            self.assertEqual(4,
                             len(jobs))
            filter = 'change == "5423" && patchset == "12"'
            expected_filter['FILTER_CONDITION'] = filter
            run_script.return_value = "Result: 1 3"
            jobs = self.jenkins.job.get_job('myjob', change=5423,
                                            patchset=12)
            expected_script = quote_plus(
                jenkins.job.GROOVY_JOB_FILTER % expected_filter)
            run_script.assert_called_with(expected_script)
            self.assertEqual(2,
                             len(jobs))
            run_script.return_value = "Result: "
            jobs = self.jenkins.job.get_job('myjob', change=5423)
            self.assertEqual(0,
                             len(jobs))
            run_script.return_value = ""
            jobs = self.jenkins.job.get_job('myjob', change=5423)
            self.assertEqual(0,
                             len(jobs))

    def test_get_job_parameters(self):
        with patch.object(SFJenkins, 'jenkins_open') as jenkins_open:
            jenkins_open.return_value = SAMPLE_JENKINS_JOB_DESC
            job = self.jenkins.job.get_job_parameters('myjob', 1234)
            self.assertEqual('myjob',
                             job['job_name'])
            self.assertEqual(1234,
                             job['job_id'])
            expected = {'first_arg': 'BonScott',
                        'second_arg': 'AngusYoung'}
            received = dict((u['name'],
                             u['value']) for u in job['parameters'])
            self.assertEqual(expected,
                             received)

    def test_get_job_status(self):
        with patch.object(SFJenkins, 'jenkins_open') as jenkins_open:
            jenkins_open.return_value = SAMPLE_JENKINS_JOB_DESC
            job = self.jenkins.job.get_job_status('myjob', 1234)
            self.assertEqual('myjob',
                             job['job_name'])
            self.assertEqual(1234,
                             job['job_id'])
            self.assertEqual('SUCCESS',
                             job['status'])
        job_in_progress = json.loads(SAMPLE_JENKINS_JOB_DESC)
        job_in_progress['building'] = True
        job_in_progress['result'] = None
        with patch.object(SFJenkins, 'jenkins_open') as jenkins_open:
            jenkins_open.return_value = json.dumps(job_in_progress)
            job = self.jenkins.job.get_job_status('myjob', 1234)
            self.assertEqual('myjob',
                             job['job_name'])
            self.assertEqual(1234,
                             job['job_id'])
            self.assertEqual('IN_PROGRESS',
                             job['status'])

    def test_get_job_logs(self):
        l = ('https://sftests.com/jenkins/sample-unit-tests/'
             '3700/timestamps/?time=MMM+dd+HH:mm:ss.SSS&appendLog')
        with patch.object(SFJenkins, 'jenkins_open') as jenkins_open:
            jenkins_open.return_value = SAMPLE_JENKINS_JOB_DESC
            job = self.jenkins.job.get_job_logs('myjob', 1234)
            self.assertEqual('myjob',
                             job['job_name'])
            self.assertEqual(1234,
                             job['job_id'])
            self.assertEqual(l,
                             job['logs_url'])

    def test_run(self):
        with patch.object(SFJenkins, 'jenkins_open') as jenkins_open, \
                patch.object(SFJenkins, 'get_job_info') as get_job_info:
            jenkins_open.return_value = SAMPLE_JENKINS_JOB_DESC
            get_job_info.return_value = {'nextBuildNumber': '9999'}
            job = self.jenkins.job.run('myjob',
                                       job_parameters={'first_arg': 'Mercury',
                                                       'second_arg': 'May'})
            self.assertEqual('myjob',
                             job['job_name'])
            self.assertEqual('9999',
                             job['job_id'])

    def test_stop(self):
        with patch.object(SFJenkins, 'jenkins_open') as jenkins_open, \
                patch.object(SFJenkins, 'stop_build') as stop_build:
            jenkins_open.return_value = SAMPLE_JENKINS_JOB_DESC
            self.jenkins.job.stop('myjob', 4567)
            stop_build.assert_called_with('myjob', 4567)
