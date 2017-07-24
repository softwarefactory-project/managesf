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


from unittest import TestCase

from mock import patch, call, Mock
from managesf.api.v2.builds import Build
from managesf.tests import dummy_conf
from managesf.tests.fixtures import ZUUL_DB_URI

from webtest import TestApp
from pecan import load_app


c = dummy_conf()
c.zuul['dburi'] = ZUUL_DB_URI
c.zuul['status_url'] = 'blip'
config = {'services': c.services,
          'gerrit': c.gerrit,
          'app': c.app,
          'admin': c.admin,
          'sqlalchemy': c.sqlalchemy,
          'auth': c.auth,
          'htpasswd': c.htpasswd,
          'managesf': c.managesf,
          'storyboard': c.storyboard,
          'mysql': c.mysql,
          'policy': c.policy,
          'resources': c.resources,
          'jenkins': c.jenkins,
          'nodepool': c.nodepool,
          'api': c.api,
          'zuul': c.zuul, }

# App must be loaded before we can import v2 managers
TestApp(load_app(config))


from managesf.api.v2.jobs.services import sfzuul  # noQA


class TestZuulJobManager(TestCase):
    @classmethod
    def setupClass(cls):
        cls.manager = sfzuul.ZuulJobsManager(c)

    def test_get_pipelines(self):
        """Test that pipelines are correctly retrieved"""
        pipelines = self.manager.jobs.pipelines
        self.assertEqual(4, len(pipelines), pipelines)
        for p in ['periodic', 'check', 'gate', 'post']:
            self.assertTrue(p in pipelines, pipelines)

    def test_get_jobs_exception(self):
        self.assertRaisesRegexp(Exception, "Jobs must be distinguished",
                                self.manager.jobs.get, order_by='repository',
                                per_repo=False)
        self.assertRaisesRegexp(Exception, "Jobs must be distinguished",
                                self.manager.jobs.get, order_by='repository')

    def test_get_job_ordering(self):
        """Test ordering arguments"""
        with patch.object(self.manager.jobs, '_get_last_builds') as glb:
            glb.return_value = [], []
            # last_run
            j = self.manager.jobs.get(order_by='last_run')
            self.assertEqual(5, j['total'], j)
            job = j['results'][0]
            # run infos are mocked so not available here
            self.assertEqual('config-check', job.name, job.to_dict())
            j = self.manager.jobs.get(order_by='last_run', desc=True)
            self.assertEqual(5, j['total'], j)
            job = j['results'][0]
            # run infos are mocked so not available here
            self.assertEqual('periodic-zuul-demo', job.name, job.to_dict())
            # job_name
            j = self.manager.jobs.get(order_by='job_name')
            self.assertEqual(5, j['total'], j)
            job = j['results'][0]
            self.assertEqual('config-check', job.name, job.to_dict())
            j = self.manager.jobs.get(order_by='job_name', desc=True)
            self.assertEqual(5, j['total'], j)
            job = j['results'][0]
            self.assertEqual('sexbobomb-unit-tests', job.name, job.to_dict())
            # repository
            j = self.manager.jobs.get(order_by='repository', per_repo=True)
            self.assertEqual(5, j['total'], j)
            job = j['results'][0]
            self.assertEqual('config/config-check', job.id, job.to_dict())
            j = self.manager.jobs.get(order_by='repository', per_repo=True,
                                      desc=True)
            self.assertEqual(5, j['total'], j)
            job = j['results'][0]
            self.assertEqual('zuul-demo/periodic-zuul-demo', job.id,
                             job.to_dict())
            # exec_count
            j = self.manager.jobs.get(order_by='exec_count')
            self.assertEqual(5, j['total'], j)
            job = j['results'][0]
            self.assertEqual(4, job.exec_count,
                             job.to_dict())
            self.assertEqual('config-check', job.name,
                             job.to_dict())
            j = self.manager.jobs.get(order_by='exec_count',
                                      desc=True)
            self.assertEqual(5, j['total'], j)
            job = j['results'][0]
            self.assertEqual(11, job.exec_count,
                             job.to_dict())
            self.assertEqual('sexbobomb-functional-tests', job.name,
                             job.to_dict())

    def test_get_jobs_filtering(self):
        """Test filtering arguments"""
        with patch.object(self.manager.jobs, '_get_last_builds') as glb:
            glb.return_value = [], []
            # instagram no filter
            j = self.manager.jobs.get()
            self.assertEqual(5, j['total'], j)
            for job in j['results']:
                self.assertTrue(job.name in ['config-check',
                                             'config-update',
                                             'periodic-zuul-demo',
                                             'sexbobomb-functional-tests',
                                             'sexbobomb-unit-tests'])
                self.assertTrue(job.id in ['config-check',
                                           'config-update',
                                           'periodic-zuul-demo',
                                           'sexbobomb-functional-tests',
                                           'sexbobomb-unit-tests'])
            # job_name
            j = self.manager.jobs.get(job_name='sexbobomb-unit-tests')
            self.assertEqual(1, j['total'], j)
            self.assertEqual('sexbobomb-unit-tests',
                             j['results'][0].name,
                             j['results'][0])
            j = self.manager.jobs.get(job_name='sexbobomb-unit-tests',
                                      per_repo=True)
            self.assertEqual(1, j['total'], j)
            self.assertEqual('sexbobomb/sexbobomb-unit-tests',
                             j['results'][0].id,
                             j['results'][0])
            # repository
            j = self.manager.jobs.get(repository='sexbobomb')
            self.assertEqual(2, j['total'], j)
            for job in j['results']:
                self.assertTrue(job.name in ['sexbobomb-unit-tests',
                                             'sexbobomb-functional-tests'],
                                job.to_dict())
            # pipeline
            j = self.manager.jobs.get(pipeline='check')
            self.assertEqual(2, j['total'], j)
            for job in j['results']:
                self.assertTrue(job.name in ['sexbobomb-unit-tests',
                                             'config-check'],
                                job.to_dict())

    def test_get_last_builds(self):
        # pipelines = self.manager.jobs.pipelines
        pipelines = ['gate', ]
        job = 'sexbobomb-functional-tests'
        bm = Mock()
        bm.builds.get.return_value = {'results': [Build(build_id=1,
                                                        pipeline=None,
                                                        repository=None,
                                                        change=None,
                                                        patchset=None,
                                                        ref=None, uuid=None,
                                                        job_name=None,
                                                        result=None,
                                                        start_time=1,
                                                        end_time=2,
                                                        voting=None,
                                                        log_url=None,
                                                        node_name=None,
                                                        buildset_id=None,)]}
        sfzuul.build_manager = bm
        self.manager.jobs._get_last_builds(pipelines, job)
        calls = [call(id=15), call(id=6)]
        bm.builds.get.assert_has_calls(calls)
        # no failure
        pipelines = ['post', ]
        job = 'sexbobomb-unit-tests'
        bm = Mock()
        bm.builds.get.return_value = {'results': [Build(build_id=1,
                                                        pipeline=None,
                                                        repository=None,
                                                        change=None,
                                                        patchset=None,
                                                        ref=None, uuid=None,
                                                        job_name=None,
                                                        result=None,
                                                        start_time=1,
                                                        end_time=2,
                                                        voting=None,
                                                        log_url=None,
                                                        node_name=None,
                                                        buildset_id=None,)]}
        sfzuul.build_manager = bm
        self.manager.jobs._get_last_builds(pipelines, job)
        calls = [call(id=16), ]
        bm.builds.get.assert_has_calls(calls)
