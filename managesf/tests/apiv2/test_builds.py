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


from datetime import datetime
from unittest import TestCase

from mock import patch, Mock

from managesf.api.v2.base import isotime
from managesf.api.v2.builds import Build, BuildSet
from managesf.api.v2.builds.services import sfzuul  # noQA
from managesf.tests.fixtures import ZUUL_DB_URI
from managesf.tests import dummy_conf


SAMPLE_STATUS_JSON = {
  "pipelines": [
    {
      "description": "Check !",
      "change_queues": [
        {
          "window": 0,
          "heads": [
            [
              {
                "failing_reasons": [],
                "items_behind": [
                  "8536,7"
                ],
                "jobs": [],
                "url": "https://softwarefactory-project.io/r/8491",
                "item_ahead": None,
                "enqueue_time": 1498120550403,
                "project": "software-factory/sf-config",
                "owner": {
                  "username": "morucci",
                  "name": "Fabien Boucher",
                  "email": "fboucher@redhat.com"
                },
                "live": False,
                "remaining_time": 0,
                "zuul_ref": "Z2597aed1976c4046aa7f46879e74bd90",
                "active": True,
                "id": "8491,22"
              },
              {
                "failing_reasons": [],
                "items_behind": [],
                "jobs": [
                  {
                    "pipeline": "check",
                    "retry": False,
                    "name": "sf-rpm-build",
                    "canceled": False,
                    "url": "https://sftests/jenkins/job/sf-rpm-build/2934/",
                    "worker": {
                      "name": "Unknown",
                      "extra": {},
                      "hostname": None,
                      "fqdn": None,
                      "ips": [],
                      "program": None,
                      "version": None
                    },
                    "start_time": 1498120640.39495,
                    "launch_time": 1498120552.320508,
                    "number": 2934,
                    "remaining_time": 0,
                    "node_name": "dib-centos-7-rcip-dev-163495",
                    "elapsed_time": 416703,
                    "estimated_time": 370.8,
                    "report_url": "https://sftests/job/sf-rpm-build/2934/",
                    "end_time": 1498121057.098061,
                    "result": "SUCCESS",
                    "node_labels": [
                      "dib-centos-7",
                      "dib-centos-7-rcip-dev-163495"
                    ],
                    "voting": True,
                    "uuid": "58c6d065169f49969d3d3b3e1a23dc31"
                  },
                  {
                    "pipeline": "check",
                    "retry": False,
                    "name": "sf-ci-functional-minimal",
                    "canceled": False,
                    "url": "https://sftests/sf-ci-functional-minimal/257/",
                    "worker": {
                      "name": "Unknown",
                      "extra": {},
                      "hostname": None,
                      "fqdn": None,
                      "ips": [],
                      "program": None,
                      "version": None
                    },
                    "start_time": 1498121057.125627,
                    "launch_time": 1498121057.110507,
                    "number": 257,
                    "remaining_time": 3073042,
                    "node_name": None,
                    "elapsed_time": 870158,
                    "estimated_time": 3943.2,
                    "report_url": "https://sftests/sf-ci/257/",
                    "end_time": None,
                    "result": None,
                    "node_labels": [],
                    "voting": True,
                    "uuid": "210edec340644d2b92f37e158b7f26eb"
                  },
                  {
                    "pipeline": "check",
                    "retry": False,
                    "name": "sf-ci-upgrade-minimal",
                    "canceled": False,
                    "url": "https://sftests/251/",
                    "worker": {
                      "name": "Unknown",
                      "extra": {},
                      "hostname": None,
                      "fqdn": None,
                      "ips": [],
                      "program": None,
                      "version": None
                    },
                    "start_time": 1498121057.164845,
                    "launch_time": 1498121057.11549,
                    "number": 251,
                    "remaining_time": 2562981,
                    "node_name": None,
                    "elapsed_time": 870119,
                    "estimated_time": 3433.1,
                    "report_url": "https://sftests/251/",
                    "end_time": None,
                    "result": None,
                    "node_labels": [],
                    "voting": True,
                    "uuid": "6e5c1fc3931d4966a44a19e6cadd4e56"
                  },
                  {
                    "pipeline": "check",
                    "retry": False,
                    "name": "sf-ci-functional-allinone",
                    "canceled": False,
                    "url": "https://sftests/252/",
                    "worker": {
                      "name": "Unknown",
                      "extra": {},
                      "hostname": None,
                      "fqdn": None,
                      "ips": [],
                      "program": None,
                      "version": None
                    },
                    "start_time": 1498121057.183883,
                    "launch_time": 1498121057.120055,
                    "number": 252,
                    "remaining_time": 5517500,
                    "node_name": None,
                    "elapsed_time": 870100,
                    "estimated_time": 6387.6,
                    "report_url": "https://sftests/252/",
                    "end_time": None,
                    "result": None,
                    "node_labels": [],
                    "voting": True,
                    "uuid": "502432f810c4462caad082c942858736"
                  },
                  {
                    "pipeline": "check",
                    "retry": False,
                    "name": "sf-ci-upgrade-allinone",
                    "canceled": False,
                    "url": "https://sftests/233/",
                    "worker": {
                      "name": "Unknown",
                      "extra": {},
                      "hostname": None,
                      "fqdn": None,
                      "ips": [],
                      "program": None,
                      "version": None
                    },
                    "start_time": 1498121285.407457,
                    "launch_time": 1498121057.123957,
                    "number": 233,
                    "remaining_time": 2833824,
                    "node_name": None,
                    "elapsed_time": 641876,
                    "estimated_time": 3475.7,
                    "report_url": "https://sftests/233/",
                    "end_time": None,
                    "result": None,
                    "node_labels": [],
                    "voting": True,
                    "uuid": "a7fe49444e044a6cb72a351c327204b3"
                  }
                ],
                "url": "https://softwarefactory-project.io/r/8536",
                "item_ahead": "8491,22",
                "enqueue_time": 1498120550403,
                "project": "software-factory/sf-config",
                "owner": {
                  "username": "morucci",
                  "name": "Fabien Boucher",
                  "email": "fboucher@redhat.com"
                },
                "live": True,
                "remaining_time": 5517500,
                "zuul_ref": "Ze35f64e28b0b4b3d929602a98b3648b1",
                "active": True,
                "id": "8536,7"
              }
            ]
          ],
          "name": "software-factory/sf-config"
        }
      ],
      "name": "check"
    },
    {
      "description": "Post pipeline.",
      "change_queues": [
        {
          "window": 0,
          "heads": [
            [
              {
                "failing_reasons": [],
                "items_behind": [],
                "jobs": [
                  {
                    "pipeline": "post",
                    "retry": False,
                    "name": "horizon-branch-tarball",
                    "canceled": False,
                    "url": "telnet://104.130.216.51:19885",
                    "worker": {
                      "name": "Unknown",
                      "extra": {},
                      "hostname": None,
                      "fqdn": None,
                      "ips": [],
                      "program": None,
                      "version": None
                    },
                    "start_time": 1499065290.095232,
                    "launch_time": 1499065289.824253,
                    "number": "a538124bc665477f9d0d85cd9b1c701f",
                    "remaining_time": 0,
                    "node_name": None,
                    "elapsed_time": 272643,
                    "estimated_time": 259.1,
                    "report_url": "http://blip/",
                    "end_time": 1499065562.738986,
                    "result": "SUCCESS",
                    "node_labels": [],
                    "voting": True,
                    "uuid": "a538124bc665477f9d0d85cd9b1c701f"
                  },
                  {
                    "pipeline": "post",
                    "retry": False,
                    "name": "horizon-docs-unified-ubuntu-xenial",
                    "canceled": False,
                    "url": "telnet://89.46.81.142:19885",
                    "worker": {
                      "name": "Unknown",
                      "extra": {},
                      "hostname": None,
                      "fqdn": None,
                      "ips": [],
                      "program": None,
                      "version": None
                    },
                    "start_time": 1499065289.90023,
                    "launch_time": 1499065289.828573,
                    "number": "700a1e4f72e841288dce3ff71a8050d5",
                    "remaining_time": 0,
                    "node_name": None,
                    "elapsed_time": 297582,
                    "estimated_time": 289.625,
                    "report_url": "http://blipblip/",
                    "end_time": 1499065587.482519,
                    "result": "SUCCESS",
                    "node_labels": [],
                    "voting": True,
                    "uuid": "700a1e4f72e841288dce3ff71a8050d5"
                  },
                ],
                "url": "https://bluh/",
                "item_ahead": None,
                "enqueue_time": 1499065284989,
                "project": "openstack/horizon",
                "owner": None,
                "live": True,
                "remaining_time": None,
                "zuul_ref": None,
                "active": True,
                "id": "9bcd4c43a25a0298c26e40fde27fa5e518621ea2"
              }
            ]
          ],
          "name": "openstack/horizon"
        },
      ],
      "name": "post"
    },
    {
      "description": "Jobs in this queue are triggered daily.",
      "change_queues": [],
      "name": "periodic"
    },
    {
      "description": "This pipeline runs jobs in response to any tag event.",
      "change_queues": [],
      "name": "tag"
    },
    {
      "description": "Experimental !",
      "change_queues": [],
      "name": "experimental"
    },
    {
      "description": "This pipeline manages swift mirrors update",
      "change_queues": [
        {
          "window": 0,
          "heads": [
            [
              {
                "failing_reasons": [],
                "items_behind": [],
                "jobs": [
                  {
                    "pipeline": "periodic_mirrors",
                    "retry": False,
                    "name": "sf-mirror-update",
                    "canceled": False,
                    "url": "https://blop",
                    "worker": {
                      "name": "Unknown",
                      "extra": {},
                      "hostname": None,
                      "fqdn": None,
                      "ips": [],
                      "program": None,
                      "version": None
                    },
                    "start_time": 1499040276.928339,
                    "launch_time": 1499040276.844429,
                    "number": 47,
                    "remaining_time": 0,
                    "node_name": None,
                    "elapsed_time": 31594128,
                    "estimated_time": 14313.7,
                    "report_url": "https://blip/",
                    "end_time": None,
                    "result": None,
                    "node_labels": [],
                    "voting": True,
                    "uuid": "69ac6c1236f8441f8b6d4f2fe01ba50f"
                  }
                ],
                "url": None,
                "item_ahead": None,
                "enqueue_time": 1499040000189,
                "project": "sf-mirror-update",
                "owner": None,
                "live": True,
                "remaining_time": 0,
                "zuul_ref": None,
                "active": True,
                "id": None
              }
            ]
          ],
          "name": "sf-mirror-update"
        }
      ],
      "name": "periodic_mirrors"
    }
  ],
  "zuul_version": "2.5.1",
  "trigger_event_queue": {
    "length": 0
  },
  "result_event_queue": {
    "length": 0
  },
  "last_reconfigured": 1498101675000
}


class TestHelperFunctions(TestCase):
    def test_compute_ref(self):
        change, patchset = 5423, 12
        self.assertEqual("refs/changes/23/5423/12",
                         sfzuul.compute_ref(change, patchset))
        change, patchset = "5423", "12"
        self.assertEqual("refs/changes/23/5423/12",
                         sfzuul.compute_ref(change, patchset))
        change, patchset = 54, 2
        self.assertEqual("refs/changes/54/54/2",
                         sfzuul.compute_ref(change, patchset))
        change, patchset = 9, 3
        self.assertEqual("refs/changes/09/9/3",
                         sfzuul.compute_ref(change, patchset))

    def test_get_buildsets_from_status_page(self):
        jmock = Mock()
        jmock.json.return_value = SAMPLE_STATUS_JSON
        jmock.ok = True
        with patch('requests.get') as g:
            g.return_value = jmock
            buildsets = sfzuul.get_buildsets_from_status_page('mockurl')
            self.assertEqual(3, len(buildsets))
            bs1 = buildsets[0]
            self.assertEqual("Ze35f64e28b0b4b3d929602a98b3648b1",
                             bs1.zuul_ref)
            self.assertEqual(5, len(bs1.builds))
        jmock.ok = False
        with patch('requests.get') as g:
            g.return_value = jmock
            buildsets = sfzuul.get_buildsets_from_status_page('mockurl')
            self.assertEqual(0, len(buildsets))


class TestInProgressSwitch(TestCase):
    @classmethod
    def setupClass(cls):
        c = dummy_conf()
        c.zuul['dburi'] = ZUUL_DB_URI
        c.zuul['status_url'] = 'blop'
        cls.manager = sfzuul.ZuulBuildsManager(c)

    def test_in_progress_switch(self):
        with patch.object(self.manager.builds, '_get_from_status_url') as g:
            g.return_value = [Build(build_id=9999, pipeline=None,
                                    repository=None, change=None,
                                    patchset=None, ref=None, uuid=None,
                                    job_name='eh eh', result=None,
                                    start_time=None, end_time=None,
                                    voting=None, log_url=None,
                                    node_name=None, buildset_id=None)]
            r = self.manager.builds.get(id=9999,
                                        in_progress_only=False)
            self.assertEqual(0, r['total'])
            r = self.manager.builds.get(id=9999,
                                        in_progress_only=True)
            self.assertEqual(1, r['total'])
            self.assertEqual('eh eh', r['results'][0].job_name)
        with patch.object(self.manager.buildsets, '_get_from_status_url') as g:
            g.return_value = [BuildSet(buildset_id=9999, zuul_ref=None,
                                       pipeline=None, repository=None,
                                       change=None, patchset=None,
                                       ref=None, score=None,
                                       message='eh eh', builds=[])]
            r = self.manager.buildsets.get(id=9999,
                                           in_progress_only=False)
            self.assertEqual(0, r['total'])
            r = self.manager.buildsets.get(id=9999,
                                           in_progress_only=True)
            self.assertEqual(1, r['total'])
            self.assertEqual('eh eh', r['results'][0].message)


class TestZuulBuildManagerFromStatusURL(TestCase):
    @classmethod
    def setupClass(cls):
        cls.manager = Mock()
        cls.manager.status_url = 'blip'
        cls.manager.connection = Mock()
        cls.ZuulBuildManager = sfzuul.ZuulBuildManager(cls.manager)
        cls.ZuulBuildSetManager = sfzuul.ZuulBuildSetManager(cls.manager)

    def test_get_builds_from_status_url(self):
        jmock = Mock()
        jmock.json.return_value = SAMPLE_STATUS_JSON
        with patch('requests.get') as g:
            g.return_value = jmock
            # no filtering
            results = self.ZuulBuildManager._get_from_status_url()
            self.assertEqual(8, len(results))
            # non applicable fields
            for k in ['buildset_id', 'id', 'score', 'message']:
                r = self.ZuulBuildManager._get_from_status_url(**{k: 'bleh'})
                self.assertEqual([], r)
            kwargs = {k: 'bleh', 'change': '8536'}
            r = self.ZuulBuildManager._get_from_status_url(**kwargs)
            self.assertEqual([], r)
            kwargs = {'job_name': 'sf-rpm-build'}
            r = self.ZuulBuildManager._get_from_status_url(**kwargs)
            self.assertEqual(1, len(r))
            kwargs = {'job_name': 'sf-rpm-build',
                      'pipeline': 'check'}
            r = self.ZuulBuildManager._get_from_status_url(**kwargs)
            self.assertEqual(1, len(r))
            d = datetime.fromtimestamp(1498120660)
            kwargs = {'started_before': d}
            r = self.ZuulBuildManager._get_from_status_url(**kwargs)
            self.assertEqual(1, len(r))
            d = datetime.fromtimestamp(1499065290)
            kwargs = {'started_after': d}
            r = self.ZuulBuildManager._get_from_status_url(**kwargs)
            self.assertEqual(1, len(r))

    def test_get_build_from_status_url_other_pipelines(self):
        jmock = Mock()
        jmock.json.return_value = SAMPLE_STATUS_JSON
        with patch('requests.get') as g:
            g.return_value = jmock
            kwargs = {'pipeline': 'periodic_mirrors'}
            r = self.ZuulBuildManager._get_from_status_url(**kwargs)
            self.assertEqual(1, len(r))
            self.assertEqual("69ac6c1236f8441f8b6d4f2fe01ba50f",
                             r[0].uuid)
            self.assertEqual(None,
                             r[0].change)
            kwargs = {'pipeline': 'post'}
            r = self.ZuulBuildManager._get_from_status_url(**kwargs)
            self.assertEqual(2, len(r))
            self.assertEqual("9bcd4c43a25a0298c26e40fde27fa5e518621ea2",
                             r[0].ref)
            self.assertEqual("a538124bc665477f9d0d85cd9b1c701f",
                             r[0].uuid)
            self.assertEqual("700a1e4f72e841288dce3ff71a8050d5",
                             r[1].uuid)

    def test_get_buildsets_from_status_url(self):
        jmock = Mock()
        jmock.json.return_value = SAMPLE_STATUS_JSON
        with patch('requests.get') as g:
            g.return_value = jmock
            # no filtering
            results = self.ZuulBuildSetManager._get_from_status_url()
            self.assertEqual(3, len(results))
            # non applicable fields
            for k in ['id', 'score', 'message']:
                r = self.ZuulBuildSetManager._get_from_status_url(
                    **{k: 'bleh'})
                self.assertEqual([], r)
            kwargs = {k: 'bleh', 'change': '8536'}
            r = self.ZuulBuildSetManager._get_from_status_url(**kwargs)
            self.assertEqual([], r)
            kwargs = {'change': '8536'}
            r = self.ZuulBuildSetManager._get_from_status_url(**kwargs)
            self.assertEqual(1, len(r))
            kwargs = {'change': '8537'}
            r = self.ZuulBuildSetManager._get_from_status_url(**kwargs)
            self.assertEqual(0, len(r))
            kwargs = {'change': '8536',
                      'pipeline': 'check'}
            r = self.ZuulBuildSetManager._get_from_status_url(**kwargs)
            self.assertEqual(1, len(r))


class TestZuulBuildManagerFromDB(TestCase):
    @classmethod
    def setupClass(cls):
        c = dummy_conf()
        c.zuul['dburi'] = ZUUL_DB_URI
        c.zuul['status_url'] = 'blop'
        cls.manager = sfzuul.ZuulBuildsManager(c)

    def test_get_build_single_filter(self):
        """Test that every filtering parameter is accounted for"""
        # uuid
        b = self.manager.builds.get(uuid='4b5b02270c664b3c95e7c1c0711f0534',
                                    in_progress_only=False)
        self.assertEqual(1, b['total'], b)
        self.assertEqual(1, len(b['results']), b)
        for r in b['results']:
            self.assertEqual('4b5b02270c664b3c95e7c1c0711f0534',
                             r.uuid,
                             r.to_dict())
        # job_name
        b = self.manager.builds.get(job_name='config-check',
                                    in_progress_only=False,)
        self.assertEqual(4, b['total'], b)
        for r in b['results']:
            self.assertEqual('config-check',
                             r.job_name,
                             r.to_dict())
        # id
        b = self.manager.builds.get(id=1,
                                    in_progress_only=False,)
        self.assertEqual(1, b['total'], b)
        for r in b['results']:
            self.assertEqual(1,
                             r.id,
                             r.to_dict())
        # ref
        b = self.manager.builds.get(ref='refs/changes/01/1/1',
                                    in_progress_only=False,)
        self.assertEqual(2, b['total'], b)
        for r in b['results']:
            self.assertEqual('refs/changes/01/1/1',
                             r.ref,
                             r.to_dict())
        # repository
        b = self.manager.builds.get(repository='sexbobomb',
                                    in_progress_only=False,)
        self.assertEqual(20, b['total'], b)
        for r in b['results']:
            self.assertEqual('sexbobomb',
                             r.repository,
                             r.to_dict())
        # change & patchset
        b = self.manager.builds.get(change=2,
                                    in_progress_only=False)
        self.assertEqual(6, b['total'], b)
        for r in b['results']:
            self.assertEqual(2,
                             int(r.change),
                             r.to_dict())
        b = self.manager.builds.get(change=2, patchset=1,
                                    in_progress_only=False)
        self.assertEqual(3, b['total'], b)
        for r in b['results']:
            self.assertEqual(2,
                             int(r.change),
                             r.to_dict())
            self.assertEqual(1,
                             int(r.patchset),
                             r.to_dict())
        self.assertRaisesRegexp(ValueError, "Please specify a change",
                                self.manager.builds.get,
                                patchset=1, in_progress_only=False)
        # buildset_id
        b = self.manager.builds.get(buildset_id=5,
                                    in_progress_only=False)
        self.assertEqual(2, b['total'], b)
        for r in b['results']:
            self.assertEqual(5,
                             int(r.buildset_id),
                             r.to_dict())
        # pipeline
        b = self.manager.builds.get(pipeline='gate',
                                    in_progress_only=False)
        self.assertEqual(8, b['total'], b)
        for r in b['results']:
            self.assertEqual('gate',
                             r.pipeline,
                             r.to_dict())
        # started_before
        test_time = datetime.strptime('2017-07-05T15:35:38', isotime)
        b = self.manager.builds.get(started_before=test_time,
                                    in_progress_only=False)
        self.assertEqual(38, b['total'], b)
        for r in b['results']:
            self.assertTrue(test_time > r.start_time,
                            r.to_dict())
        # started_after
        b = self.manager.builds.get(started_after=test_time,
                                    in_progress_only=False)
        self.assertEqual(5, b['total'], b)
        for r in b['results']:
            self.assertTrue(test_time <= r.start_time,
                            r.to_dict())
        # result
        b = self.manager.builds.get(result='FAILURE',
                                    in_progress_only=False)
        self.assertEqual(2, b['total'], b)
        for r in b['results']:
            self.assertEqual('FAILURE',
                             r.result,
                             r.to_dict())
        # voting
        b = self.manager.builds.get(voting=1,
                                    in_progress_only=False)
        self.assertEqual(43, b['total'], b)
        for r in b['results']:
            self.assertEqual(1,
                             int(r.voting),
                             r.to_dict())
        # TODO node

    def test_get_buildset_single_filter(self):
        """Test that every filtering parameter is accounted for"""
        # ref
        b = self.manager.buildsets.get(ref='refs/changes/01/1/1',
                                       in_progress_only=False,)
        self.assertEqual(2, b['total'], b)
        for r in b['results']:
            self.assertEqual('refs/changes/01/1/1',
                             r.ref,
                             r.to_dict())
        # repository
        b = self.manager.buildsets.get(repository='sexbobomb',
                                       in_progress_only=False,)
        self.assertEqual(17, b['total'], b)
        for r in b['results']:
            self.assertEqual('sexbobomb',
                             r.repository,
                             r.to_dict())
        # change & patchset
        b = self.manager.buildsets.get(change=2,
                                       in_progress_only=False)
        self.assertEqual(4, b['total'], b)
        for r in b['results']:
            self.assertEqual(2,
                             int(r.change),
                             r.to_dict())
        b = self.manager.buildsets.get(change=2, patchset=1,
                                       in_progress_only=False)
        self.assertEqual(2, b['total'], b)
        for r in b['results']:
            self.assertEqual(2,
                             int(r.change),
                             r.to_dict())
            self.assertEqual(1,
                             int(r.patchset),
                             r.to_dict())
        self.assertRaisesRegexp(ValueError, "Please specify a change",
                                self.manager.buildsets.get,
                                patchset=1, in_progress_only=False)
        # zuul_ref
        zuul_ref = 'Zd46db7de71d445b6863429b37640d04d'
        b = self.manager.buildsets.get(zuul_ref=zuul_ref,
                                       in_progress_only=False,)
        self.assertEqual(1, b['total'], b)
        for r in b['results']:
            self.assertEqual(zuul_ref,
                             r.zuul_ref,
                             r.to_dict())
        # id
        b = self.manager.buildsets.get(id=7,
                                       in_progress_only=False,)
        self.assertEqual(1, b['total'], b)
        for r in b['results']:
            self.assertEqual(7,
                             r.id,
                             r.to_dict())
        # pipeline
        b = self.manager.buildsets.get(pipeline='check',
                                       in_progress_only=False,)
        self.assertEqual(7, b['total'], b)
        for r in b['results']:
            self.assertEqual('check',
                             r.pipeline,
                             r.to_dict())
        # score
        b = self.manager.buildsets.get(score=-2,
                                       in_progress_only=False,)
        self.assertEqual(1, b['total'], b)
        for r in b['results']:
            self.assertEqual(-2,
                             int(r.score),
                             r.to_dict())

    def test_get_build_ordering(self):
        """Test ordering parameters"""
        # id
        b = self.manager.builds.get(order_by='id', in_progress_only=False, )
        self.assertEqual(43, b['total'], b)
        self.assertEqual(1, b['results'][0].id,
                         b['results'][0].to_dict())
        b = self.manager.builds.get(order_by='id', in_progress_only=False,
                                    desc=True)
        self.assertEqual(43, b['results'][0].id,
                         b['results'][0].to_dict())
        # buildset_id
        b = self.manager.builds.get(order_by='buildset_id',
                                    in_progress_only=False)
        self.assertEqual(43, b['total'], b)
        self.assertEqual(1, b['results'][0].buildset_id,
                         b['results'][0].to_dict())
        b = self.manager.builds.get(order_by='buildset_id',
                                    in_progress_only=False,
                                    desc=True)
        self.assertEqual(40, b['results'][0].buildset_id,
                         b['results'][0].to_dict())
        # pipeline
        b = self.manager.builds.get(order_by='pipeline',
                                    in_progress_only=False)
        self.assertEqual(43, b['total'], b)
        self.assertEqual('check', b['results'][0].pipeline,
                         b['results'][0].to_dict())
        b = self.manager.builds.get(order_by='pipeline',
                                    in_progress_only=False,
                                    desc=True)
        self.assertEqual('post', b['results'][0].pipeline,
                         b['results'][0].to_dict())
        # change
        b = self.manager.builds.get(order_by='change',
                                    in_progress_only=False)
        self.assertEqual(43, b['total'], b)
        self.assertEqual(0, b['results'][0].change,
                         b['results'][0].to_dict())
        b = self.manager.builds.get(order_by='change',
                                    in_progress_only=False,
                                    desc=True)
        self.assertEqual(10, b['results'][0].change,
                         b['results'][0].to_dict())
        # repository
        b = self.manager.builds.get(order_by='repository',
                                    in_progress_only=False)
        self.assertEqual(43, b['total'], b)
        self.assertEqual('config', b['results'][0].repository,
                         b['results'][0].to_dict())
        b = self.manager.builds.get(order_by='repository',
                                    in_progress_only=False,
                                    desc=True)
        self.assertEqual('zuul-demo', b['results'][0].repository,
                         b['results'][0].to_dict())
        # result
        b = self.manager.builds.get(order_by='result', in_progress_only=False)
        self.assertEqual(43, b['total'], b)
        self.assertEqual('FAILURE', b['results'][0].result,
                         b['results'][0].to_dict())
        b = self.manager.builds.get(order_by='result', in_progress_only=False,
                                    desc=True)
        self.assertEqual('SUCCESS', b['results'][0].result,
                         b['results'][0].to_dict())
        # job_name
        b = self.manager.builds.get(order_by='job_name',
                                    in_progress_only=False)
        self.assertEqual(43, b['total'], b)
        self.assertEqual('config-check', b['results'][0].job_name,
                         b['results'][0].to_dict())
        b = self.manager.builds.get(order_by='job_name',
                                    in_progress_only=False,
                                    desc=True)
        self.assertEqual('sexbobomb-unit-tests', b['results'][0].job_name,
                         b['results'][0].to_dict())
        # start_time
        b = self.manager.builds.get(order_by='start_time',
                                    in_progress_only=False)
        self.assertEqual(43, b['total'], b)
        self.assertEqual('2017-06-28T21:34:38',
                         b['results'][0].start_time.strftime(isotime),
                         b['results'][0].to_dict())
        b = self.manager.builds.get(order_by='start_time',
                                    in_progress_only=False,
                                    desc=True)
        self.assertEqual('2017-07-05T15:35:43',
                         b['results'][0].start_time.strftime(isotime),
                         b['results'][0].to_dict())
        # end_time
        b = self.manager.builds.get(order_by='end_time',
                                    in_progress_only=False)
        self.assertEqual(43, b['total'], b)
        self.assertEqual('2017-06-28T21:34:53',
                         b['results'][0].end_time.strftime(isotime),
                         b['results'][0].to_dict())
        b = self.manager.builds.get(order_by='end_time',
                                    in_progress_only=False,
                                    desc=True)
        self.assertEqual('2017-07-05T15:35:43',
                         b['results'][0].end_time.strftime(isotime),
                         b['results'][0].to_dict())

    def test_get_buildset_ordering(self):
        """Test ordering parameters"""
        # id
        b = self.manager.buildsets.get(order_by='id', in_progress_only=False, )
        self.assertEqual(40, b['total'], b)
        self.assertEqual(1, b['results'][0].id,
                         b['results'][0].to_dict())
        b = self.manager.buildsets.get(order_by='id', in_progress_only=False,
                                       desc=True)
        self.assertEqual(40, b['results'][0].id,
                         b['results'][0].to_dict())
        # pipeline
        b = self.manager.buildsets.get(order_by='pipeline',
                                       in_progress_only=False)
        self.assertEqual(40, b['total'], b)
        self.assertEqual('check', b['results'][0].pipeline,
                         b['results'][0].to_dict())
        b = self.manager.buildsets.get(order_by='pipeline',
                                       in_progress_only=False,
                                       desc=True)
        self.assertEqual('post', b['results'][0].pipeline,
                         b['results'][0].to_dict())
        # change
        b = self.manager.buildsets.get(order_by='change',
                                       in_progress_only=False)
        self.assertEqual(40, b['total'], b)
        self.assertEqual(0, b['results'][0].change,
                         b['results'][0].to_dict())
        b = self.manager.buildsets.get(order_by='change',
                                       in_progress_only=False,
                                       desc=True)
        self.assertEqual(10, b['results'][0].change,
                         b['results'][0].to_dict())
        # repository
        b = self.manager.buildsets.get(order_by='repository',
                                       in_progress_only=False)
        self.assertEqual(40, b['total'], b)
        self.assertEqual('config', b['results'][0].repository,
                         b['results'][0].to_dict())
        b = self.manager.buildsets.get(order_by='repository',
                                       in_progress_only=False,
                                       desc=True)
        self.assertEqual('zuul-demo', b['results'][0].repository,
                         b['results'][0].to_dict())
        # score
        b = self.manager.buildsets.get(order_by='score',
                                       in_progress_only=False)
        self.assertEqual(40, b['total'], b)
        self.assertEqual(-4, b['results'][0].score,
                         b['results'][0].to_dict())
        b = self.manager.buildsets.get(order_by='score',
                                       in_progress_only=False,
                                       desc=True)
        self.assertEqual(2, b['results'][0].score,
                         b['results'][0].to_dict())
