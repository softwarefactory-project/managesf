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

from mock import patch, Mock

# from managesf.api.v2 import builds
from managesf.api.v2.builds.services import sfzuul
# from managesf.tests import dummy_conf


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
        with patch('requests.get') as g:
            g.return_value = jmock
            buildsets = sfzuul.get_buildsets_from_status_page('mockurl')
            self.assertEqual(3, len(buildsets))
            bs1 = buildsets[0]
            self.assertEqual("Ze35f64e28b0b4b3d929602a98b3648b1",
                             bs1.zuul_ref)
            self.assertEqual(5, len(bs1.builds))


class TestZuulBuildManager(TestCase):
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
