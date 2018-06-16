# Copyright (C) 2018 Red Hat
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

import copy
import yaml
from unittest import TestCase

from managesf.controllers.api.v2.configurations import ZuulTenantsLoad


class ZuulTenantsLoadTests(TestCase):

    def test_merge_tenant_from_flat_files(self):
        ztl = ZuulTenantsLoad(utests=True)
        tenants_data = """
        - tenant:
            name: local
            source:
              gerrit:
                config-projects:
                  - common-config
        - tenant:
            name: local
            max-nodes-per-job: 5
            source:
              gerrit:
                untrusted-projects:
                  - repo1
                  - repo2
        """
        final_tenants = {}
        projects_list = {}
        tenants = yaml.load(tenants_data)
        for tenant in tenants:
            ztl.merge_tenant_from_data(
                final_tenants, tenant, '/data', 'local', projects_list)
        projects_list_expected = {'local': ['common-config', 'repo1', 'repo2']}
        self.assertItemsEqual(
            projects_list['local'], projects_list_expected['local'])
        final_tenants = ztl.final_tenant_merge(final_tenants)
        expected = {
            'tenant': {
                'name': 'local',
                'max-nodes-per-job': 5,
                'source': {
                    'gerrit': {
                        'config-projects': ['common-config'],
                        'untrusted-projects': ['repo1', 'repo2']
                        }
                    }
                }
            }
        self.assertDictEqual(final_tenants[0], expected)
        self.assertEqual(len(final_tenants), 1)

    def test_merge_tenant_error_from_flat_files(self):
        ztl = ZuulTenantsLoad(utests=True)
        tenant_data = """
        - tenant:
            name: local
            source:
              gerrit:
                config-projects:
                  - config
        - tenant:
            name: local
            source:
              gerrit:
                config-projects:
                  - config
        """
        final_tenants = {}
        projects_list = {}
        tenants = yaml.load(tenant_data)
        ztl.merge_tenant_from_data(
            final_tenants, tenants[0], '/data', 'local', projects_list)
        projects_list_expected = {'local': ['config']}
        self.assertItemsEqual(
            projects_list['local'], projects_list_expected['local'])
        with self.assertRaises(RuntimeError) as ctx:
            ztl.merge_tenant_from_data(
                final_tenants, tenants[1], '/data', 'local',  projects_list)
        self.assertEqual(
            str(ctx.exception),
            '/data: define existing project config for tenant local')

    def test_merge_tenants_from_flat_files(self):
        ztl = ZuulTenantsLoad(utests=True)
        tenant_data_1 = """
        - tenant:
            name: local
            source:
              gerrit:
                config-projects:
                  - config
        """
        tenant_data_2 = """
        - tenant:
            name: ansible-network
            max-nodes-per-job: 5
            source:
              gerrit:
                config-projects:
                  - config
              github:
                untrusted-projects:
                  - repo1
                  - repo2
                  - include: []
                    projects:
                      - repo3
        """
        final_tenants = {}
        projects_list = {}
        tenant1 = yaml.load(tenant_data_1)[0]
        tenant2 = yaml.load(tenant_data_2)[0]
        ztl.merge_tenant_from_data(
            final_tenants, tenant1, '/t1', 'local', projects_list)
        ztl.merge_tenant_from_data(
            final_tenants, tenant2, '/t2', 'ansible-network', projects_list)
        projects_list_expected = {
            'local': ['config'],
            'ansible-network': ['config', 'repo1', 'repo2', 'repo3']}
        self.assertItemsEqual(projects_list['local'],
                              projects_list_expected['local'])
        self.assertItemsEqual(projects_list['ansible-network'],
                              projects_list_expected['ansible-network'])
        final_tenants = ztl.final_tenant_merge(final_tenants)
        expected_tenant_ansible_network = {
            'tenant': {
                'max-nodes-per-job': 5,
                'name': 'ansible-network',
                'source': {
                    'github': {
                        'untrusted-projects': [
                            'repo1',
                            'repo2',
                            {'include': [],
                             'projects': ['repo3']}
                            ]
                        },
                    'gerrit': {
                        'config-projects': ['config']
                        }
                    }
                }
            }
        expected_tenant_local = {
            'tenant': {
                'name': 'local',
                'source': {
                    'gerrit': {
                        'config-projects': ['config']
                        }
                    }
                }
            }
        self.assertDictEqual(
            [t for t in final_tenants if
             t['tenant']['name'] == 'ansible-network'][0],
            expected_tenant_ansible_network)
        self.assertDictEqual(
            [t for t in final_tenants if
             t['tenant']['name'] == 'local'][0],
            expected_tenant_local)
        self.assertEqual(len(final_tenants), 2)

    def test_merge_tenants_from_resources(self):
        ztl = ZuulTenantsLoad(utests=True)
        tenants = {
            'local': {
                'source': {
                    'gerrit': {
                        'config-projects': [
                            'config'
                        ]
                    }
                }
            },
            'ansible-network': {
                'source': {
                    'gerrit': {
                        'untrusted-projects': ['repo1', 'repo2'],
                        'config-projects': ['config'],
                    },
                },
                'max-nodes-per-job': 5}
        }
        orig_tenants = copy.deepcopy(tenants)
        projects_list = {
            'local': ['config'],
            'ansible-network': ['repo1', 'repo2', 'config']
        }
        local_resources = {
            'resources': {
                'connections': {
                    'gerrit': {}
                }
            }
        }
        resources = {
            'resources': {
                'projects': {
                    'project1': {
                        'connection': 'gerrit',
                        'source-repositories': [
                            {'repo3': {
                                'zuul/exclude-unprotected-branches': True,
                                'zuul/include': [],
                            }},
                            {'config2': {
                                'zuul/config-project': True,
                            }},
                            # Is already part of flat tenant definition then
                            # will be ignored
                            {'repo1': {
                                'zuul/include': [],
                            }}
                        ]
                    }
                }
            }
        }
        ztl.merge_tenant_from_resources(
            tenants, resources, 'ansible-network', projects_list,
            local_resources, 'gerrit')
        up = tenants['ansible-network']['source'][
            'gerrit']['untrusted-projects']
        cp = tenants['ansible-network']['source'][
            'gerrit']['config-projects']
        self.assertIn('config', cp)
        self.assertIn({'config2': {}}, cp)
        self.assertIn('repo1', up)
        self.assertIn('repo2', up)
        self.assertIn(
            {'repo3': {
                'exclude-unprotected-branches': True,
                'include': [],
            }}, up)

        local_resources = {
            'resources': {
                'connections': {
                    'gerrit2': {}
                }
            }
        }
        tenants = orig_tenants
        with self.assertRaises(RuntimeError) as ctx:
            ztl.merge_tenant_from_resources(
                tenants, resources, 'ansible-network', {},
                local_resources, 'gerrit')
        self.assertEqual(str(ctx.exception), "gerrit is an unknown connection")

    def test_tenant_options_from_resources(self):
        tenants = {}
        ztl = ZuulTenantsLoad(utests=True)
        tenant_options = {
            "zuul-tenant-options": {
                "default-jobs-timeout": "3600",
                "allowed-reporter": "review.openstack.org"
            }
        }
        ztl.merge_tenant_from_resources(
            tenants, {}, "third-party-ci-tenant", {}, {}, 'gerrit',
            tenant_options)
        final_data = ztl.final_tenant_merge(tenants)
        self.assertIn("default-jobs-timeout", final_data[0]['tenant'])
        self.assertEqual(final_data[0]['tenant']['default-jobs-timeout'],
                         "3600")

    def test_tenant_add_extra_repo(self):
        tenants = {}
        local_resources = {
            'resources': {
                'connections': {
                    'gerrit': {}
                }
            }
        }
        tenant_resources = {
            'resources': {
                'projects': {
                    'project1': {
                        'tenant': 'tenant1',
                        'source-repositories': [
                            {'repo1': {'zuul/include': ['jobs']}},
                            {'repo3': {}},
                        ]
                    }
                },
                'repos': {
                    'repo1': {},
                    'repo2': {},
                }
            }
        }
        ztl = ZuulTenantsLoad(utests=True)
        ztl.merge_tenant_from_resources(
            tenants, tenant_resources, "tenant1", {},
            local_resources, 'gerrit')
        up = tenants['tenant1']['source']['gerrit']['untrusted-projects']
        self.assertIn({'repo1': {'include': ['jobs']}}, up)
        self.assertIn({'repo2': {'include': []}}, up)
        self.assertIn({'repo3': {}}, up)
        self.assertEqual(len(up), 3)
