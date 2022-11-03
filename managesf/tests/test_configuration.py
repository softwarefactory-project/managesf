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
from managesf.controllers.api.v2.configurations import NodepoolConf
from managesf.controllers.api.v2.configurations import HoundConf
from managesf.controllers.api.v2.configurations import CauthConf


class ZuulTenantsLoadTests(TestCase):
    def assertItemsEqual(self, *args, **kwargs):
        try:
            super(ZuulTenantsLoadTests, self).assertItemsEqual(*args, **kwargs)
        except Exception:  # python 3
            self.assertCountEqual(*args, **kwargs)

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
        tenants = yaml.safe_load(tenants_data)
        for tenant in tenants:
            ztl.merge_tenant_from_data(
                final_tenants, tenant, '/data', 'local', projects_list)
        projects_list_expected = {'local': ['common-config', 'repo1', 'repo2']}
        self.assertItemsEqual(
            projects_list['local'], projects_list_expected['local'])
        final_tenants = ztl.final_tenant_merge(final_tenants)
        expected = {
            'tenant': {
                'admin-rules': [
                    '__SF_DEFAULT_ADMIN',
                    '__SF_TENANT_ZUUL_ADMIN',
                ],
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

    def test_merge_tenant_from_flat_files_with_admin_rules(self):
        ztl = ZuulTenantsLoad(utests=True)
        tenants_data = """
        - tenant:
            name: local
            admin-rules:
              - rule1
              - rule2
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
        - authorization-rule:
            name: rule1
            conditions:
              - iss: some_iss
        - authorization-rule:
            name: rule2
            conditions:
              - email: some@email.com
        """
        final_tenants = {}
        final_rules = {}
        projects_list = {}
        tenants = yaml.safe_load(tenants_data)
        for data in tenants:
            if 'tenant' in data.keys():
                ztl.merge_tenant_from_data(
                    final_tenants, data, '/data', 'local', projects_list)
            else:
                ztl.merge_auth_rule_from_data(
                    final_rules, data)
        projects_list_expected = {'local': ['common-config', 'repo1', 'repo2']}
        self.assertItemsEqual(
            projects_list['local'], projects_list_expected['local'])
        final_tenants = ztl.final_tenant_merge(final_tenants)
        final_rules = ztl.merge_auth_rules(final_rules)
        expected = {
            'tenant': {
                'name': 'local',
                'admin-rules': [
                    'rule1',
                    'rule2',
                    '__SF_DEFAULT_ADMIN',
                    '__SF_TENANT_ZUUL_ADMIN',
                ],
                'max-nodes-per-job': 5,
                'source': {
                    'gerrit': {
                        'config-projects': ['common-config'],
                        'untrusted-projects': ['repo1', 'repo2']
                        }
                    }
                }
            }
        expected_rules = [
            {'authorization-rule': {
                'name': 'rule1',
                'conditions': [
                    {'iss': 'some_iss'}
                ]
            }},
            {'authorization-rule': {
                'name': 'rule2',
                'conditions': [
                    {'email': 'some@email.com'}
                ]
            }},
            {'authorization-rule': {
                'name': '__SF_DEFAULT_ADMIN',
                'conditions': [
                    {'username': 'admin'},
                    {'roles': 'zuul_admin'},
                ]
            }},
            {'authorization-rule': {
                'name': '__SF_TENANT_ZUUL_ADMIN',
                'conditions': [
                    {'roles': '{tenant.name}_zuul_admin'},
                ]
            }},
        ]
        self.assertDictEqual(final_tenants[0], expected)
        self.assertTrue(
            all(r in final_rules for r in expected_rules)
        )

    def test_merge_tenant_from_flat_files_cannot_override_default_rule(self):
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
        - authorization-rule:
            name: __SF_DEFAULT_ADMIN
            conditions:
              - iss: some_iss
        """
        final_tenants = {}
        final_rules = {}
        projects_list = {}
        tenants = yaml.safe_load(tenants_data)
        for data in tenants:
            if 'tenant' in data.keys():
                ztl.merge_tenant_from_data(
                    final_tenants, data, '/data', 'local', projects_list)
            else:
                ztl.merge_auth_rule_from_data(
                    final_rules, data)
        projects_list_expected = {'local': ['common-config', 'repo1', 'repo2']}
        self.assertItemsEqual(
            projects_list['local'], projects_list_expected['local'])
        final_tenants = ztl.final_tenant_merge(final_tenants)
        final_rules = ztl.merge_auth_rules(final_rules)
        expected = {
            'tenant': {
                'name': 'local',
                'admin-rules': [
                    '__SF_DEFAULT_ADMIN',
                    '__SF_TENANT_ZUUL_ADMIN',
                ],
                'max-nodes-per-job': 5,
                'source': {
                    'gerrit': {
                        'config-projects': ['common-config'],
                        'untrusted-projects': ['repo1', 'repo2']
                        }
                    }
                }
            }
        expected_rules = [
            {'authorization-rule': {
                'name': '__SF_DEFAULT_ADMIN',
                'conditions': [
                    {'username': 'admin'},
                    {'roles': 'zuul_admin'},
                ]
            }},
            {'authorization-rule': {
                'name': '__SF_TENANT_ZUUL_ADMIN',
                'conditions': [
                    {'roles': '{tenant.name}_zuul_admin'},
                ]
            }},
        ]
        self.assertDictEqual(final_tenants[0], expected)
        self.assertTrue(expected_rules[0] in final_rules)

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
        tenants = yaml.safe_load(tenant_data)
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
        tenant_data_3 = """
        - tenant:
            name: local2
            max-nodes-per-job: 5
        """
        final_tenants = {}
        projects_list = {}
        tenant1 = yaml.safe_load(tenant_data_1)[0]
        tenant2 = yaml.safe_load(tenant_data_2)[0]
        tenant3 = yaml.safe_load(tenant_data_3)[0]
        ztl.merge_tenant_from_data(
            final_tenants, tenant1, '/t1', 'local', projects_list)
        ztl.merge_tenant_from_data(
            final_tenants, tenant2, '/t2', 'ansible-network', projects_list)
        ztl.merge_tenant_from_data(
            final_tenants, tenant3, '/t3', 'local2', projects_list)
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
                'admin-rules': [
                    '__SF_DEFAULT_ADMIN',
                    '__SF_TENANT_ZUUL_ADMIN'
                ],
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
                'admin-rules': [
                    '__SF_DEFAULT_ADMIN',
                    '__SF_TENANT_ZUUL_ADMIN'
                ],
                'source': {
                    'gerrit': {
                        'config-projects': ['config']
                        }
                    }
                }
            }
        # Verify tenants def w/o sources are supported
        expected_tenant_local2 = {
            'tenant': {
                'name': 'local2',
                'admin-rules': [
                    '__SF_DEFAULT_ADMIN',
                    '__SF_TENANT_ZUUL_ADMIN'
                ],
                'max-nodes-per-job': 5,
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
        self.assertDictEqual(
            [t for t in final_tenants if
             t['tenant']['name'] == 'local2'][0],
            expected_tenant_local2)
        self.assertEqual(len(final_tenants), 3)

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
                    'project2': {
                        'connection': 'gerrit',
                        'options': ['zuul/skip'],
                        'source-repositories': [
                            {'repo4': {'zuul/include': []}}
                        ]
                    },
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
                            }},
                            {'repo4': {
                                'zuul/ignore': True,
                            }},
                            {'repo5': {
                                'private': True,
                            }},
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
        self.assertNotIn('repo4', up)
        self.assertNotIn('repo5', up)

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
            "tenant-options": {
                "zuul/default-jobs-timeout": "3600",
                "zuul/allowed-reporter": "review.openstack.org"
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
        projects_list = {}
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
            tenants, tenant_resources, "tenant1", projects_list,
            local_resources, 'gerrit')
        ztl.add_missing_repos(
            tenants, tenant_resources, "tenant1", projects_list,
            local_resources, 'gerrit')
        up = tenants['tenant1']['source']['gerrit']['untrusted-projects']
        self.assertIn({'repo1': {'include': ['jobs']}}, up)
        self.assertIn({'repo2': {'include': []}}, up)
        self.assertIn({'repo3': {}}, up)
        self.assertEqual(len(up), 3)


class NodepoolConfTests(TestCase):

    def test_load(self):
        nc = NodepoolConf(
            config_dir='managesf/tests/fixtures',
            hostname='nl01',
            catchall=True)
        ret = nc.merge()
        expected_ret = {
            'elements-dir': '/etc/opt/rh/rh-python35/nodepool/elements:/usr/share/sf-elements',  # noqa
            'images-dir': '/var/opt/rh/rh-python35/lib/nodepool/dib',
            'providers': [
                {
                    'name': 'default',
                    'image-name-format': '{image_name}-{timestamp}',
                    'rate': 10.0,
                    'clean-floating-ips': True,
                    'pools': [
                        {
                            'labels':
                            [
                                {
                                    'min-ram': 1024,
                                    'name': 'dib-centos-7',
                                    'diskimage': 'dib-centos-7'
                                }
                            ],
                            'name': 'main',
                            'max-servers': 5,
                            'networks': ['slave-net-name']
                        }
                    ],
                    'boot-timeout': 120,
                    'diskimages': [{'name': 'dib-centos-7'}],
                    'cloud': 'default'
                }
            ],
            'labels': [{'name': 'dib-centos-7', 'min-ready': 1}],
            'build-log-retention': 7,
            'zookeeper-servers': [
                {
                    'host': 'managesf.sftests.com',
                    'port': 2181
                }
            ],
            'webapp': {'port': 8006},
            'build-log-dir': '/var/www/nodepool-log/',
            'diskimages': [
                {
                    'username': 'zuul-worker',
                    'env-vars': {
                        'DIB_GRUB_TIMEOUT': '0',
                        'DIB_IMAGE_CACHE': '/var/cache/nodepool/dib_cache',
                        'DIB_CHECKSUM': '1',
                        'TMPDIR': '/var/cache/nodepool/dib_tmp',
                        'REQUESTS_CA_BUNDLE': ''
                    },
                    'elements': [
                        'centos-minimal',
                        'nodepool-minimal',
                        'zuul-worker-user'
                    ],
                    'name': 'dib-centos-7'
                }
            ]
        }
        self.assertEqual(ret, yaml.safe_dump(expected_ret,
                                             default_flow_style=False))

        # nl02 should only have the extra provider
        old_provider = expected_ret['providers'][0]
        expected_ret['providers'] = [{
            'name': 'k1s',
            'driver': 'openshift',
        }]
        nc = NodepoolConf(
            config_dir='managesf/tests/fixtures', hostname='nl02')
        ret = nc.merge()
        self.assertEqual(ret, yaml.safe_dump(expected_ret,
                                             default_flow_style=False))

        # builder host should have all the providers
        expected_ret['providers'].insert(0, old_provider)
        nc = NodepoolConf(
            config_dir='managesf/tests/fixtures',
            hostname='nb01',
            builder=True)
        ret = nc.merge()
        self.assertEqual(ret, yaml.safe_dump(expected_ret,
                                             default_flow_style=False))


class CauthConfTests(TestCase):

    def test_load(self):
        rpc = CauthConf(utests=True)
        resources = {
            'resources': {
                'tenants': {
                    'local': {
                        'url': 'https://sftests.com/manage',
                        'default-connection': 'gerrit',
                    },
                    'tenant2': {
                        'url': 'https://sftests.com/manage',
                    }
                },
                'connections': {
                    'gerrit': {
                        'base-url': 'https://sftests.com/r',
                        'type': 'gerrit'
                    }
                },
                'projects': {
                    'project1': {
                        'tenant': 'local',
                        'source-repositories': [
                            {'repo1': {}},
                        ]
                    },
                    'project2': {
                        'tenant': 'tenant2',
                        'source-repositories': [
                            {'repo3': {}},
                            {'repo4': {
                                'connection': 'gerrit'
                            }},
                            {'repo5': {
                                'private': True
                            }},
                        ]
                    },
                    'project3': {
                        'tenant': 'local',
                        'source-repositories': [
                            {'repo6': {}},
                            {'repo7': {
                                'repoxplorer/skip': True,
                            }},
                        ]
                    },
                    'project4': {
                        'tenant': 'local',
                        'options': [
                            'repoxplorer/skip',
                        ],
                        'source-repositories': [
                            {'repo7': {}},
                        ]
                    },
                },
                'repos': {
                    'repo2': {},
                    'repo5': {},
                },
                'groups': {
                    'group1': {
                        'members': [
                            'admin@sftests.com'
                        ]
                    }
                }
            }
        }
        rpc.main_resources = resources
        ret = yaml.safe_load(rpc.start())
        expected_ret = {
            'groups': {
                'group1': {
                    'description': '',
                    'members': [
                        'admin@sftests.com',
                    ]
                }
            },
        }
        self.assertDictEqual(ret, expected_ret)


class HoundConfTests(TestCase):

    def test_load(self):
        rpc = HoundConf(utests=True)
        self.maxDiff = None
        resources = {
            'resources': {
                'tenants': {
                    'local': {
                        'url': 'https://sftests.com/manage',
                        'default-connection': 'gerrit',
                    },
                    'tenant2': {
                        'url': 'https://sftests.com/manage',
                    }
                },
                'connections': {
                    'gerrit': {
                        'base-url': 'https://sftests.com/r',
                        'type': 'gerrit'
                    },
                    'github': {
                        'base-url': 'https://github.com/',
                        'type': 'github'
                    },
                    'pagure': {
                        'base-url': 'https://pagure.io/',
                        'type': 'pagure'
                    },
                    'gitlab': {
                        'base-url': 'https://gitlab.com/',
                        'type': 'gitlab'
                    },
                    'gerrithub': {
                        'base-url': 'https://review.gerrithub.io/',
                        'type': 'gerrit'
                    }
                },
                'projects': {
                    'project1': {
                        'tenant': 'local',
                        'source-repositories': [
                            {'repo1': {}},
                        ]
                    },
                    'project2': {
                        'tenant': 'tenant2',
                        'source-repositories': [
                            {'repo3': {}},
                            {'repo4': {
                                'connection': 'gerrit'
                            }},
                            {'repo5': {
                                'private': True
                            }},
                        ]
                    },
                    'project3': {
                        'tenant': 'local',
                        'source-repositories': [
                            {'repo6': {}},
                            {'repo7': {
                                'hound/skip': True,
                            }},
                        ]
                    },
                    'project4': {
                        'tenant': 'local',
                        'options': [
                            'hound/skip',
                        ],
                        'source-repositories': [
                            {'repo7': {}},
                        ]
                    },
                    'project5': {
                        'tenant': 'local',
                        'source-repositories': [
                            {'repo8': {
                                'connection': 'github'
                            }},
                            {'repo9': {
                                'connection': 'gerrithub'
                            }},
                        ]
                    },
                    'project6': {
                        'tenant': 'local',
                        'source-repositories': [
                            {'repo10': {
                                'connection': 'pagure',
                                'default-branch': 'main'
                            }},
                            {'repo11': {
                                'connection': 'gitlab'
                            }},
                        ]
                    },
                },
                'repos': {
                    'repo2': {},
                    'repo5': {},
                },
            }
        }
        rpc.main_resources = resources
        ret = yaml.safe_load(rpc.start())
        expected_ret = {
            'repos': {
                'repo2': {
                    'ms-between-poll': 43200000,
                    'url': 'https://sftests.com/r/repo2',
                    'vcs-config': {
                        'ref': 'master'
                     },
                    'url-pattern': {
                        'base-url': (
                            'https://sftests.com/r/plugins/gitiles/repo2'
                            '/+/refs/heads/master/{path}{anchor}'),
                        'anchor': '#{line}'
                    }
                },
                'repo1': {
                    'ms-between-poll': 43200000,
                    'url': 'https://sftests.com/r/repo1',
                    'vcs-config': {
                        'ref': 'master'
                    },
                    'url-pattern': {
                        'base-url': (
                            'https://sftests.com/r/plugins/gitiles/repo1'
                            '/+/refs/heads/master/{path}{anchor}'),
                        'anchor': '#{line}'
                    }
                },
                'repo6': {
                    'ms-between-poll': 43200000,
                    'url': 'https://sftests.com/r/repo6',
                    'vcs-config': {
                        'ref': 'master'
                    },
                    'url-pattern': {
                        'base-url': (
                            'https://sftests.com/r/plugins/gitiles/repo6'
                            '/+/refs/heads/master/{path}{anchor}'),
                        'anchor': '#{line}'
                    }
                },
                'repo4': {
                    'ms-between-poll': 43200000,
                    'url': 'https://sftests.com/r/repo4',
                    'vcs-config': {
                        'ref': 'master'
                    },
                    'url-pattern': {
                        'base-url': (
                            'https://sftests.com/r/plugins/gitiles/repo4'
                            '/+/refs/heads/master/{path}{anchor}'),
                        'anchor': '#{line}'
                    }
                },
                'repo8': {
                    'ms-between-poll': 43200000,
                    'url': 'http://github.com/repo8',
                    'vcs-config': {
                        'ref': 'master'
                    },
                    'url-pattern': {
                        'anchor': '#L{line}',
                        'base-url': (
                            'http://github.com/repo8/blob/master/'
                            '{path}{anchor}')
                    }
                },
                'repo9': {
                    'ms-between-poll': 43200000,
                    'url': 'https://review.gerrithub.io/repo9',
                    'vcs-config': {
                        'ref': 'master'
                    },
                    'url-pattern': {
                        'base-url': (
                            'http://github.com/repo9/blob/master/'
                            '{path}{anchor}'),
                        'anchor': '#L{line}'
                    }
                },
                'repo10': {
                    'ms-between-poll': 43200000,
                    'url': 'https://pagure.io/repo10',
                    'vcs-config': {
                        'ref': 'main'
                    },
                    'url-pattern': {
                        'base-url': (
                            'https://pagure.io/repo10/blob/main/f/'
                            '{path}{anchor}'),
                        'anchor': '#_{line}'
                    }
                },
                'repo11': {
                    'ms-between-poll': 43200000,
                    'url': 'https://gitlab.com/repo11',
                    'vcs-config': {
                        'ref': 'master'
                    },
                    'url-pattern': {
                        'base-url': (
                            'https://gitlab.com/repo11/-/blob/master/'
                            '{path}{anchor}'),
                        'anchor': '#L{line}'
                    }
                },
            },
            'dbpath': '/var/lib/hound/data',
            'max-concurrent-indexers': 2
        }
        self.assertDictEqual(ret, expected_ret)
