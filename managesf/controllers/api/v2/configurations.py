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

import os
import sys
import git
import yaml
import requests
import logging

from pecan import conf
from pecan import expose

from managesf.controllers.api.v2 import base
from managesf.model.yamlbkd.engine import SFResourceBackendEngine


import unittest


class BaseConfigurationController(base.APIv2RestController):
    def __init__(self, engine):
        self.engine = engine


class ZuulConfigurationController(BaseConfigurationController):
    @expose()
    def get(self, **kwargs):
        return ZuulTenantsLoad(self.engine).start()


class ConfigurationController:
    def __init__(self):
        self.engine = SFResourceBackendEngine(
            os.path.join(conf.resources['workdir'], 'read'),
            conf.resources['subdir'])

        self.zuul = ZuulConfigurationController(self.engine)


class ZuulTenantsLoad:
    log = logging.getLogger("managesf.ZuulTenantsLoad")

    def __init__(self, engine=None, utests=False):
        if utests:
            # Skip this for unittests
            return
        if engine is None:
            # From cli uses api instead
            self.main_resources = self.get_resources(
                "http://localhost:20001/v2/resources")
        else:
            self.main_resources = engine.get(
                conf.resources['master_repo'], 'master')

    def get_resources(self, url, verify_ssl=True):
        ret = requests.get(url, verify=bool(int(verify_ssl)))
        return ret.json()

    def fetch_git_repo(self, tenant, url, store, ssl_verify=True):
        tenant_config_project_path = os.path.join(
            store, tenant, os.path.basename(url))
        if not os.path.isdir(tenant_config_project_path):
            os.makedirs(tenant_config_project_path)
        if not os.path.isdir(os.path.join(tenant_config_project_path, '.git')):
            # Clone this is the first time
            git.Repo.clone_from(
                url, tenant_config_project_path, branch='master',
                depth=1, config='http.sslVerify=%s' % bool(int(ssl_verify)))
        else:
            # Refresh the repository
            repo = git.Repo(tenant_config_project_path)
            repo.remotes.origin.pull()
        return tenant_config_project_path

    def discover_yaml_files(self, tenants_dir):
        # Discover all files in config_path
        paths = []
        for root, dirs, files in os.walk(tenants_dir, topdown=True):
            paths.extend([os.path.join(root, path) for path in files])
            # Keeps only .yaml files
        paths = filter(
            lambda x: x.endswith('.yaml') or x.endswith('.yml'), paths)
        return paths

    def merge_tenant_from_files(
            self, tenants, tenants_conf_files, tenant_name, projects_list):
        for path in tenants_conf_files:
            data = yaml.safe_load(open(path))
            if not data:
                continue
            for tenant in data:
                self.merge_tenant_from_data(
                    tenants, tenant, path, tenant_name, projects_list)

    def sanitize_projects_list(self, projects_list):
        for tenant, tenant_projects_list in projects_list.items():
            sanitized_project_names = []
            for kp in tenant_projects_list:
                if isinstance(kp, dict) and 'projects' in kp.keys():
                    sanitized_project_names.extend(kp['projects'])
                elif isinstance(kp, dict):
                    sanitized_project_names.append(kp.keys()[0])
                else:
                    sanitized_project_names.append(kp)
            projects_list[tenant] = sanitized_project_names

    def merge_source(
            self, tenant_conf, sources, path, tenant_name, projects_list):
        tenant_sources = tenant_conf.setdefault("source", {})
        for source in sources.keys():
            source_conf = tenant_sources.setdefault(source, {})
            for project_type in sources[source]:
                projects = source_conf.setdefault(project_type, [])
                for project in sources[source][project_type]:
                    if project in projects:
                        raise RuntimeError(
                            "%s: define existing project %s for tenant %s"
                            % (path, project, tenant_name))
                    projects_list.setdefault(tenant_name, []).append(project)
                    projects.append(project)

    def merge_tenant_from_data(
            self, tenants, tenant, path, tenant_name, projects_list):
        # Merge document
        if not isinstance(tenant, dict) or not tenant.get('tenant'):
            raise RuntimeError("%s: invalid tenant block: %s" % (
                path, tenant
            ))
        tenant = tenant.get('tenant')
        if tenant['name'] != tenant_name:
            return
        tenant_conf = tenants.setdefault(
            tenant['name'], {})
        for name, value in tenant.items():
            if name == "source":
                # Merge source lists
                self.merge_source(
                    tenant_conf, value, path, tenant_name, projects_list)
            elif name != "name":
                # Set tenant option
                if name in tenant_conf:
                    raise RuntimeError(
                        "%s: define multiple %s for tenant %s" % (
                            path, tenant["name"], name))
                tenant_conf[name] = value
        self.sanitize_projects_list(projects_list)

    def merge_tenant_from_resources(
            self, tenants, tenant_resources, tenant_name, projects_list,
            local_resources):
        for pid, project in tenant_resources['resources']['projects'].items():
            if project['tenant'] != tenant_name:
                continue
            for sr in project['source-repositories']:
                # TODO(fbo): support tenants/zuul-tenant-options
                sr_name = sr.keys()[0]
                if (tenant_name in projects_list and
                        sr_name in projects_list[tenant_name]):
                    # already defined in flat zuul tenant file
                    continue
                source = (sr[sr_name].get('connection') or
                          project['connection'])
                if source not in local_resources['resources']['connections']:
                    raise RuntimeError("%s is an unknown connection" % source)
                _project = {sr_name: {}}
                type = 'untrusted-projects'
                if sr[sr_name].get('zuul/config-project') is True:
                    type = 'config-projects'
                    del sr[sr_name]['zuul/config-project']
                for option, value in sr[sr_name].items():
                    if option.startswith('zuul/'):
                        _project[sr_name][option.replace('zuul/', '')] = value
                tenants.setdefault(
                    tenant_name, {}).setdefault(
                        'source', {}).setdefault(
                            source, {}).setdefault(
                                type, []).append(_project)

    def final_tenant_merge(self, tenants):
        final_data = []
        for tenant, tenant_conf in tenants.items():
            data = {'tenant': {'name': tenant}}
            data['tenant'].update(tenant_conf)
            final_data.append(data)
        return final_data

    def start(self):
        tenants = {}
        projects_list = {}
        for tenant_name, data in self.main_resources.get(
                "resources", {}).get("tenants", {}).items():
            if tenant_name != "local" and \
               data["url"] == self.main_resources["public-url"]:
                # Tenant is hosted locally
                continue
            if tenant_name != "local":
                url = os.path.join(data['url'], 'resources')
                self.log.debug("%s: loading resources %s", tenant_name, url)
                tenant_resources = self.get_resources(url)
            else:
                tenant_resources = self.main_resources
            path = self.fetch_git_repo(
                tenant_name, tenant_resources["config-repo"],
                "/var/lib/managesf/git")
            tenants_dir = os.path.join(path, 'zuul')
            if not os.path.isdir(tenants_dir):
                continue
            tenants_conf_files = self.discover_yaml_files(tenants_dir)
            self.merge_tenant_from_files(
                tenants, tenants_conf_files, tenant_name, projects_list)
            self.merge_tenant_from_resources(
                tenants, tenant_resources, tenant_name, projects_list,
                self.main_resources)

        final_yaml = self.final_tenant_merge(tenants)
        return yaml.safe_dump(final_yaml)


class TenantsLoadTests(unittest.TestCase):

    def test_merge_tenant_case_1(self):
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

    def test_merge_tenant_case_2(self):
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

    def test_merge_tenant_case_3(self):
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

    def test_merge_tenant_case_4(self):
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
        import copy
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
                        'tenant': 'ansible-network',
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
            local_resources)
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
                tenants, resources, 'ansible-network', projects_list,
                local_resources)
        self.assertEqual(str(ctx.exception), "gerrit is an unknown connection")


def cli():
    import argparse

    p = argparse.ArgumentParser()
    p.add_argument("--output")
    p.add_argument("service", choices=["zuul"])
    args = p.parse_args()

    if args.service == "zuul":
        ztl = ZuulTenantsLoad()
        conf = ztl.start()

    if args.output:
        open(args.output, "w").write(conf)
    else:
        print(conf)


if __name__ == "__main__":
    try:
        ztl = ZuulTenantsLoad()
        print(ztl.start())
    except Exception:
        print("Unexpected error running %s" % " ".join(sys.argv))
        raise