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
        """Get resources and config location from tenant deployment."""
        ret = requests.get(url, verify=bool(int(verify_ssl)))
        return ret.json()

    # Legacy zuul flat files handling
    def fetch_git_repo(self, tenant, url, store, ssl_verify=True):
        """Get config repository from tenant deployment"""
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
        """Fetch legacy zuul yaml file from config repository"""
        paths = []
        for root, dirs, files in os.walk(tenants_dir, topdown=True):
            paths.extend([os.path.join(root, path) for path in files])
        # Keeps only .yaml files
        paths = filter(
            lambda x: x.endswith('.yaml') or x.endswith('.yml'), paths)
        return paths

    def sanitize_projects_list(self, projects_list):
        """Convert flat files projects list to strings list"""
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
        """Merge sources that may be defined in different objects"""
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
        """Load legacy zuul data object into the tenants object"""
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

    def merge_tenant_from_files(
            self, tenants, tenants_conf_files, tenant_name, projects_list):
        """Load legacy zuul yaml file into the tenants object"""
        for path in tenants_conf_files:
            data = yaml.safe_load(open(path))
            if not data:
                continue
            for tenant in data:
                self.merge_tenant_from_data(
                    tenants, tenant, path, tenant_name, projects_list)

    # Zuul configuration loading directly from resources
    def merge_tenant_from_resources(
            self, tenants, tenant_resources, tenant_name, projects_list,
            local_resources, tenant_conf={}):
        # Set zuul-tenant-option
        tenant_options = tenant_conf.get("zuul-tenant-options", {})
        for name, value in tenant_options.items():
            tenants.setdefault(tenant_name, {})[name] = value

        for project_name, project in tenant_resources.get(
                'resources', {}).get('projects', {}).items():
            # TODO: check if resources are remote, and fail/warn if tenant
            #       deployment tries to add project to other tenant
            if project['tenant'] != tenant_name:
                continue
            for sr in project['source-repositories']:
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
                sr_type = 'untrusted-projects'
                if sr[sr_name].get('zuul/config-project') is True:
                    sr_type = 'config-projects'
                    del sr[sr_name]['zuul/config-project']
                for option, value in sr[sr_name].items():
                    if option.startswith('zuul/'):
                        _project[sr_name][option.replace('zuul/', '')] = value
                tenants.setdefault(
                    tenant_name, {}).setdefault(
                        'source', {}).setdefault(
                            source, {}).setdefault(
                                sr_type, []).append(_project)

    def final_tenant_merge(self, tenants):
        final_data = []
        for tenant, tenant_conf in sorted(tenants.items()):
            data = {'tenant': {'name': tenant}}
            data['tenant'].update(tenant_conf)
            final_data.append(data)
        return final_data

    def start(self):
        """Generate a zuul main.yaml from managesf resources and flat files"""

        # tenants is the main structure to be converted into zuul main.yaml
        tenants = {}
        # projects_list is the list of projects used to check for conflicts
        projects_list = {}

        for tenant_name, tenant_conf in self.main_resources.get(
                "resources", {}).get("tenants", {}).items():

            # First we look for the tenant resources
            if tenant_name != "local" and \
               tenant_conf["url"] == self.main_resources["public-url"]:
                url = os.path.join(tenant_conf['url'], 'resources')
                self.log.debug("%s: loading resources %s", tenant_name, url)
                tenant_resources = self.get_resources(url)
            else:
                tenant_resources = self.main_resources

            # Then we pull tenant config repository for legacy zuul flat files
            path = self.fetch_git_repo(
                tenant_name, tenant_resources["config-repo"],
                "/var/lib/managesf/git")
            tenants_dir = os.path.join(path, 'zuul')
            if not os.path.isdir(tenants_dir):
                continue
            tenants_conf_files = self.discover_yaml_files(tenants_dir)
            # And we load flat files
            self.merge_tenant_from_files(
                tenants, tenants_conf_files, tenant_name, projects_list)

            # Finaly we load project from the resources
            self.merge_tenant_from_resources(
                tenants, tenant_resources, tenant_name, projects_list,
                self.main_resources, tenant_conf)

        final_data = self.final_tenant_merge(tenants)
        return yaml.safe_dump(final_data)


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
