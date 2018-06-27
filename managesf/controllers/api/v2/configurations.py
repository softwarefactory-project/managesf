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
import git
import yaml
import copy
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
        return ZuulTenantsLoad(
            engine=self.engine,
            default_tenant_name=conf.resources.get('tenant_name', 'local')
            ).start()


class RepoXplorerConfigurationController(BaseConfigurationController):
    @expose()
    def get(self, **kwargs):
        return RepoXplorerConf(engine=self.engine).start()


class ConfigurationController:
    def __init__(self):
        self.engine = SFResourceBackendEngine(
            os.path.join(conf.resources['workdir'], 'read'),
            conf.resources['subdir'])

        self.zuul = ZuulConfigurationController(self.engine)
        self.repoxplorer = RepoXplorerConfigurationController(self.engine)


class ZuulTenantsLoad:
    log = logging.getLogger("managesf.ZuulTenantsLoad")

    def __init__(self, engine=None, utests=False,
                 cache_dir="/var/lib/managesf/git",
                 default_tenant_name="local",
                 config_dir=None,
                 gateway_url=None,
                 tenant=None,
                 master_sf_url=None):
        self.cache_dir = cache_dir
        self.default_tenant_name = default_tenant_name
        self.tenant_resources = None
        self.gateway_url = gateway_url
        if utests:
            # Skip this for unittests
            return
        if not os.path.isdir(self.cache_dir):
            os.makedirs(self.cache_dir)
        if config_dir and gateway_url:
            # Direct use of the resources engine to read
            # resources from a config repo copy.
            # Main usage is by the config-check job
            eng = SFResourceBackendEngine(
                os.path.join(self.cache_dir, 'validate'), 'resources')
            resources = eng.get(
               'file://%s' % config_dir,
               'master', '%s/manage' % gateway_url.rstrip('/'))
            if tenant and master_sf_url:
                self.main_resources = self.get_resources(
                    "%s/manage/v2/resources" % master_sf_url)
                self.tenant_resources = resources
            else:
                self.main_resources = resources
        elif engine is None:
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
            if name != "name":
                self.log.debug("  -> %s: %s" % (name, value))
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
        self.log.debug('Merge tenant files for tenant %s' % tenant_name)
        for path in tenants_conf_files:
            data = yaml.safe_load(open(path))
            if not data:
                continue
            self.log.debug(" Merge tenant from data (%s)" % path)
            for tenant in data:
                self.merge_tenant_from_data(
                    tenants, tenant, path, tenant_name, projects_list)

    # Zuul configuration loading directly from resources
    def merge_tenant_from_resources(
            self, tenants, tenant_resources, tenant_name, projects_list,
            local_resources, default_conn, tenant_conf={}):
        self.log.debug('Merge resources for tenant %s' % tenant_name)
        # Set zuul-tenant-option
        tenant_options = tenant_conf.get("tenant-options", {})
        for name, value in tenant_options.items():
            if name.startswith('zuul/'):
                tenants.setdefault(
                    tenant_name, {})[name.replace('zuul/', '')] = value

        for project_name, project in tenant_resources.get(
                'resources', {}).get('projects', {}).items():
            if not project.get('tenant'):
                project['tenant'] = tenant_name
            else:
                if project['tenant'] != tenant_name:
                    continue
            for sr in project['source-repositories']:
                sr_name = sr.keys()[0]
                if (tenant_name in projects_list and
                        sr_name in projects_list[tenant_name]):
                    # already defined in flat zuul tenant file
                    continue
                else:
                    projects_list.setdefault(tenant_name, []).append(sr_name)
                    if sr[sr_name].get('zuul/ignore') is True:
                        continue
                source = (sr[sr_name].get('connection') or
                          project.get('connection', default_conn))
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
                self.log.debug(" -> Adding %s to %s" % (_project, source))
                tenants.setdefault(
                    tenant_name, {}).setdefault(
                        'source', {}).setdefault(
                            source, {}).setdefault(
                                sr_type, []).append(_project)

    def add_missing_repos(self, tenants, tenant_resources, tenant_name,
                          projects_list, local_resources, default_conn):
        self.log.debug('Merge missing repos for tenant %s' % tenant_name)
        tenant_repos = tenant_resources.get(
            'resources', {}).get('repos', {}).items()
        r_type = 'untrusted-projects'
        for repo_name, repo in tenant_repos:
            if not [True for v in projects_list.values() if repo_name in v]:
                _project = {repo_name: {'include': []}}
                self.log.debug("-> Adding %s to %s" % (_project, default_conn))
                tenants.setdefault(
                    tenant_name, {}).setdefault(
                        'source', {}).setdefault(
                            default_conn, {}).setdefault(
                                r_type, []).append(_project)
            projects_list.setdefault(tenant_name, []).append(repo_name)

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
        tenant_resources_cache = {}

        for tenant_name, tenant_conf in self.main_resources.get(
                "resources", {}).get("tenants", {}).items():

            # When a tenant_resources already exists
            # It is only set if we loaded tenant resources from
            # a config repo copy (eg. config-check)
            if self.tenant_resources:
                # We only proceed when the args gateway_url
                # match the tenant url
                if tenant_conf['url'] != '%s/manage' % (
                        self.gateway_url.rstrip('/')):
                    continue

            self.log.debug(
                "--[ Processing %s - %s" % (tenant_name, tenant_conf))

            # First we look for the tenant resources
            if tenant_name != self.default_tenant_name and \
               tenant_conf["url"] != self.main_resources["public-url"]:
                url = os.path.join(tenant_conf['url'], 'resources')
                if self.tenant_resources:
                    self.log.debug("%s: loading resources from workspace",
                                   tenant_name)
                    tenant_resources = self.tenant_resources
                else:
                    self.log.debug("%s: loading resources %s",
                                   tenant_name, url)
                    tenant_resources = self.get_resources(url)
            else:
                tenant_resources = self.main_resources
                # Fallback to default_tenant_name tenant default connection
                if not tenant_conf.get("default-connection"):
                    tenant_conf["default-connection"] = self.main_resources[
                        "resources"]["tenants"][self.default_tenant_name][
                            "default-connection"]

            tenant_resources_cache[tenant_name] = tenant_resources

            # Then we pull tenant config repository for legacy zuul flat files
            path = self.fetch_git_repo(
                tenant_name, tenant_resources["config-repo"], self.cache_dir)
            tenants_dir = os.path.join(path, 'zuul')
            if not os.path.isdir(tenants_dir):
                continue
            tenants_conf_files = self.discover_yaml_files(tenants_dir)
            # And we load flat files
            self.merge_tenant_from_files(
                tenants, tenants_conf_files, tenant_name, projects_list)

            # We load project from the resources
            default_conn = tenant_conf["default-connection"]
            self.merge_tenant_from_resources(
                tenants, tenant_resources, tenant_name, projects_list,
                self.main_resources, default_conn, tenant_conf)

        for tenant_name, tenant_conf in self.main_resources.get(
                "resources", {}).get("tenants", {}).items():

            tenant_resources = tenant_resources_cache[tenant_name]

            # Finally we add Repos not listed in sr with an include: [] to Zuul
            skip_missing_resources = False
            if tenant_conf["url"] == self.main_resources["public-url"]:
                if tenant_name != self.default_tenant_name:
                    # We only add local missing resources to the
                    # default_tenant_name tenant
                    skip_missing_resources = True
            # Check default_conn is a registered connection
            if default_conn not in self.main_resources[
                    'resources']['connections']:
                # We cannot add repos to Zuul if no valid connection for
                # that tenant
                self.log.debug(
                    "Skip adding missing repos. The tenant has an invalid"
                    " default connection: %s" % default_conn)
                continue
            if not skip_missing_resources:
                self.add_missing_repos(
                    tenants, tenant_resources, tenant_name, projects_list,
                    self.main_resources, default_conn)

            self.log.debug("]-- Finish processing %s" % tenant_name)

        final_data = self.final_tenant_merge(tenants)
        return yaml.safe_dump(final_data)


class RepoXplorerConf():
    log = logging.getLogger("managesf.RepoXplorerConf")

    def __init__(self, engine=None,
                 utests=False, default_tenant_name="local"):
        self.default_tenant_name = default_tenant_name
        self.repos_cache = set()
        self.default = {
            'project-templates': {
                'default': {
                    'branches': ['master']
                }
            },
            'projects': {},
            'identities': {},
            'groups': {},
        }
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

    def compute_uri_gitweb(self, conn):
        conn_type = self.main_resources['resources'][
            'connections'][conn]['type']
        base_url = self.main_resources['resources'][
            'connections'][conn]['base-url'].rstrip('/')
        if conn_type == 'gerrit':
            uri = base_url + '/%(name)s'
            gitweb = (base_url + '/gitweb?p=%(name)s.git' +
                      ';a=commitdiff;h=%%(sha)s;ds=sidebyside')
        elif conn_type == 'github':
            uri = 'http://github.com/%(name)s'
            gitweb = 'http://github.com/%(name)s/commit/%%(sha)s'
        else:
            uri = base_url + '/%(name)s'
            gitweb = base_url + '/%(name)s' + '/commit/?id=%%(sha)s'
        return uri, gitweb

    def start(self):
        for project, data in self.main_resources[
                'resources']['projects'].items():

            # Get the connection type to get the gitweb model
            conn = data.get('connection')
            if not conn:
                tenant_name = data.get('tenant', self.default_tenant_name)
                tenant = self.main_resources['resources'][
                    'tenants'][tenant_name]
                conn = tenant['default-connection']
            uri, gitweb = self.compute_uri_gitweb(conn)

            # Add the project
            self.default['projects'][project] = {
                'repos': {},
                'description': data.get('description', '')
            }

            # Set a template by project to ease overwriting via the config repo
            self.default['project-templates'][project] = copy.deepcopy(
                self.default['project-templates']['default'])
            self.default['project-templates'][project]['uri'] = uri
            self.default['project-templates'][project]['gitweb'] = gitweb

            # Add repos in the project
            for repo in data['source-repositories']:
                reponame = list(repo.keys())[0]
                self.default['projects'][project]['repos'][reponame] = {
                    'template': project}
                self.repos_cache.add(reponame)

        # Add the groups
        for group, data in self.main_resources[
                'resources']['groups'].items():
            grp = {}
            grp['description'] = data.get('description', '')
            grp['emails'] = dict((member, None) for
                                 member in data.get('members', []))
            # Only add groups with members
            if grp['emails']:
                self.default['groups'][group] = grp

        # Add not associated repos
        repos = set(self.main_resources['resources']['repos'].keys())
        missing_repos = repos - self.repos_cache
        if missing_repos:
            tenant = self.main_resources['resources'][
                'tenants'].get(self.default_tenant_name)
            if tenant:
                conn = tenant['default-connection']
                uri, gitweb = self.compute_uri_gitweb(conn)
                self.default['project-templates']['default']['uri'] = uri
                self.default['project-templates']['default']['gitweb'] = gitweb
                default_project = 'extras'
                self.default['projects'][default_project] = {
                    'repos': {},
                    'description':
                        'Repositories not associated to any projects'
                }
                for repo in missing_repos:
                    self.default['projects'][default_project][
                            'repos'][repo] = {
                        'template': 'default'}

        return yaml.safe_dump(self.default)


def cli():
    import argparse

    p = argparse.ArgumentParser()
    p.add_argument("--output")
    p.add_argument("--config-dir")
    p.add_argument("--gateway-url")
    p.add_argument("--master-sf-url")
    p.add_argument("--tenant", action='store_true')
    p.add_argument(
        "--cache-dir", default="/var/lib/software-factory/git-configuration")
    p.add_argument("--debug", action="store_true")
    p.add_argument("--default-tenant-name", default="local")
    p.add_argument("service", choices=["zuul", "repoxplorer"])
    args = p.parse_args()

    logging.basicConfig(
        format='%(asctime)s %(levelname)-5.5s %(name)s - %(message)s',
        level=logging.DEBUG if args.debug else logging.INFO)

    if args.service == "zuul":
        ztl = ZuulTenantsLoad(
            cache_dir=args.cache_dir,
            default_tenant_name=args.default_tenant_name,
            config_dir=args.config_dir,
            gateway_url=args.gateway_url,
            master_sf_url=args.master_sf_url,
            tenant=args.tenant)
        conf = ztl.start()

    if args.service == "repoxplorer":
        rpc = RepoXplorerConf(
            default_tenant_name=args.default_tenant_name)
        conf = rpc.start()

    if args.output:
        open(args.output, "w").write(conf)
    else:
        print(conf)
