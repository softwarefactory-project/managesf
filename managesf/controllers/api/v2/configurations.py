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

import git
import json
import logging
import os
import requests
import yaml

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


class NodepoolConfigurationController(base.APIv2RestController):
    @expose()
    def get(self, **kwargs):
        return NodepoolConf(via_web=True).start()


class HoundConfigurationController(BaseConfigurationController):
    @expose()
    def get(self, **kwargs):
        return HoundConf(
            engine=self.engine,
            default_tenant_name=conf.resources.get('tenant_name', 'local')
            ).start()


class CauthConfigurationController(BaseConfigurationController):
    @expose()
    def get(self, **kwargs):
        return CauthConf(
            engine=self.engine,
            default_tenant_name=conf.resources.get('tenant_name', 'local')
            ).start()


class ConfigurationController:
    def __init__(self):
        self.engine = SFResourceBackendEngine(
            os.path.join(conf.resources['workdir'], 'read'),
            conf.resources['subdir'])

        self.zuul = ZuulConfigurationController(self.engine)
        self.nodepool = NodepoolConfigurationController()
        self.hound = HoundConfigurationController(self.engine)
        self.cauth = CauthConfigurationController(self.engine)


def get_resources(url):
    """Get resources and config location from tenant deployment."""
    ret = requests.get(url, verify='/etc/ssl/certs/ca-bundle.crt')
    res = ret.json()
    if res.get('error_description'):
        raise RuntimeError("%s: failed %s" % (url, res))
    return res


class ZuulTenantsLoad:
    log = logging.getLogger("managesf.ZuulTenantsLoad")

    def __init__(self, engine=None, utests=False,
                 cache_dir="/var/lib/managesf/git",
                 default_tenant_name="local",
                 config_dir=None,
                 gateway_url=None,
                 tenant=None,
                 master_sf_url=None):
        self.main_resources = {}
        self.cache_dir = cache_dir
        self.default_tenant_name = default_tenant_name
        self.tenant_resources = None
        self.gateway_url = gateway_url
        self.utests = utests
        self.default_auth_rule_name = "__SF_DEFAULT_ADMIN"
        self.default_auth_rule = {
            'name': self.default_auth_rule_name,
            'conditions': [
                {'username': 'admin'},
                {'roles': 'zuul_admin'}
            ]
        }
        self.default_tenant_rule_name = "__SF_TENANT_ZUUL_ADMIN"
        self.default_tenant_rule = {
            "name": self.default_tenant_rule_name,
            'conditions': [
                {'roles': '{tenant.name}_zuul_admin'}
            ]
        }
        if self.utests:
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
                self.main_resources = get_resources(
                    "%s/manage/v2/resources" % master_sf_url)
                self.tenant_resources = resources
            else:
                self.main_resources = resources
        elif engine is None:
            # From cli uses api instead
            self.main_resources = get_resources(
                "http://localhost:20001/v2/resources")
        else:
            self.main_resources = engine.get(
                conf.resources['master_repo'], 'master')

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
                config='http.sslVerify=%s' % bool(int(ssl_verify)))
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
                    sanitized_project_names.append(list(kp)[0])
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

    def merge_auth_rule_from_data(self, auth_rules, auth_rule):
        auth_rule = auth_rule.get('authorization-rule')
        rule_name = auth_rule.get('name')
        auth_rules[rule_name] = {
            'conditions': auth_rule['conditions']
        }

    def merge_tenant_from_files(
            self, tenants, auth_rules, tenants_conf_files,
            tenant_name, projects_list):
        """Load legacy zuul yaml file into the tenants object"""
        self.log.debug('Merge tenant files for tenant %s' % tenant_name)
        for path in tenants_conf_files:
            data = yaml.safe_load(open(path))
            if not data:
                continue
            self.log.debug(" Merge tenant from data (%s)" % path)
            for data_block in data:
                if not isinstance(data_block, dict):
                    raise RuntimeError(
                        "%s: invalid Zuul configuration block: %s" % (
                            path, data_block))
                if data_block.get('tenant'):
                    tenant = data_block
                    self.merge_tenant_from_data(
                        tenants, tenant, path, tenant_name, projects_list)
                elif data_block.get('authorization-rule'):
                    auth_rule = data_block
                    self.merge_auth_rule_from_data(
                        auth_rules, auth_rule)
                else:
                    raise RuntimeError(
                        "%s: invalid Zuul configuration block: %s" % (
                            path, data_block))

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
                if tenant_resources == self.main_resources and \
                      tenant_name != self.default_tenant_name:
                    # This is a tenant hosted on the master instance,
                    # we only match project with an explicit tenant name
                    continue
                project['tenant'] = tenant_name
            else:
                if project['tenant'] != tenant_name:
                    continue
            for sr in project['source-repositories']:
                sr_name = list(sr)[0]
                if (sr[sr_name].get('zuul/skip') is True or
                        'zuul/skip' in project.get('options', [])):
                    continue
                if (tenant_name in projects_list and
                        sr_name in projects_list[tenant_name]):
                    # already defined in flat zuul tenant file
                    continue
                else:
                    projects_list.setdefault(tenant_name, []).append(sr_name)
                    if sr[sr_name].get('zuul/ignore') is True:
                        continue
                    if sr[sr_name].get('private') is True:
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
            # if the default admin-rules are already set, do not add them
            admin_rules = data['tenant'].get('admin-rules', [])
            for rule_name in [
                self.default_auth_rule_name,
                self.default_tenant_rule_name,
            ]:
                if rule_name not in admin_rules:
                    admin_rules.append(rule_name)
            data['tenant']['admin-rules'] = admin_rules
            final_data.append(data)
        return final_data

    def merge_auth_rules(self, auth_rules):
        final = [
            {'authorization-rule': self.default_auth_rule},
            {'authorization-rule': self.default_tenant_rule},
        ]
        for rule_name, rule in sorted(auth_rules.items()):
            if rule_name in [
                self.default_auth_rule_name,
                self.default_tenant_rule_name,
            ]:
                # we do not allow overriding this rule
                continue
            data = {'authorization-rule': {'name': rule_name}}
            data['authorization-rule'].update(rule)
            final.append(data)
        return final

    def start(self):
        """Generate a zuul main.yaml from managesf resources and flat files"""

        # tenants is the main structure to be converted into zuul main.yaml
        tenants = {}
        # projects_list is the list of projects used to check for conflicts
        projects_list = {}
        tenant_resources_cache = {}

        auth_rules = {}

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
                # check for v2
                tenant_url = tenant_conf['url'].rstrip('/')
                if not tenant_url.endswith('/v2'):
                    tenant_url = os.path.join(tenant_url, "v2")
                url = os.path.join(tenant_url, 'resources')
                if self.tenant_resources:
                    self.log.debug("%s: loading resources from workspace",
                                   tenant_name)
                    tenant_resources = self.tenant_resources
                else:
                    self.log.debug("%s: loading resources %s",
                                   tenant_name, url)
                    tenant_resources = get_resources(url)
            else:
                tenant_resources = self.main_resources
                # Fallback to default_tenant_name tenant default connection
                if not tenant_conf.get("default-connection"):
                    tenant_conf["default-connection"] = self.main_resources[
                        "resources"]["tenants"][self.default_tenant_name][
                            "default-connection"]

            tenant_resources_cache[tenant_name] = tenant_resources

            if not self.utests:
                # Then we pull tenant config repository for legacy zuul
                # flat files
                path = self.fetch_git_repo(
                    tenant_name, tenant_resources["config-repo"],
                    self.cache_dir)
                tenants_dir = os.path.join(path, 'zuul')
                if not os.path.isdir(tenants_dir):
                    continue
                tenants_conf_files = self.discover_yaml_files(tenants_dir)
                # And we load flat files
                self.merge_tenant_from_files(
                    tenants, auth_rules, tenants_conf_files,
                    tenant_name, projects_list)

            # We load project from the resources
            default_conn = tenant_conf["default-connection"]
            self.merge_tenant_from_resources(
                tenants, tenant_resources, tenant_name, projects_list,
                self.main_resources, default_conn, tenant_conf)

        for tenant_name, tenant_conf in self.main_resources.get(
                "resources", {}).get("tenants", {}).items():

            tenant_resources = tenant_resources_cache.get(tenant_name)
            if not tenant_resources:
                continue

            default_conn = tenant_conf["default-connection"]

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

        final_tenant_data = self.final_tenant_merge(tenants)
        auth_rules_data = self.merge_auth_rules(auth_rules)
        final_data = auth_rules_data + final_tenant_data
        return yaml.safe_dump(final_data)


class NodepoolConf():
    log = logging.getLogger("managesf.NodepoolConf")

    def __init__(self, via_web=None,
                 cache_dir="/var/lib/managesf/git",
                 config_dir=None,
                 builder=False,
                 catchall=False,
                 hostname=None):
        self.cache_dir = cache_dir
        self.hostname = hostname
        self.builder = builder
        self.catchall = catchall

        if via_web:
            self.config_repo_path = self.fetch_git_repo(
                conf.resources['tenant_name'],
                conf.resources["master_repo"],
                self.cache_dir)
        else:
            self.config_repo_path = config_dir or '/root/config'

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

    def yaml_merge_load(self, nodepool_dir, _nodepool_conf):
        paths = []
        for file in filter(
                lambda x: x.endswith('.yaml') or x.endswith('.yml'),
                os.listdir(nodepool_dir)):
            paths.append(os.path.join(nodepool_dir, file))

        user = {}
        for path in paths:
            # Do not load base config
            if _nodepool_conf in path:
                continue
            data = yaml.safe_load(open(path))
            if not data:
                continue
            for key, value in data.items():
                user.setdefault(key, []).extend(value)
        return user

    def merge(self):
        nodepool_dir = '%s/nodepool' % self.config_repo_path
        _nodepool_conf = '%s/_nodepool.yaml' % nodepool_dir

        user = self.yaml_merge_load(nodepool_dir, _nodepool_conf)
        conf = yaml.safe_load(open(_nodepool_conf))

        # Builder service always catch all
        catchall = True if self.builder else self.catchall

        cache_dir = "/var/cache/nodepool"

        for dib in user.get('diskimages', []):
            self.log.debug('dibimage: %s' % dib)
            dib.setdefault('username', 'zuul-worker')
            envvars = dib.setdefault('env-vars', {})
            envvars['TMPDIR'] = "%s/dib_tmp" % cache_dir
            envvars['DIB_IMAGE_CACHE'] = "%s/dib_cache" % cache_dir
            envvars['DIB_GRUB_TIMEOUT'] = '0'
            envvars['DIB_CHECKSUM'] = '1'
            # Ensure host CA bundle doesn't interfer with dib
            envvars['REQUESTS_CA_BUNDLE'] = ''
            # Make sure env-vars are str
            for k, v in envvars.items():
                if not isinstance(v, str):
                    envvars[k] = str(v)

        if 'cron' in user:
            conf['cron'] = user['cron']
        conf['labels'] = user.get('labels', [])
        providers = user.get('providers', [])
        conf['diskimages'] = user.get('diskimages', [])
        for extra_labels in user.get('extra-labels', []):
            added = False
            for provider in providers:
                if provider['name'] != extra_labels['provider']:
                    continue
                if extra_labels.get('cloud-images'):
                    provider.setdefault('cloud-images', []).extend(
                        extra_labels['cloud-images'])
                for pool in provider.get('pools', []):
                    if pool['name'] == extra_labels['pool']:
                        pool['labels'].extend(extra_labels['labels'])
                        added = True
                        break
                if added:
                    break
            if not added:
                raise RuntimeError("%s: couldn't find provider" % extra_labels)

        # Ensure zuul-console-dir is removed from runc provider
        for provider in providers:
            if provider.get("zuul-console-dir"):
                provider.pop("zuul-console-dir")

        # Add providers
        conf['providers'] = []
        for provider in providers:
            if provider.get("launcher-host") is not None:
                if self.builder or provider["launcher-host"] == self.hostname:
                    conf['providers'].append(provider)
                provider.pop("launcher-host")
            elif catchall:
                conf['providers'].append(provider)

        self.log.debug('final conf: %s' % conf)
        return yaml.safe_dump(conf, default_flow_style=False)

    def start(self):
        """Generate nodepool.yaml file from managesf flat files"""
        return self.merge()


class HoundConf():
    log = logging.getLogger("managesf.HoundConf")

    def __init__(self, engine=None,
                 utests=False,
                 master_sf_url=None,
                 default_tenant_name='local'):
        self.default_tenant_name = default_tenant_name
        self.master_sf_url = master_sf_url
        self.privates = set()
        self.config = {
            "max-concurrent-indexers": 2,
            "dbpath": "/var/lib/hound/data",
            "repos": {},
        }
        if utests:
            # Skip this for unittests
            return
        if engine is None:
            # From cli uses api instead
            self.main_resources = get_resources(
                "http://localhost:20001/v2/resources")
        else:
            self.main_resources = engine.get(
                conf.resources['master_repo'], 'master')

    def compute_uri_gitweb(self, conn):
        conn_type = self.main_resources['resources'][
            'connections'][conn]['type']
        base_url = self.main_resources['resources'][
            'connections'][conn]['base-url'].rstrip('/')
        if conn_type == 'gerrit':
            uri = base_url + '/%(name)s'
            gitweb = (
                base_url +
                '/plugins/gitiles/%(name)s/+/' +
                'refs/heads/%(branch)s/{path}{anchor}')
            anchor = '#{line}'
            if 'https://review.gerrithub.io' in base_url:
                gitweb = (
                    'http://github.com/%(name)s/blob/%(branch)s/{path}{anchor}'
                )
                anchor = '#L{line}'
        if conn_type == 'github':
            uri = 'http://github.com/%(name)s'
            gitweb = (
                'http://github.com/%(name)s/blob/%(branch)s/{path}{anchor}')
            anchor = '#L{line}'
        if conn_type == 'pagure':
            uri = base_url + '/%(name)s'
            gitweb = (
                base_url + '/%(name)s/blob/%(branch)s/f/{path}{anchor}')
            anchor = '#_{line}'
        if conn_type == 'gitlab':
            uri = base_url + '/%(name)s'
            gitweb = base_url + '/%(name)s/-/blob/%(branch)s/{path}{anchor}'
            anchor = '#L{line}'

        return uri, gitweb, anchor

    def add_in_conf(self, repo, conn, branch):
        conn_type = self.main_resources['resources'][
            'connections'][conn]['type']
        if conn_type not in ['gerrit', 'github', 'pagure', 'gitlab']:
            return
        uri, gitweb, anchor = self.compute_uri_gitweb(conn)
        self.config["repos"][repo] = {
            "url": uri % {'name': repo},
            "ms-between-poll": int(12*60*60*1000),
            "vcs-config": {
                "ref": branch
            },
            "url-pattern": {
                "base-url": gitweb % {'name': repo, 'branch': branch},
                "anchor": anchor,
            }
        }

    def start(self):
        for project, data in self.main_resources.get(
                "resources", {}).get("projects", {}).items():
            for sr in data.get('source-repositories', []):
                repo_name = list(sr.keys())[0]
                if sr[repo_name].get('private') is True:
                    self.privates.add(repo_name)
                    continue
                if (sr[repo_name].get('hound/skip') is True or
                        'hound/skip' in data.get('options', [])):
                    self.privates.add(repo_name)
                    continue
                conn = sr[repo_name].get('connection')
                if not conn:
                    conn = data.get('connection')
                if not conn:
                    tenant_name = data.get('tenant', self.default_tenant_name)
                    tenant = self.main_resources['resources'][
                        'tenants'][tenant_name]
                    conn = tenant.get('default-connection')
                conn_defined = self.main_resources['resources'].get(
                    'connections', {}).get(conn)
                if conn_defined:
                    branch = sr[repo_name].get('default-branch', 'master')
                    self.add_in_conf(repo_name, conn, branch)
                    self.privates.add(repo_name)

        # Add repositories not associated to a project
        for repo, data in self.main_resources.get(
                "resources", {}).get("repos", {}).items():
            if repo in self.privates:
                continue
            tenant = self.main_resources['resources'][
                'tenants'][self.default_tenant_name]
            conn = tenant.get('default-connection')
            if conn_defined:
                branch = data.get('default-branch', 'master')
                self.add_in_conf(repo, conn, branch)

        return json.dumps(self.config, indent=True, sort_keys=True)


class CauthConf():
    log = logging.getLogger("managesf.CauthConf")

    def __init__(self, engine=None,
                 utests=False,
                 master_sf_url=None,
                 default_tenant_name='local'):
        self.default_tenant_name = default_tenant_name
        self.master_sf_url = master_sf_url
        self.repos_cache = set()
        self.default = {
            'groups': {},
        }
        if utests:
            # Skip this for unittests
            return
        if engine is None:
            # From cli uses api instead
            self.main_resources = get_resources(
                "http://localhost:20001/v2/resources")
        else:
            self.main_resources = engine.get(
                conf.resources['master_repo'], 'master')

    def start(self):
        # Add the groups
        for group, data in self.main_resources[
                'resources'].get('groups', {}).items():
            grp = {}
            grp['description'] = data.get('description', '')
            grp['members'] = data.get('members', [])
            # Only add groups with members
            if len(grp['members']) > 0:
                self.default['groups'][group] = grp

        return yaml.safe_dump(self.default)


def cli():
    import argparse

    p = argparse.ArgumentParser()
    p.add_argument("--output")
    p.add_argument("--config-dir")
    p.add_argument("--gateway-url")
    p.add_argument("--master-sf-url")
    p.add_argument("--extra-launcher", action='store_true', default=False,
                   help="This host is not the main nodepool-launcher")
    p.add_argument("--builder", action='store_true',
                   help="This host is a nodepool-builder")
    p.add_argument("--hostname", help="Get configuration for a dedicated host "
                   "(only for nodepool services)")
    p.add_argument("--tenant", action='store_true')
    p.add_argument(
        "--cache-dir", default="/var/lib/software-factory/git-configuration")
    p.add_argument("--debug", action="store_true")
    p.add_argument("--default-tenant-name", default="local")
    p.add_argument("service", choices=["zuul", "nodepool", "repoxplorer",
                                       "hound", "cauth"])
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

    if args.service == "nodepool":
        rpc = NodepoolConf(
            cache_dir=args.cache_dir,
            config_dir=args.config_dir,
            builder=args.builder,
            catchall=not args.extra_launcher,
            hostname=args.hostname)
        conf = rpc.start()

    if args.service == "hound":
        rpc = HoundConf(
            master_sf_url=args.master_sf_url,
            default_tenant_name=args.default_tenant_name)
        conf = rpc.start()

    if args.service == "cauth":
        rpc = CauthConf(
            master_sf_url=args.master_sf_url,
            default_tenant_name=args.default_tenant_name)
        conf = rpc.start()

    if args.output:
        open(args.output, "w").write(conf)
    else:
        print(conf)
