#
# Copyright (c) 2016 Red Hat, Inc.
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

import re
import json
import hashlib
import logging

from git.config import GitConfigParser

from requests.exceptions import HTTPError

from managesf.services.gerrit import SoftwareFactoryGerrit
from managesf.model.yamlbkd.resource import BaseResource
from managesf.services.gerrit import utils

# ## DEBUG statements to ease run that standalone ###
# import logging
# logging.basicConfig()
# logging.getLogger().setLevel(logging.DEBUG)
# requests_log = logging.getLogger("requests.packages.urllib3")
# requests_log.setLevel(logging.DEBUG)
# requests_log.propagate = True
#
# from pecan import configuration
# from managesf.model.yamlbkd.resources.gitrepository import GitRepositoryOps
# conf = configuration.conf_from_file('/etc/managesf/config.py')
# g = GitRepositoryOps(conf, {})
# g._set_client()
# ###

logger = logging.getLogger(__name__)
DEFAULT_GROUPS = ('Non-Interactive Users',
                  'Administrators',
                  'Anonymous Users')


class GitRepositoryOps(object):

    def __init__(self, conf, new):
        self.conf = conf
        self.new = new
        self.client = None

    def _set_client(self):
        if not self.client:
            gerrit = SoftwareFactoryGerrit(self.conf)
            self.client = gerrit.get_client()

    def get_all(self):
        logs = []
        gitrepos = {}
        acls = {}

        self._set_client()

        try:
            repos = self.client.get_projects()
            if repos is False:
                logs.append("Repo list: err API returned HTTP 404/409")
        except Exception, e:
            logger.exception("get_projects failed %s" % e)
            logs.append("Repo list: err API returned %s" % e)

        for name in repos:
            gitrepos[name] = {}
            r = utils.GerritRepo(name, self.conf)
            # Remove the project section when it only contains description
            remove_project_section = False
            acl_path = r.get_raw_acls()
            acl_groups = set()
            c = GitConfigParser(acl_path)
            c.read()
            for section_name in c.sections():
                for k, v in c.items(section_name):
                    if section_name == 'project':
                        if k == 'description':
                            if len(c.items(section_name)) == 1:
                                remove_project_section = True
                            gitrepos[name]['description'] = v
                        continue
                    r = re.search('group (.*)', v)
                    if r:
                        acl_groups.add(r.groups()[0].strip())

            _acl = file(acl_path).read()
            acl = ""
            # Clean the ACL file to avoid issue at YAML multiline
            # serialization. Remove the description and as a good
            # practice description should never appears in a ACL rtype
            # TODO(fbo): extra_validation of acl must deny the description
            for l in _acl.splitlines():
                if remove_project_section and l.find('[project]') != -1:
                    continue
                if l.find('description') != -1:
                    continue
                acl += l.replace('\t', '    ').rstrip() + '\n'
            m = hashlib.md5()
            m.update(acl)
            acl_id = m.hexdigest()
            gitrepos[name]['name'] = name
            gitrepos[name]['acl'] = acl_id
            acls[acl_id] = {}
            acls[acl_id]['file'] = acl
            acls[acl_id]['groups'] = acl_groups
            acls[acl_id]['groups'] -= set(DEFAULT_GROUPS)
            acls[acl_id]['groups'] -= set(('Registered Users',))
            acls[acl_id]['groups'] = list(acls[acl_id]['groups'])
        return logs, {'repos': gitrepos, 'acls': acls}

    def create(self, **kwargs):
        logs = []
        name = kwargs['name']
        description = kwargs['description']
        kwargs['acl']

        self._set_client()

        try:
            ret = self.client.create_project(name,
                                             description,
                                             ['Administrators'])
            if ret is False:
                logs.append("Repo create: err API returned HTTP 404/409")
        except Exception, e:
            logger.exception("create_project failed %s" % e)
            logs.append("Repo create: err API returned %s" % e)
            return logs

        try:
            r = utils.GerritRepo(name, self.conf)
            r.clone()
        except Exception, e:
            logger.exception("GerritRepo create repo checkout failed %s" % e)
            logs.append("Repo create fails to checkout the repo %s" % e)
            return logs

        logs.extend(self.install_acl(r, **kwargs))
        logs.extend(self.install_git_review_file(r, name, 'master'))
        logs.extend(self.create_branches(r, **kwargs))

        return logs

    def delete(self, **kwargs):
        logs = []
        name = kwargs['name']

        self._set_client()

        try:
            ret = self.client.delete_project(name, True)
            if ret is False:
                logs.append("Repo delete: err API returned HTTP 404/409")
        except Exception, e:
            logger.exception("delete_project failed %s" % e)
            logs.append("Repo delete: err API returned %s" % e)

        return logs

    def update(self, **kwargs):
        logs = []

        self._set_client()

        try:
            r = utils.GerritRepo(kwargs['name'], self.conf)
            r.clone()
        except Exception, e:
            logger.exception("GerritRepo update repo checkout failed %s" % e)
            logs.append("Repo update fails to checkout the repo %s" % e)
            return logs

        logs.extend(self.install_acl(r, **kwargs))
        logs.extend(self.create_branches(r, **kwargs))

        return logs

    def install_git_review_file(self, r, name, branch):
        logs = []

        gitreview_template = """[gerrit]
host=%(gerrit-host)s
port=%(gerrit-host-port)s
project=%(name)s
defaultbranch=%(branch)s
"""

        paths = {}
        content = gitreview_template % (
            {'gerrit-host': self.conf.gerrit['top_domain'],
             'gerrit-host-port': self.conf.gerrit['ssh_port'],
             'name': name,
             'branch': branch})
        paths['.gitreview'] = content

        # Clone the master branch and push the .gitreview file
        try:
            r.push_branch(branch, paths)
        except Exception, e:
            logger.exception("GerritRepo push_branch failed %s" % e)
            logs.append(str(e))

        return logs

    def install_acl(self, r, **kwargs):
        logs = []
        description = kwargs['description']
        acl_id = kwargs['acl']

        group_names = set([])
        acl_data = ""

        # Add default groups implicitly
        for default_group in DEFAULT_GROUPS:
            group_names.add(default_group)

        # If the string is not empty (default empty)
        if acl_id:
            # Fetch the ACL
            acl_data = self.new['resources']['acls'][acl_id]['file']
            acl_group_ids = set(
                self.new['resources']['acls'][acl_id]['groups'])

            # Fetch groups name
            for group_id in acl_group_ids:
                gname = self.new['resources']['groups'][group_id]['name']
                group_names.add(gname)
        else:
            acl_data = """[access]
        inheritFrom = All-Projects
[project]
        description = No description provided"""

        # Fill a groups file
        groups_file = """# UUID Group Name
global:Registered-Users\tRegistered Users"""
        for group in group_names:
            gid = self.client.get_group_id(group)
            groups_file += "\n%s\t%s" % (gid, group)

        # Overwrite the description if given in the ACL file
        if 'description =' in acl_data:
            acl_data = re.sub('description =.*',
                              'description = %s' % description,
                              acl_data)
        else:
            acl_data += """[project]
        description = %s
"""
            acl_data = acl_data % description

        # Clone the meta/config branch and push the ACL
        try:
            paths = {}
            paths['project.config'] = acl_data
            paths['groups'] = groups_file
            r.push_config(paths)
        except Exception, e:
            logger.exception("GerritRepo push_config failed %s" % e)
            logs.append(str(e))
        return logs

    def set_default_branch(self, name, branch):
        endpoint = "projects/%s/HEAD" % name
        headers = {'Content-Type': 'application/json'}
        data = json.dumps({"ref": "refs/heads/%s" % branch})
        try:
            self.client.g.put(endpoint, headers=headers, data=data)
        except HTTPError as e:
            return self.client._manage_errors(e)

    def create_branches(self, r, **kwargs):
        logs = []
        name = kwargs['name']
        branches = kwargs.get('branches')
        dbranch = kwargs.get('default-branch')

        try:
            refs = r.list_remote_branches()
        except Exception, e:
            logger.exception("GerritRepo create_branches failed %s" % e)
            logs.append("Get repo branches failed %s" % e)
            return logs

        to_create = dict(
            [(branch, sha) for branch, sha in branches.items() if
             branch not in refs.keys() and sha != '0'])
        to_delete = [branch for branch, sha in branches.items() if
                     branch in refs.keys() and sha == '0']

        # First create requested branches
        for branch, sha in to_create.items():
            try:
                r.create_remote_branch(branch, sha)
            except Exception, e:
                logger.exception("GerritRepo create_branch/create %s "
                                 "from sha %s failed %s" % (branch, sha, e))
                logs.append("Create branch %s from sha %s failed %s" % (
                    branch, sha, e))

        # Set default branch
        if refs['HEAD'] != dbranch:
            try:
                ret = self.set_default_branch(name, dbranch)
                if ret is False:
                    logs.append("Set default branch %s err API "
                                "returned HTTP 404/409" % dbranch)
            except Exception, e:
                logger.exception("GerritRepo create_branch/set_default %s "
                                 "failed %s" % (dbranch, e))
                logs.append("Set default branch %s err API returned %s" % (
                            dbranch, e))

        # Then delete requested branches
        for branch in to_delete:
            try:
                r.delete_remote_branch(branch)
            except Exception, e:
                logger.exception("GerritRepo create_branch/delete %s "
                                 "failed %s" % (branch, e))
                logs.append("Delete branch %s failed %s" % (branch + e))

        return logs


class GitRepository(BaseResource):

    MODEL_TYPE = 'git'
    DESCRIPTION = ("The git resource is used to describe a git repository "
                   "hosted on Gerrit. An acl ID can be provided via the acl "
                   "key.")
    MODEL = {
        'name': (
            str,
            '^([a-zA-Z0-9\-_\./])+$',
            False,
            "",
            False,
            "The repository name",
        ),
        'description': (
            str,
            '.*',
            False,
            "No description provided",
            True,
            "The repository description",
        ),
        'acl': (
            str,
            '.*',
            False,
            "",
            True,
            "The ACLs id",
        ),
        'default-branch': (
            str,
            '[a-zA-Z0-9\-_\./]+',
            False,
            "master",
            True,
            "The repository default branch",
        ),
        'branches': (
            dict,
            ('[a-zA-Z0-9\-_\./]+', '[a-f0-9]+'),
            False,
            {},
            True,
            "Repository branches. Branches name is the key and "
            "branch init SHA is the branch value. When branch already exist "
            "then no reset to the given SHA is done except for the 0 value "
            "that ensure the branch does not exist"
        ),
    }
    PRIORITY = 20
    PRIMARY_KEY = 'name'
    CALLBACKS = {
        'update': lambda conf, new, kwargs:
            GitRepositoryOps(conf, new).update(**kwargs),
        'create': lambda conf, new, kwargs:
            GitRepositoryOps(conf, new).create(**kwargs),
        'delete': lambda conf, new, kwargs:
            GitRepositoryOps(conf, new).delete(**kwargs),
        'extra_validations': lambda conf, new, kwargs: [],
        'get_all': lambda conf, new:
            GitRepositoryOps(conf, new).get_all(),
    }

    def get_deps(self, keyname=False):
        if keyname:
            return 'acl'
        if self.resource.get('acl'):
            return {'acls': set([self.resource['acl']])}
        else:
            return {'acls': set([])}
