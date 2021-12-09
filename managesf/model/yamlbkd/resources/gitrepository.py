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
try:
    from urllib import quote_plus
except ImportError:
    from urllib.parse import quote_plus
import hashlib
import logging

from git.config import GitConfigParser

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
DEFAULT_GROUPS = ('Service Users',
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

    def extra_validations(self, **kwargs):
        repo_name = kwargs['name']
        acl_id = kwargs['acl']

        logs = []
        set_private = False

        acls = self.new['resources']['acls'][acl_id]['file']
        # Detect if the ACL make that repository private
        if ('read = deny group Registered Users' in acls and
                'read = deny group Anonymous Users' in acls):
            # Find repos marked as private in projects
            # and remove them from the private_repos accu
            projects = self.new['resources']['projects'].values()
            for project in projects:
                for sr in project['source-repositories']:
                    if isinstance(sr, dict):
                        sr_name = list(sr.keys())[0]
                        sr_attrs = sr[sr_name]
                        if (sr_name == repo_name and
                                sr_attrs.get('private') is True):
                            set_private = True
            if not set_private:
                logs.append(
                    "%s repository use a private Gerrit ACL but are not"
                    " defined as private in a project" % repo_name)

        return logs

    def get_all(self):
        logs = []
        gitrepos = {}
        acls = {}

        self._set_client()

        try:
            repos = self.client.get_projects()
        except Exception as e:
            logger.exception("get_projects failed")
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

            _acl = open(acl_path).read()
            acl = ""
            # Clean the ACL file to avoid issue at YAML multiline
            # serialization. Remove the description and as a good
            # practice description should never appears in a ACL rtype
            # TODO(fbo): extra_validation of acl must deny the description
            for line in _acl.splitlines():
                if remove_project_section and line.find('[project]') != -1:
                    continue
                if line.find('description') != -1:
                    continue
                acl += line.replace('\t', '    ').rstrip() + '\n'
            m = hashlib.md5()
            m.update(acl.encode())
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
            self.client.create_project(name, description, ['Administrators'])
        except Exception as e:
            logger.exception("create_project failed")
            logs.append("Repo create: err API returned %s" % e)

        try:
            r = utils.GerritRepo(name, self.conf)
            r.clone()
        except Exception as e:
            logger.exception("GerritRepo create repo checkout failed")
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
            self.client.delete_project(name, True)
        except Exception as e:
            logger.exception("delete_project failed")
            logs.append("Repo delete: err API returned %s" % e)

        return logs

    def update(self, **kwargs):
        logs = []

        self._set_client()

        try:
            r = utils.GerritRepo(kwargs['name'], self.conf)
            r.clone()
        except Exception as e:
            logger.exception("GerritRepo update repo checkout failed")
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
        except Exception as e:
            logger.exception("GerritRepo push_branch failed")
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
        except Exception as e:
            logger.exception("GerritRepo push_config failed")
            logs.append(str(e))
        return logs

    def set_default_branch(self, name, branch):
        endpoint = "projects/%s/HEAD" % quote_plus(name)
        data = {"ref": "refs/heads/%s" % branch}
        return self.client.put(endpoint, data)

    def create_branches(self, r, **kwargs):
        logs = []
        name = kwargs['name']
        branches = kwargs.get('branches')
        dbranch = kwargs.get('default-branch')

        try:
            refs = r.list_remote_branches()
        except Exception as e:
            logger.exception("GerritRepo create_branches failed")
            logs.append("Get repo branches failed %s" % e)
            return logs

        to_create = dict(
            [(branch, sha) for branch, sha in branches.items() if
             branch not in refs.keys() and sha != '0'])
        to_delete = [branch for branch, sha in branches.items() if
                     branch in refs.keys() and sha == '0']

        if (refs['HEAD'] != dbranch and
                dbranch not in refs.keys() and
                dbranch not in to_create.keys() and
                dbranch != ""):
            # Then a default-branch is requested but not defined in
            # branches list. It may be coherent with the situation of first
            # creating a repo with a specific default-branch
            to_create[dbranch] = 'HEAD'

        # First create requested branches
        for branch, sha in to_create.items():
            try:
                r.create_remote_branch(branch, sha)
                logs.extend(self.install_git_review_file(
                    r, name, branch))
            except Exception as e:
                logger.exception("GerritRepo create_branch/create %s "
                                 "from sha %s failed" % (branch, sha))
                logs.append("Create branch %s from sha %s failed %s" % (
                    branch, sha, e))

        # Set default branch
        if refs['HEAD'] != dbranch and dbranch != "":
            try:
                self.set_default_branch(name, dbranch)
            except Exception as e:
                logger.exception("set_default_branch failed")
                logs.append("Set default branch %s err API returned %s" % (
                            dbranch, e))

        # Then delete requested branches
        for branch in to_delete:
            try:
                r.delete_remote_branch(branch)
            except Exception as e:
                logger.exception("GerritRepo create_branch/delete %s "
                                 "failed" % branch)
                logs.append("Delete branch %s failed %s" % (branch, e))

        return logs


class GitRepository(BaseResource):

    MODEL_TYPE = 'git'
    DESCRIPTION = ("The git resource is used to describe a git repository "
                   "hosted on Gerrit. An acl ID can be provided via the acl "
                   "key.")
    MODEL = {
        'name': (
            str,
            r'^([a-zA-Z0-9\-_\./])+$',
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
            r'[a-zA-Z0-9\-_\./]*',
            False,
            "",
            True,
            "The repository default branch. If the branch does not exist yet "
            "or have not been defined in the 'branches' attribute then "
            "default-branch is first created from origin/HEAD",
        ),
        'branches': (
            dict,
            (r'[a-zA-Z0-9\-_\./]+', r'[a-zA-Z0-9\-_\./]+'),
            False,
            {},
            True,
            "Repository branches. Branches name is the key and "
            "branch is the branch value (a SHA/or an existing branch "
            "name/or HEAD). When branch already exist then no reset to "
            "the given value is done except for the '0' value that "
            "ensure the branch does not exist by removing the ref. "
            "If you intend to explicitly declare already existing branches "
            "then please use HEAD as value.",
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
        'extra_validations': lambda conf, new, kwargs:
            GitRepositoryOps(conf, new).extra_validations(**kwargs),
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
