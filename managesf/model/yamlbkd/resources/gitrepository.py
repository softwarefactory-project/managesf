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

from managesf.services.gerrit import SoftwareFactoryGerrit
from managesf.model.yamlbkd.resource import BaseResource
from managesf.services.gerrit import utils
from managesf.controllers.utils import template

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
# conf = configuration.conf_from_file('/var/www/managesf/config.py')
# g = GitRepositoryOps(conf, {})
# g._set_client()
# ###


class GitRepositoryOps(object):

    def __init__(self, conf, new):
        self.conf = conf
        self.new = new
        self.client = None

    def _set_client(self):
        if not self.client:
            gerrit = SoftwareFactoryGerrit(self.conf)
            self.client = gerrit.get_client()

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
            logs.append("Repo create: err API returned %s" % e)

        logs.extend(self.install_acl(**kwargs))
        logs.extend(self.install_git_review_file(**kwargs))

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
            logs.append("Repo delete: err API returned %s" % e)

        return logs

    def update(self, **kwargs):
        logs = []

        logs.extend(self.install_acl(**kwargs))
        logs.extend(self.install_git_review_file(**kwargs))

        return logs

    def install_git_review_file(self, **kwargs):
        logs = []

        name = kwargs['name']

        paths = {}
        content = file(template('gitreview')).read() % (
            {'gerrit-host': self.conf.gerrit['top_domain'],
             'gerrit-host-port': self.conf.gerrit['ssh_port'],
             'name': name})
        paths['.gitreview'] = content

        # Clone the master branch and push the .gitreview file
        try:
            r = utils.GerritRepo(name, self.conf)
            r.clone()
            r.push_master(paths)
        except Exception, e:
            logs.append(str(e))

        return logs

    def install_acl(self, **kwargs):
        logs = []
        name = kwargs['name']
        description = kwargs['description']
        acl_id = kwargs['acl']

        self._set_client()

        group_names = set([])
        acl_data = ""

        # Add default groups implicitly
        for default_group in ('Non-Interactive Users',
                              'Administrators',
                              'Anonymous Users'):
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
            r = utils.GerritRepo(name, self.conf)
            r.clone()
            paths = {}
            paths['project.config'] = acl_data
            paths['groups'] = groups_file
            r.push_config(paths)
        except Exception, e:
            logs.append(str(e))
        return logs


class GitRepository(BaseResource):

    MODEL_TYPE = 'git'
    MODEL = {
        'name': (
            str,
            '^([a-zA-Z0-9\-_\./])+$',
            True,
            None,
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
    }

    def get_deps(self):
        if self.resource.get('acl'):
            return {'acls': set([self.resource['acl']])}
        else:
            return {'acls': set([])}
