#!/usr/bin/env python
#
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

import os.path

from managesf.api.v2 import base
from managesf.api.v2 import resources
from managesf.model.yamlbkd.engine import SFResourceBackendEngine


"""Resources service plugin using manageSF's built-in resource engine."""


def prepare_resources_data(raw_resources, type='project'):
    raw_projects = raw_resources['resources'].get('projects', {})
    raw_groups = raw_resources['resources'].get('groups', {})
    raw_acls = raw_resources['resources'].get('acls', {})
    raw_repositories = raw_resources['resources'].get('repos', {})
    if type == 'project':
        projects = {}
        for project in raw_projects:
            p = {}
            p['name'] = raw_projects[project].get('name')
            p['repository'] = \
                raw_projects[project].get('source-repositories')
            p['issue_tracker'] = raw_projects[project].get('issue-tracker')
            p['description'] = raw_projects[project].get('description')
            p['documentation'] = raw_projects[project].get('documentation')
            p['website'] = raw_projects[project].get('website')
            p['mailing_list'] = raw_projects[project].get('mailing-lists')
            p['contact'] = raw_projects[project].get('contact')
            p_acl = {}
            p_members = {}
            for repo in p['repository']:
                acl = raw_repositories[repo]['acl']
                p_acl[acl] = 0
                p_groups = raw_acls[acl]['groups']
                for p_group in p_groups:
                    for m in raw_groups[p_group]['members']:
                        p_members[m] = 0
            p['acl'] = p_acl.keys()
            p['member_id'] = p_members.keys()
            projects[project] = p
        return projects
    if type == 'acl':
        acls = {}
        for acl in raw_acls:
            a = {}
            a['id'] = acl
            a['file'] = raw_acls[acl].get('id')
            a['group'] = raw_acls[acl].get('groups')
            a_projects = {}
            a_repositories = {}
            a_members = {}
            for group in a['group']:
                for member in raw_groups[group]['members']:
                    a_members[member] = 0
            for rep in raw_repositories:
                if raw_repositories[rep].get('acl') == acl:
                    a_repositories[rep] = 0
                    prj = [q for q in raw_projects
                           if rep in raw_projects[q]['source-repositories']]
                    for p in prj:
                        a_projects[p] = 0
            a['member_id'] = a_members.keys()
            a['project'] = a_projects.keys()
            a['repository'] = a_repositories.keys()
            acls[acl] = a
        return acls


class ProjectManager(resources.ProjectManager):
    def __init__(self, manager):
        super(ProjectManager, self).__init__()
        self.manager = manager

    @base.paginate
    def get(self, **kwargs):
        results = []
        engine = self.manager.get_engine('read')
        raw_resources = engine.get(self.manager.master_repo, 'master')
        projects = prepare_resources_data(raw_resources, 'project')
        predicates = []
        # initialize predicates for empty query
        predicates.append(lambda x: True)
        # id and name
        if kwargs.get('id'):
            predicates.append(lambda x: x == kwargs['id'])
        if kwargs.get('name'):
            predicates.append(
                lambda x: projects[x].get('name', x) == kwargs['name'])
        # website, documentation & issue_tracker

        def _f(k):
            return lambda x: projects[x].get(k) == kwargs[k]

        for k in ['website', 'documentation', 'issue_tracker', ]:
            if kwargs.get(k):
                predicates.append(_f(k))
        # list-type properties: repository, mailing_list, contact, member_id

        def _l(k):
            return lambda x: kwargs[k] in projects[x].get(k)

        for k in ['repository', 'mailing_list', 'contact', 'member_id', ]:
            if kwargs.get(k):
                predicates.append(_l(k))
        for p in projects:
            if all(f(p) for f in predicates):
                _p = projects[p]
                # repositories should always be found
                repos = [self.manager.repositories.get(name=r)['results'][0]
                         for r in _p.get('repository')]
                pj = resources.Project(id=p, name=_p.get('name'),
                                       description=_p.get('description'),
                                       website=_p.get('website'),
                                       documentation=_p.get('documentation'),
                                       issue_tracker=_p.get('issue_tracker'),
                                       mailing_lists=_p.get('mailing_list'),
                                       contacts=_p.get('contact'),
                                       repositories=repos)
                results.append(pj)
        return results


class ACLManager(resources.ACLManager):
    def __init__(self, manager):
        super(ACLManager, self).__init__()
        self.manager = manager

    @base.paginate
    def get(self, **kwargs):
        results = []
        engine = self.manager.get_engine('read')
        raw_resources = engine.get(self.manager.master_repo, 'master')
        acls = prepare_resources_data(raw_resources, 'acl')
        predicates = []
        # initialize predicates for empty query
        predicates.append(lambda x: True)
        # id
        if kwargs.get('id'):
            predicates.append(lambda x: x == kwargs['id'])
        # list-type properties: repository, project, group, member_id

        def _l(k):
            return lambda x: kwargs[k] in acls[x].get(k)

        for k in ['repository', 'project', 'group', 'member_id', ]:
            if kwargs.get(k):
                predicates.append(_l(k))
        for a in acls:
            if all(f(a) for f in predicates):
                _a = acls[a]
                # groups should always be found
                groups = [self.manager.groups.get(id=g)['results'][0]
                          for g in _a.get('group')]
                aa = resources.ACL(id=a, file=_a.get('file'), groups=groups)
                results.append(aa)
        return results


class GroupManager(resources.GroupManager):
    def __init__(self, manager):
        super(GroupManager, self).__init__()
        self.manager = manager

    @base.paginate
    def get(self, **kwargs):
        return [resources.Group('toto-grp'), ]


class RepositoryManager(resources.RepositoryManager):
    def __init__(self, manager):
        super(RepositoryManager, self).__init__()
        self.manager = manager

    @base.paginate
    def get(self, **kwargs):
        return [resources.Repository('toto'), ]


class ResourcesManager(resources.ResourcesManager):
    def __init__(self, manager):
        super(ResourcesManager, self).__init__()
        self.manager = manager

    def get(self, **kwargs):
        engine = self.manager.get_engine('read')
        if kwargs.get('get_missing_resources'):
            return engine.get_missing_resources(self.manager.master_repo,
                                                'master')
        else:
            return engine.get(self.manager.master_repo, 'master')

    def update(self, **kwargs):
        engine = self.manager.get_engine('apply')
        if kwargs.get('COMMIT') or\
           all(kwargs.get(c) is None for c in ['COMMIT', 'prev', 'new']):
            commit = kwargs.get('COMMIT', 'master')
            status, logs = engine.apply(self.manager.master_repo,
                                        '%s^1' % commit,
                                        self.manager.master_repo,
                                        commit)
        elif (kwargs.get('COMMIT') is None and
              kwargs.get('prev') is not None and
              kwargs.get('new') is not None):
            status, logs = engine.direct_apply(kwargs['prev'], kwargs['new'])
        else:
            raise ValueError(
                'Invalid arguments: either provide a "COMMIT" or the '
                '"new" and "prev" arguments')
        return status, logs

    def create(self, **kwargs):
        if kwargs.get('zuul_url') is None:
            raise ValueError('Invalid request: missing "zuul_url"')
        zuul_url = kwargs['zuul_url']
        if kwargs.get('zuul_ref') is None:
            raise ValueError('Invalid request: missing "zuul_ref"')
        zuul_ref = kwargs['zuul_ref']
        engine = self.manager.get_engine('validate')
        status, logs = engine.validate(self.manager.master_repo,
                                       'master', zuul_url, zuul_ref)
        return status, logs


class SFResourcesManager(resources.ResourcesServiceManager):

    _config_section = "resources"
    service_name = "manageSF"

    def __init__(self, conf):
        super(SFResourcesManager, self).__init__(conf)
        self.subdir = self.conf['subdir']
        self.workdir = self.conf['workdir']
        self.master_repo = self.conf['master_repo']
        self.projects = ProjectManager(self)
        self.acls = ACLManager(self)
        self.groups = GroupManager(self)
        self.repositories = RepositoryManager(self)
        self.resources = ResourcesManager(self)

    def get_engine(self, operation):
        """Returns a resource engine for the right operation.
        Valid operations: read, validate, apply"""
        if operation not in ['read', 'validate', 'apply']:
            raise ValueError('Unknown operation "%s"' % operation)
        engine = SFResourceBackendEngine(
            os.path.join(self.workdir, operation),
            self.subdir)
        return engine
