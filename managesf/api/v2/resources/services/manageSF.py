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

import sqlalchemy as sqla
from sqlalchemy.sql import select
from sqlalchemy.sql.expression import alias

from managesf.api.v2 import base
from managesf.api.v2 import resources
from managesf.model.yamlbkd.engine import SFResourceBackendEngine


"""Resources service plugin using manageSF's built-in resource engine."""


def prepare_resources_data(raw_resources):
    # TODO this should be cached and updated only when changes occur on config
    """Creates a flat in-memory table to simplify querying."""
    raw_projects = raw_resources['resources'].get('projects', {})
    raw_groups = raw_resources['resources'].get('groups', {})
    raw_acls = raw_resources['resources'].get('acls', {})
    raw_repositories = raw_resources['resources'].get('repos', {})

    engine = sqla.create_engine('sqlite://')
    metadata = sqla.MetaData()
    tables = {}
    project_table = sqla.Table(
        'project', metadata,
        sqla.Column('id', sqla.TEXT(), primary_key=True),
        sqla.Column('name', sqla.TEXT()),
        sqla.Column('website', sqla.TEXT()),
        sqla.Column('documentation', sqla.TEXT()),
        sqla.Column('issue_tracker', sqla.TEXT()),
    )
    tables['project'] = project_table
    mailing_list_table = sqla.Table(
        'mailing_list', metadata,
        sqla.Column('project_id', sqla.TEXT(),
                    sqla.ForeignKey('project.id')),
        sqla.Column('mailing_list', sqla.TEXT()),
    )
    tables['mailing_list'] = mailing_list_table
    contact_table = sqla.Table(
        'contact', metadata,
        sqla.Column('project_id', sqla.TEXT(),
                    sqla.ForeignKey('project.id')),
        sqla.Column('contact', sqla.TEXT()),
    )
    tables['contact'] = contact_table
    acl_table = sqla.Table(
        'acl', metadata,
        sqla.Column('id', sqla.TEXT(), primary_key=True),
        sqla.Column('name', sqla.TEXT()),
    )
    tables['acl'] = acl_table
    repository_table = sqla.Table(
        'repository', metadata,
        sqla.Column('id', sqla.TEXT(), primary_key=True),
        sqla.Column('name', sqla.TEXT()),
        sqla.Column('acl', sqla.TEXT(),
                    sqla.ForeignKey('acl.id')),
    )
    tables['repository'] = repository_table
    project_repo_table = sqla.Table(
        'project_repo', metadata,
        sqla.Column('project_id', sqla.TEXT(),
                    sqla.ForeignKey('project.id')),
        sqla.Column('repo_id', sqla.TEXT(),
                    sqla.ForeignKey('repository.id')),
    )
    tables['project_repo'] = project_repo_table
    group_table = sqla.Table(
        'group', metadata,
        sqla.Column('id', sqla.TEXT(), primary_key=True),
        sqla.Column('name', sqla.TEXT()),
    )
    tables['group'] = group_table
    member_table = sqla.Table(
        'member', metadata,
        sqla.Column('group_id', sqla.TEXT(),
                    sqla.ForeignKey('group.id')),
        sqla.Column('member_email', sqla.TEXT()),
    )
    tables['member'] = member_table
    acl_group_table = sqla.Table(
        'acl_group', metadata,
        sqla.Column('acl_id', sqla.TEXT(),
                    sqla.ForeignKey('acl.id')),
        sqla.Column('group_id', sqla.TEXT(),
                    sqla.ForeignKey('group.id')),
    )
    tables['acl_group'] = acl_group_table

    metadata.create_all(engine)

    ins_project = []
    ins_ml = []
    ins_contact = []
    ins_project_repo = []
    for p in raw_projects:
        project = {}
        _p = raw_projects[p]
        project['id'] = p
        project['name'] = _p.get('name') or p
        project['website'] = _p.get('website')
        project['documentation'] = _p.get('documentation')
        project['issue_tracker'] = _p.get('issue-tracker')
        ins_project.append(project)
        for ml in _p.get('mailing-lists') or []:
            ins_ml.append({'project_id': p, 'mailing_list': ml})
        for c in _p.get('contacts') or []:
            ins_contact.append({'project_id': p, 'contact': c})
        for r in _p.get('source-repositories') or []:
            ins_project_repo.append({'project_id': p, 'repo_id': r})
    ins_group = []
    ins_member = []
    for g in raw_groups:
        group = {}
        _g = raw_groups[g]
        group['id'] = g
        group['name'] = _g.get('name') or g
        ins_group.append(group)
        for m in _g.get('members') or []:
            ins_member.append({'group_id': g, 'member_email': m})
    ins_acl = []
    ins_acl_group = []
    for a in raw_acls:
        acl = {}
        _a = raw_acls[a]
        acl['id'] = a
        acl['name'] = _a.get('name') or a
        ins_acl.append(acl)
        for g in _a.get('groups') or []:
            ins_acl_group.append({'acl_id': a, 'group_id': g})
    ins_repo = []
    for r in raw_repositories:
        repo = {}
        _r = raw_repositories[r]
        repo['id'] = r
        repo['name'] = _r.get('name') or r
        repo['acl'] = _r.get('acl')
        ins_repo.append(repo)
    with engine.begin() as conn:
        # Insert in order with respect to primary keys
        conn.execute(project_table.insert(), ins_project)
        conn.execute(mailing_list_table.insert(), ins_ml)
        conn.execute(contact_table.insert(), ins_contact)
        conn.execute(group_table.insert(), ins_group)
        conn.execute(member_table.insert(), ins_member)
        conn.execute(acl_table.insert(), ins_acl)
        conn.execute(acl_group_table.insert(), ins_acl_group)
        conn.execute(repository_table.insert(), ins_repo)
        conn.execute(project_repo_table.insert(), ins_project_repo)
    return engine, tables


class ProjectManager(resources.ProjectManager):
    def __init__(self, manager):
        super(ProjectManager, self).__init__()
        self.manager = manager

    @base.paginate
    def get(self, **kwargs):
        results = []
        engine = self.manager.get_engine('read')
        raw_resources = engine.get(self.manager.master_repo, 'master')
        engine, tables = prepare_resources_data(raw_resources)
        bigtable = tables['project']\
            .outerjoin(tables['mailing_list'])\
            .outerjoin(tables['contact'])\
            .outerjoin(tables['project_repo'])\
            .outerjoin(tables['repository'])\
            .outerjoin(tables['acl'])\
            .outerjoin(tables['acl_group'])\
            .outerjoin(tables['group'])\
            .outerjoin(tables['member'])
        query = sqla.select([tables['project'].c.id]).select_from(bigtable)
#        with engine.begin() as conn:
#            import csv
#            fh = open('/tmp/bigtable.csv', 'wb')
#            out = csv.writer(fh)
#            x = conn.execute(sqla.select(['*']).select_from(bigtable))
#            out.writerow(x.keys())
#            out.writerows(x)
#            fh.close()
        # id, website, documentation, issue_tracker and name
        for param in ['id', 'name', 'website',
                      'documentation', 'issue_tracker']:
            if param in kwargs:
                query = query.where(
                    getattr(tables['project'].c, param) == kwargs.get(param))
        # joined properties: repository, mailing_list, contact, member_email
        if 'repository' in kwargs:
            query = query.where(
                tables['repository'].c.name == kwargs['repository'])
        if 'mailing_list' in kwargs:
            query = query.where(
                tables['mailing_list'].c.mailing_list ==
                kwargs['mailing_list'])
        if 'contact' in kwargs:
            query = query.where(
                tables['contact'].c.contact == kwargs['contact'])
        if 'member_email' in kwargs:
            query = query.where(
                tables['member'].c.member_email == kwargs['member_email'])
        if 'order_by' in kwargs:
            if kwargs.get('desc'):
                query = query.order_by(
                    sqla.desc(getattr(tables['project'].c,
                                      kwargs['order_by'])))
            else:
                query = query.order_by(
                    getattr(tables['project'].c, kwargs['order_by']))
        query = query.group_by(tables['project'].c.id)
        # count total results
        query_alias = alias(query, 'count_alias')
        count = select(
            [sqla.func.count('id')]).select_from(query_alias)
        query = query.limit(kwargs['limit']).offset(kwargs['skip'])
        self._logger.debug(str(query.compile(
            compile_kwargs={"literal_binds": True})))
        with engine.begin() as conn:
            total = conn.execute(count).fetchall()
            if total:
                self._logger.info(total)
                total = total[0][0]
            else:
                total = 0
            for p in conn.execute(query):
                _p = raw_resources['resources']['projects'][p[0]]
                # repositories should always be found
                repos = [self.manager.repositories.get(name=r)['results'][0]
                         for r in _p.get('source-repositories')]
                pj = resources.Project(id=p[0], name=_p.get('name') or p[0],
                                       description=_p.get('description'),
                                       website=_p.get('website'),
                                       documentation=_p.get('documentation'),
                                       issue_tracker=_p.get('issue-tracker'),
                                       mailing_lists=_p.get('mailing-lists'),
                                       contacts=_p.get('contacts'),
                                       repositories=repos)
                results.append(pj)
        self._logger.info(total)
        return results, total


class ACLManager(resources.ACLManager):
    def __init__(self, manager):
        super(ACLManager, self).__init__()
        self.manager = manager

    @base.paginate
    def get(self, **kwargs):
        results = []
        engine = self.manager.get_engine('read')
        raw_resources = engine.get(self.manager.master_repo, 'master')
        engine, tables = prepare_resources_data(raw_resources)
        bigtable = tables['acl']\
            .outerjoin(tables['acl_group'])\
            .outerjoin(tables['group'])\
            .outerjoin(tables['member'])\
            .outerjoin(tables['repository'])\
            .outerjoin(tables['project_repo'])\
            .outerjoin(tables['project'])
        query = sqla.select([tables['acl'].c.id]).select_from(bigtable)
        # id
        for param in ['id']:
            if param in kwargs:
                query = query.where(
                    getattr(tables['acl'].c, param) == kwargs.get(param))
        # joined properties: repository, group, project, member_email
        if 'repository' in kwargs:
            query = query.where(
                tables['repository'].c.name == kwargs['repository'])
        if 'group' in kwargs:
            query = query.where(
                tables['group'].c.name == kwargs['group'])
        if 'project' in kwargs:
            query = query.where(
                tables['project'].c.name == kwargs['project'])
        if 'member_email' in kwargs:
            query = query.where(
                tables['member'].c.member_email == kwargs['member_email'])
        if 'order_by' in kwargs:
            if kwargs.get('desc'):
                query = query.order_by(
                    sqla.desc(getattr(tables['acl'].c,
                                      kwargs['order_by'])))
            else:
                query = query.order_by(
                    getattr(tables['acl'].c, kwargs['order_by']))
        query = query.group_by(tables['acl'].c.id)
        # count total results
        query_alias = alias(query, 'count_alias')
        count = select([sqla.func.count('*')]).select_from(query_alias)
        query = query.limit(kwargs['limit']).offset(kwargs['skip'])
        self._logger.debug(str(query.compile(
            compile_kwargs={"literal_binds": True})))
        with engine.begin() as conn:
            total = conn.execute(count).fetchall()
            if total:
                total = total[0][0]
            else:
                total = 0
            for a in conn.execute(query):
                _a = raw_resources['resources']['acls'][a[0]]
                # groups should always be found
                groups = [self.manager.groups.get(id=g)['results'][0]
                          for g in _a.get('groups')]
                aa = resources.ACL(id=a[0], file=_a.get('file'), groups=groups)
                results.append(aa)
        return results, total


class GroupManager(resources.GroupManager):
    def __init__(self, manager):
        super(GroupManager, self).__init__()
        self.manager = manager

    @base.paginate
    def get(self, **kwargs):
        results = []
        engine = self.manager.get_engine('read')
        raw_resources = engine.get(self.manager.master_repo, 'master')
        engine, tables = prepare_resources_data(raw_resources)
        bigtable = tables['group']\
            .outerjoin(tables['member'])\
            .outerjoin(tables['acl_group'])\
            .outerjoin(tables['acl'])\
            .outerjoin(tables['repository'])\
            .outerjoin(tables['project_repo'])\
            .outerjoin(tables['project'])
        query = sqla.select([tables['group'].c.id]).select_from(bigtable)
        # id
        for param in ['id', 'name']:
            if param in kwargs:
                query = query.where(
                    getattr(tables['group'].c, param) == kwargs.get(param))
        # joined properties: repository, acl, project, member_email
        if 'repository' in kwargs:
            query = query.where(
                tables['repository'].c.name == kwargs['repository'])
        if 'acl' in kwargs:
            query = query.where(
                tables['acl'].c.name == kwargs['acl'])
        if 'project' in kwargs:
            query = query.where(
                tables['project'].c.name == kwargs['project'])
        if 'member_email' in kwargs:
            query = query.where(
                tables['member'].c.member_email == kwargs['member_email'])
        if 'order_by' in kwargs:
            if kwargs.get('desc'):
                query = query.order_by(
                    sqla.desc(getattr(tables['acl'].c,
                                      kwargs['order_by'])))
            else:
                query = query.order_by(
                    getattr(tables['acl'].c, kwargs['order_by']))
        query = query.group_by(tables['group'].c.id)
        # count total results
        query_alias = alias(query, 'count_alias')
        count = select([sqla.func.count('*')]).select_from(query_alias)
        query = query.limit(kwargs['limit']).offset(kwargs['skip'])
        self._logger.debug(str(query.compile(
            compile_kwargs={"literal_binds": True})))
        with engine.begin() as conn:
            total = conn.execute(count).fetchall()
            if total:
                total = total[0][0]
            else:
                total = 0
            for g in conn.execute(query):
                _g = raw_resources['resources']['groups'][g[0]]
                gg = resources.Group(id=g[0], name=_g.get('name') or g[0],
                                     description=_g.get('description'),
                                     members=_g.get('members'))
                results.append(gg)
        return results, total


class RepositoryManager(resources.RepositoryManager):
    def __init__(self, manager):
        super(RepositoryManager, self).__init__()
        self.manager = manager

    @base.paginate
    def get(self, **kwargs):
        results = []
        engine = self.manager.get_engine('read')
        raw_resources = engine.get(self.manager.master_repo, 'master')
        engine, tables = prepare_resources_data(raw_resources)
        bigtable = tables['repository']\
            .outerjoin(tables['project_repo'])\
            .outerjoin(tables['project'])\
            .outerjoin(tables['acl'])\
            .outerjoin(tables['acl_group'])\
            .outerjoin(tables['group'])\
            .outerjoin(tables['member'])
        query = sqla.select([tables['repository'].c.id]).select_from(bigtable)
        # id
        for param in ['id', 'name']:
            if param in kwargs:
                query = query.where(
                    getattr(tables['repository'].c, param) ==
                    kwargs.get(param))
        # joined properties: acl, project, member_email
        if 'acl' in kwargs:
            query = query.where(
                tables['acl'].c.name == kwargs['acl'])
        if 'project' in kwargs:
            query = query.where(
                tables['project'].c.name == kwargs['project'])
        if 'member_email' in kwargs:
            query = query.where(
                tables['member'].c.member_email == kwargs['member_email'])
        if 'order_by' in kwargs:
            if kwargs.get('desc'):
                query = query.order_by(
                    sqla.desc(getattr(tables['acl'].c,
                                      kwargs['order_by'])))
            else:
                query = query.order_by(
                    getattr(tables['acl'].c, kwargs['order_by']))
        query = query.group_by(tables['repository'].c.id)
        # count total results
        query_alias = alias(query, 'count_alias')
        count = select([sqla.func.count('*')]).select_from(query_alias)
        query = query.limit(kwargs['limit']).offset(kwargs['skip'])
        self._logger.debug(str(query.compile(
            compile_kwargs={"literal_binds": True})))
        with engine.begin() as conn:
            total = conn.execute(count).fetchall()
            if total:
                total = total[0][0]
            else:
                total = 0
            for r in conn.execute(query):
                _r = raw_resources['resources']['repos'][r[0]]
                ACL = None
                if _r.get('acl'):
                    ACL = self.manager.acls.get(id=_r.get('acl'))['results'][0]
                rr = resources.Repository(id=r[0], name=_r.get('name') or r[0],
                                          description=_r.get('description'),
                                          ACL=ACL)
                results.append(rr)
        return results, total


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
