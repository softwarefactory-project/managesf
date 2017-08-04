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

import os
import git
import logging
import yaml

import sqlalchemy as sqla
from pecan import conf  # noqa

logger = logging.getLogger(__name__)

RESOURCES_STRUCT = {'resources': {'rtype': {'key': {}}}}


class YAMLDBException(Exception):
    pass


class YAMLBackend(object):
    def __init__(self, git_repo_url, git_ref, sub_dir,
                 clone_path, cache_path):
        """ Class to read and validate resources from YAML
        files from stored in a GIT repository. The main data
        structure as well as resources structure must follow
        specific constraints.

        This Class also maintains a cache file to avoid full
        re-load and validation at init when ref hash has not
        changed.

        :param git_repo_url: The URI of the GIT repository
        :param git_ref: The GIT repository refs such as
               refs/zuul/master/Z3a46b05b4574472bbf093ff5562cba42
               or refs/heads/master
        :param sub_dir: The path from the GIT root to YAML files
        :param clone_path: The path where to clone the GIT repository
        :param cache_path: The path to the cached file
        """
        self._initialize(git_repo_url, git_ref, sub_dir,
                         clone_path, cache_path)
        self.refresh()

    def _initialize(self, git_repo_url, git_ref, sub_dir,
                    clone_path, cache_path):
        self.git_repo_url = git_repo_url
        self.git_ref = git_ref
        self.clone_path = clone_path
        self.cache_path = cache_path
        self.cache_path_hash = "%s_%s" % (cache_path, '_hash')
        self.db_path = os.path.join(self.clone_path, sub_dir)
        self.rids = {}

    def _get_repo_hash(self):
        repo = git.Git(self.clone_path)
        repo_hash = repo.execute(['git', '--no-pager', 'log', '-1',
                                  '--pretty=%h', 'HEAD'])
        return repo_hash

    def _get_cache_hash(self):
        return file(self.cache_path_hash).read().strip()

    def _update_cache(self):
        repo_hash = self._get_repo_hash()
        self.hash = repo_hash
        yaml.dump(self.data, file(self.cache_path, 'w'))
        file(self.cache_path_hash, 'w').write(repo_hash)
        logger.info("Cache file has been updated.")

    def _load_from_cache(self):
        if not os.path.isfile(self.cache_path_hash):
            logger.info("No DB cache file found.")
        else:
            repo_hash = self._get_repo_hash()
            cached_repo_hash = self._get_cache_hash()
            if cached_repo_hash == repo_hash:
                self.data = yaml.safe_load(file(self.cache_path))
                self.hash = repo_hash
                logger.info("Load data from the cache.")
            else:
                logger.info("DB cache is outdated.")

    def _update_git_clone(self):
        repo = git.Git(self.clone_path)
        repo.init()
        try:
            repo.execute(['git', 'remote', 'add',
                          'origin', self.git_repo_url])
        except Exception:
            logger.info("Re-using the previous repo path %s" % self.clone_path)
            repo.execute(['git', 'remote', 'remove', 'origin'])
            repo.execute(['git', 'remote', 'add',
                          'origin', self.git_repo_url])
            logger.info("Update the previous remote origin to %s." % (
                        self.git_repo_url))
        if self.git_ref != 'master' and not self.git_ref.startswith('refs/'):
            if self.git_ref == "master^1":
                # Keep that for compatibility SF < 2.4.0
                ref = 'FETCH_HEAD^1'
            else:
                # Here git_ref is a commit SHA or SHA^1
                ref = self.git_ref
            repo.execute(['git', 'fetch', 'origin', 'master'])
            repo.execute(['git', 'checkout', ref])
        else:
            repo.execute(['git', 'fetch', '-f', 'origin',
                          '%s:refs/remotes/origin/myref' % self.git_ref])
            repo.execute(['git', 'checkout', 'origin/myref'])
        logger.info("Updated GIT repo %s at ref %s." % (self.git_repo_url,
                                                        self.git_ref))

    def _load_db(self):
        def check_ext(f):
            return f.endswith('.yaml') or f.endswith('.yml')
        logger.info("Load data from the YAML files.")
        self.rids = {}
        yamlfiles = [f for f in os.listdir(self.db_path) if check_ext(f)]
        for f in yamlfiles:
            logger.info("Reading %s ..." % f)
            try:
                yaml_data = yaml.safe_load(
                    file(os.path.join(self.db_path, f)))
            except:
                raise YAMLDBException(
                    "YAML format corrupted in file %s" % (
                        os.path.join(self.db_path, f)))
            if not self.data:
                self.data = self.validate(yaml_data, self.rids)
            else:
                data_to_append = self.validate(yaml_data, self.rids)
                for rtype, resources in data_to_append['resources'].items():
                    if rtype not in self.data['resources']:
                        self.data['resources'][rtype] = {}
                    self.data['resources'][rtype].update(resources)

    @staticmethod
    def _validate_base_struct(data):
        try:
            assert isinstance(data, type(RESOURCES_STRUCT))
            assert isinstance(data['resources'],
                              type(RESOURCES_STRUCT['resources']))
        except (AssertionError, KeyError):
            raise YAMLDBException(
                "The main resource data structure is invalid")
        try:
            for rtype, resources in data['resources'].items():
                assert isinstance(
                    rtype, type(RESOURCES_STRUCT['resources'].keys()[0]))
                assert isinstance(
                    resources, type(RESOURCES_STRUCT['resources']['rtype']))
        except AssertionError:
            raise YAMLDBException(
                "Resource type %s structure is invalid" % rtype)
        try:
            for rtype, resources in data['resources'].items():
                for rid, resource in resources.items():
                    assert isinstance(rid, str)
                    assert isinstance(
                        resource,
                        type(RESOURCES_STRUCT['resources']['rtype']['key']))
        except AssertionError:
            raise YAMLDBException(
                "Resource %s of type %s is invalid" % (resource, rtype))

    @staticmethod
    def _validate_rid_unicity(data, rids):
        # Verify at YAML load time that duplicated resources key
        # are not present. To avoid overlapping of resources.
        # https://gist.github.com/pypt/94d747fe5180851196eb implements a
        # solution but seems difficult as it does not support the
        # safe_loader and usage of that loader is important to avoid
        # loading malicious yaml serialized objects.
        # Inside a single yaml file a reviewer should take care to
        # the duplicated keys issue and also look at the logs for
        # checking not expected detected changes.
        #
        # Nevertheless between two or more yaml files this check can be
        # implemented.
        for rtype, resources in data['resources'].items():
            for rid, resource in resources.items():
                rids.setdefault(rtype, {})
                if rid not in rids[rtype]:
                    rids[rtype][rid] = None
                else:
                    raise YAMLDBException(
                        "Duplicated resource ID detected for "
                        "resource type: %s id: %s" % (rtype, rid))

    def refresh(self):
        """ Reload of the YAML files.
        """
        self.data = None
        self._update_git_clone()
        self._load_from_cache()
        # Load from files. Cache is not up to date.
        if not self.data:
            self._load_db()
            self._update_cache()

    @staticmethod
    def validate(data, rids):
        """ Validate the resource data structure.
        """
        YAMLBackend._validate_base_struct(data)
        YAMLBackend._validate_rid_unicity(data, rids)
        return data

    def get_data(self):
        """ Return the full data structure.
        """
        data = self.data
        data['hash'] = self.hash
        return data


class YAMLtoSQLBackend(YAMLBackend):
    """This class is used to convert the resource tree into an SQLite
    database that can be easier to query."""
    def _initialize(self, git_repo_url, git_ref, sub_dir,
                    clone_path, cache_path):
        super(YAMLtoSQLBackend, self)._initialize(git_repo_url, git_ref,
                                                  sub_dir, clone_path,
                                                  cache_path)
        self.sqlite_cache_path = cache_path + '.sqlite3'
        self.engine = None
        self.metadata = sqla.MetaData()
        self._tables = {}

    def _load_from_cache(self):
        if not os.path.isfile(self.cache_path_hash):
            logger.info("No DB cache file found.")
        else:
            repo_hash = self._get_repo_hash()
            cached_repo_hash = self._get_cache_hash()
            if cached_repo_hash == repo_hash:
                logger.info("Load data from the cache.")
                self.data = yaml.safe_load(file(self.cache_path))
                if os.path.isfile(self.sqlite_cache_path):
                    self._load_tables()
                else:
                    logger.info('Creating SQLite cache.')
            else:
                logger.info("DB cache is outdated.")

    def _load_tables(self):
        # Handle tests in memory
        if self.sqlite_cache_path.startswith('/tmp/'):
            path = ''
        else:
            path = self.sqlite_cache_path
        self.engine = sqla.create_engine('sqlite://%s' % path)
        project_table = sqla.Table(
            'project', self.metadata,
            sqla.Column('id', sqla.TEXT(), primary_key=True),
            sqla.Column('name', sqla.TEXT()),
            sqla.Column('website', sqla.TEXT()),
            sqla.Column('documentation', sqla.TEXT()),
            sqla.Column('issue_tracker', sqla.TEXT()),
        )
        self._tables['project'] = project_table
        mailing_list_table = sqla.Table(
            'mailing_list', self.metadata,
            sqla.Column('project_id', sqla.TEXT(),
                        sqla.ForeignKey('project.id')),
            sqla.Column('mailing_list', sqla.TEXT()),
        )
        self._tables['mailing_list'] = mailing_list_table
        contact_table = sqla.Table(
            'contact', self.metadata,
            sqla.Column('project_id', sqla.TEXT(),
                        sqla.ForeignKey('project.id')),
            sqla.Column('contact', sqla.TEXT()),
        )
        self._tables['contact'] = contact_table
        acl_table = sqla.Table(
            'acl', self.metadata,
            sqla.Column('id', sqla.TEXT(), primary_key=True),
            sqla.Column('name', sqla.TEXT()),
        )
        self._tables['acl'] = acl_table
        repository_table = sqla.Table(
            'repository', self.metadata,
            sqla.Column('id', sqla.TEXT(), primary_key=True),
            sqla.Column('name', sqla.TEXT()),
            sqla.Column('acl', sqla.TEXT(),
                        sqla.ForeignKey('acl.id')),
        )
        self._tables['repository'] = repository_table
        project_repo_table = sqla.Table(
            'project_repo', self.metadata,
            sqla.Column('project_id', sqla.TEXT(),
                        sqla.ForeignKey('project.id')),
            sqla.Column('repo_id', sqla.TEXT(),
                        sqla.ForeignKey('repository.id')),
        )
        self._tables['project_repo'] = project_repo_table
        group_table = sqla.Table(
            'group', self.metadata,
            sqla.Column('id', sqla.TEXT(), primary_key=True),
            sqla.Column('name', sqla.TEXT()),
        )
        self._tables['group'] = group_table
        member_table = sqla.Table(
            'member', self.metadata,
            sqla.Column('group_id', sqla.TEXT(),
                        sqla.ForeignKey('group.id')),
            sqla.Column('member_email', sqla.TEXT()),
        )
        self._tables['member'] = member_table
        acl_group_table = sqla.Table(
            'acl_group', self.metadata,
            sqla.Column('acl_id', sqla.TEXT(),
                        sqla.ForeignKey('acl.id')),
            sqla.Column('group_id', sqla.TEXT(),
                        sqla.ForeignKey('group.id')),
        )
        self._tables['acl_group'] = acl_group_table

    def _fill_tables(self):
        del self.engine
        try:
            os.unlink(self.sqlite_cache_path)
        except OSError:
            # file not found, no problem
            logger.debug('No sqlite cache to remove, skipping.')
        # Handle tests in memory
        if self.sqlite_cache_path.startswith('/tmp/'):
            path = ''
        else:
            path = self.sqlite_cache_path
        self.engine = sqla.create_engine('sqlite://%s' % path)
        self.metadata = sqla.MetaData()
        logger.info('loading data into SQLite tables.')
        self._load_tables()
        self.metadata.create_all(self.engine)
        raw_resources = self.data
        raw_projects = raw_resources['resources'].get('projects', {})
        raw_groups = raw_resources['resources'].get('groups', {})
        raw_acls = raw_resources['resources'].get('acls', {})
        raw_repositories = raw_resources['resources'].get('repos', {})
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
        with self.engine.begin() as conn:
            # Insert in order with respect to primary keys
            conn.execute(self._tables['project'].insert(), ins_project)
            conn.execute(self._tables['mailing_list'].insert(), ins_ml)
            conn.execute(self._tables['contact'].insert(), ins_contact)
            conn.execute(self._tables['group'].insert(), ins_group)
            conn.execute(self._tables['member'].insert(), ins_member)
            conn.execute(self._tables['acl'].insert(), ins_acl)
            conn.execute(self._tables['acl_group'].insert(), ins_acl_group)
            conn.execute(self._tables['repository'].insert(), ins_repo)
            conn.execute(self._tables['project_repo'].insert(),
                         ins_project_repo)

    def refresh(self):
        """ Reload of the YAML files.
        """
        self.data = None
        self._update_git_clone()
        self._load_from_cache()
        # Load from files. Cache is not up to date.
        if not self.data:
            self._tables = {}
            self._load_db()
            self._update_cache()
        if not self._tables:
            self._fill_tables()

    def get_data(self):
        """ Return the full data structure.
        """
        return {'engine': self.engine,
                'tables': self._tables,
                'data': self.data}
