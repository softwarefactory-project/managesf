# -*- coding: utf-8 -*-
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
import yaml
try:
    from yaml import CSafeDumper as YDumper
except ImportError:
    from yaml import SafeDumper as YDumper
import tempfile


def prepare_git_repo(db_path):
    repo_path = tempfile.mkdtemp()
    db_path.append(repo_path)
    repo = git.Git(repo_path)
    repo.init()
    return repo_path


def prepare_db_env(db_path):
    clone_path = tempfile.mkdtemp()
    fd, cache_path = tempfile.mkstemp()
    os.close(fd)
    db_path.append(clone_path)
    db_path.append(cache_path)
    return clone_path, cache_path


def add_yaml_data(repo_path, data, free_style=False):
    repo = git.Git(repo_path)
    sub_dir = "resources"
    db_path = os.path.join(repo_path, sub_dir)
    if not os.path.isdir(db_path):
        os.mkdir(db_path)
    filename = "%s.yaml" % id(data)
    if not free_style:
        with open(os.path.join(db_path, filename), 'w') as dbfile:
            yaml.dump(data,
                      dbfile,
                      allow_unicode=True,
                      default_flow_style=False,
                      Dumper=YDumper)
    else:
        open(os.path.join(db_path, filename), 'w').write(data)
    repo.execute(['git', 'add', sub_dir])
    repo.update_environment(GIT_AUTHOR_EMAIL='test@test.com')
    repo.update_environment(GIT_AUTHOR_NAME='test')
    repo.update_environment(GIT_COMMITTER_EMAIL='test@test.com')
    repo.update_environment(GIT_COMMITTER_NAME='test')
    repo.execute(['git', 'commit', '-m', 'add %s' % filename])
    return repo_path
