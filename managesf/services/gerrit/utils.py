#!/usr/bin/env python
#
# Copyright (C) 2015 Red Hat <licensing@enovance.com>
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
import re
import shutil
import shlex
import stat
import logging
import tempfile
import subprocess


logger = logging.getLogger(__name__)


class LocalProcessError(Exception):
    pass


def _exec(cmd, cwd=None, env=None):
    cmd = shlex.split(cmd)
    ocwd = os.getcwd()
    if cwd:
        os.chdir(cwd)
    if not env:
        env = os.environ.copy()
    try:
        std_out = subprocess.check_output(cmd, env=env, cwd=cwd,
                                          stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as err:
        msg = '"%s" failed with error code %s: %s'
        logger.exception(msg % (' '.join(cmd), err.returncode, err.output))
        msg = '"%s" failed with error code %s'
        raise LocalProcessError(msg % (' '.join(cmd), err.returncode))

    logger.info("[gerrit] cmd %s output" % cmd)
    logger.info(std_out)
    os.chdir(ocwd)
    return std_out


def ssh_wrapper_setup(filename):
    ssh_wrapper = "ssh -o StrictHostKeyChecking=no -i %s \"$@\"" % filename
    wrapper_path = os.path.join(tempfile.mkdtemp(), 'ssh_wrapper.sh')
    file(wrapper_path, 'w').write(ssh_wrapper)
    os.chmod(wrapper_path, stat.S_IRWXU)
    return wrapper_path


def set_gitssh_wrapper_from_str(ssh_key):
    tmpf = tempfile.NamedTemporaryFile(delete=False)
    tmpf.close()
    path = tmpf.name
    os.chmod(path, 0600)
    with open(path, "wb") as f:
        f.write(ssh_key)
    wrapper_path = ssh_wrapper_setup(path)
    env = os.environ.copy()
    env['GIT_SSH'] = wrapper_path
    return env, path


class GerritRepo(object):
    def __init__(self, prj_name, conf):
        # TODO: manage to destroy temp dir/file after usage
        self.prj_name = prj_name
        self.conf = conf
        self.infos = {}
        self.infos['localcopy_path'] = os.path.join(
            tempfile.mkdtemp(), 'clone-%s' % prj_name)
        if os.path.isdir(self.infos['localcopy_path']):
            shutil.rmtree(self.infos['localcopy_path'])
        self.email = "%(admin)s <%(email)s>" % \
                     {'admin': self.conf.admin['name'],
                      'email': self.conf.admin['email']}
        ssh_key = self.conf.gerrit['sshkey_priv_path']
        self.wrapper_path = ssh_wrapper_setup(ssh_key)
        self.env = os.environ.copy()
        self.env['GIT_SSH'] = self.wrapper_path
        # Commit will be reject by gerrit if the commiter info
        # is not a registered user (author can be anything else)
        self.env['GIT_COMMITTER_NAME'] = self.conf.admin['name']
        self.env['GIT_COMMITTER_EMAIL'] = self.conf.admin['email']
        # This var is used by git-review to set the remote via git review -s
        self.env['USERNAME'] = self.conf.admin['name']

    def _exec(self, cmd):
        return _exec(cmd, cwd=self.infos['localcopy_path'], env=self.env)

    def clone(self):
        logger.info("[gerrit] Clone repository %s" % self.prj_name)
        cmd = "git clone ssh://%(admin)s@%(gerrit-host)s" \
              ":%(gerrit-host-port)s/%(name)s %(localcopy_path)s" % \
              {'admin': self.conf.admin['name'],
               'gerrit-host': self.conf.gerrit['host'],
               'gerrit-host-port': self.conf.gerrit['ssh_port'],
               'name': self.prj_name,
               'localcopy_path': self.infos['localcopy_path']
               }
        _exec(cmd, env=self.env)

    @staticmethod
    def check_upstream(remote, ssh_key=None):
        cmd = "git ls-remote %s" % remote
        try:
            if ssh_key:
                env, path = set_gitssh_wrapper_from_str(ssh_key)
                _exec(cmd, env=env)
                os.remove(path)
            else:
                _exec(cmd)
            return True, None
        except subprocess.CalledProcessError as err:
            return False, "%s: %s" % (err.message, err.output)

    def add_file(self, path, content):
        logger.info("[gerrit] Add file %s to index" % path)
        if path.split('/') > 1:
            d = re.sub(os.path.basename(path), '', path)
            try:
                os.makedirs(os.path.join(self.infos['localcopy_path'], d))
            except OSError:
                pass
        file(os.path.join(self.infos['localcopy_path'],
             path), 'w').write(content)
        cmd = "git add %s" % path
        self._exec(cmd)

    def push_config(self, paths):
        logger.info("[gerrit] Prepare push on config for repository %s" %
                    self.prj_name)
        cmd = "git fetch origin " + \
              "refs/meta/config:refs/remotes/origin/meta/config"
        self._exec(cmd)
        cmd = "git checkout meta/config"
        self._exec(cmd)
        for path, content in paths.items():
            self.add_file(path, content)
        cmd = "git commit -a --author '%s' -m'Provides ACL and Groups'" % \
              self.email
        self._exec(cmd)
        cmd = "git push origin meta/config:meta/config"
        self._exec(cmd)
        logger.info("[gerrit] Push on config for repository %s" %
                    self.prj_name)

    def push_master(self, paths):
        logger.info("[gerrit] Prepare push on master for repository %s" %
                    self.prj_name)
        cmd = "git checkout master"
        self._exec(cmd)
        for path, content in paths.items():
            self.add_file(path, content)
        cmd = "git commit -a --author '%s' -m'ManageSF commit'" % self.email
        self._exec(cmd)
        cmd = "git push origin master"
        self._exec(cmd)
        logger.info("[gerrit] Push on master for repository %s" %
                    self.prj_name)

    def _fetch_upstream_repo(self, remote, ssh_key=None):
        msg = "Add and fetch upstream repo %s to project's repo %s"
        msg = msg % (remote, self.prj_name)
        logger.info(msg)
        cmd = "git remote add upstream %s" % remote
        self._exec(cmd)
        cmd = "git fetch upstream"
        if ssh_key:
            env, path = set_gitssh_wrapper_from_str(ssh_key)
            _exec(cmd, cwd=self.infos['localcopy_path'], env=env)
            os.remove(path)
        else:
            self._exec(cmd)

    def push_master_from_git_remote(self, remote, ssh_key=None,
                                    add_branches=False):
        self._fetch_upstream_repo(remote, ssh_key)
        logger.info("Push remote (master branch) of %s to the "
                    "Gerrit repository" % remote)
        cmd = "git checkout master"
        self._exec(cmd)
        cmd = "git push -f origin upstream/master:master"
        self._exec(cmd)
        cmd = "git reset --hard origin/master"
        self._exec(cmd)
        if add_branches:
            cmd = 'git ls-remote --heads %s' % remote
            try:
                if ssh_key:
                    env, path = set_gitssh_wrapper_from_str(ssh_key)
                    output = _exec(cmd,
                                   cwd=self.infos['localcopy_path'],
                                   env=env)
                else:
                    output = self._exec(cmd)
            except subprocess.CalledProcessError:
                logger.exception('Can not list remote branches %s' % remote)
            if output:
                # Remove the '*' and master branch from the list of branches
                for line in output.splitlines():
                    branch = line.split('refs/heads/')[-1]
                    if not branch and branch in ['*', 'master']:
                        continue
                    cmd = 'git checkout upstream/%s -b %s' % (branch, branch)
                    self._exec(cmd)
                    cmd = 'git push -f origin %s' % branch
                    self._exec(cmd)

    def review_changes(self, commit_msg):
        logger.info("[gerrit] Send a review via git review")
        cmd = "ssh-agent bash -c 'ssh-add %s; git review -s'" %\
              self.conf.gerrit['sshkey_priv_path']
        self._exec(cmd)
        cmd = "git commit -a --author '%s' -m'%s'" % (self.email,
                                                      commit_msg)
        self._exec(cmd)
        cmd = 'git review'
        self._exec(cmd)
