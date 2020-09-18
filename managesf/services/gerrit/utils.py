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
import re
# import shutil
import shlex
import stat
import logging
import tempfile
import subprocess
import json
try:
    from urllib import quote_plus, unquote_plus
except ImportError:
    from urllib.parse import quote_plus, unquote_plus

import requests


logger = logging.getLogger(__name__)


class LocalProcessError(Exception):
    pass


class NotFound(Exception):
    pass


def _exec(cmd, cwd=None, env=None):
    cmd = shlex.split(cmd)
    if not env:
        env = os.environ.copy()
    try:
        std_out = subprocess.check_output(cmd, env=env, cwd=cwd,
                                          stderr=subprocess.STDOUT)
        std_out = std_out.decode()
    except subprocess.CalledProcessError as err:
        msg = u'"%s" failed with error code %s: %s'
        msg = msg % (' '.join(cmd), err.returncode, err.output)
        logger.exception(msg)
        raise LocalProcessError(msg)

    logger.info("[gerrit] cmd %s output" % cmd)
    logger.info(std_out)
    return std_out


def ssh_wrapper_setup(filename):
    ssh_wrapper = "ssh -o StrictHostKeyChecking=no -i %s \"$@\"" % filename
    wrapper_path = os.path.join(tempfile.mkdtemp(), 'ssh_wrapper.sh')
    open(wrapper_path, 'w').write(ssh_wrapper)
    os.chmod(wrapper_path, stat.S_IRWXU)
    return wrapper_path


def set_gitssh_wrapper_from_str(ssh_key):
    tmpf = tempfile.NamedTemporaryFile(delete=False)
    tmpf.close()
    path = tmpf.name
    os.chmod(path, 0o600)
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
        try:
            os.makedirs(self.infos['localcopy_path'])
        except OSError:
            pass
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
        self._exec(cmd)
        cmd = "git fetch -a"
        self._exec(cmd)

    def add_file(self, path, content):
        logger.info("[gerrit] Add file %s to index" % path)
        if len(path.split('/')) > 1:
            d = re.sub(os.path.basename(path), '', path)
            try:
                os.makedirs(os.path.join(self.infos['localcopy_path'], d))
            except OSError:
                pass
        open(os.path.join(self.infos['localcopy_path'],
             path), 'w').write(content)
        cmd = "git add %s" % path
        self._exec(cmd)

    def list_remote_branches(self):
        logger.info("[gerrit] List remote branches")
        cmd = "git branch -rv --abbrev=40"
        # Out put example
        #   origin/HEAD   -> origin/master
        #   origin/master 9dc37aee187412073a10c9df85b6878bc39bd1a2 Cmt msg
        output = self._exec(cmd).splitlines()
        refs = {}
        for line in output:
            line = line.strip()
            elms = line.split()
            refname = "/".join(elms[0].split('/')[1:])
            if refname == 'HEAD':
                refs[refname] = "/".join(elms[2].split('/')[1:])
            else:
                refs[refname] = elms[1]
        return refs

    def create_remote_branch(self, branch, sha):
        logger.info("[gerrit] Create remote branch %s from sha %s" % (
            branch, sha))
        refs = self.list_remote_branches()
        if sha in refs.keys():
            # This is not a sha then ...
            obranch = sha
            sha = refs[sha]
            logger.info("[gerrit] Create remote branch %s from branch"
                        " %s sha %s" % (branch, obranch, sha))
        cmd = "git branch %s %s" % (branch, sha)
        self._exec(cmd)
        cmd = "git push origin %s" % branch
        self._exec(cmd)

    def delete_remote_branch(self, branch):
        logger.info("[gerrit] Delete remote branch %s" % branch)
        cmd = "git push --delete origin %s" % branch
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
        if self._exec('git status -s'):
            cmd = "git commit -a --author '%s' -m'Provides ACL and Groups'" % (
                self.email)
            self._exec(cmd)
            cmd = "git push origin meta/config:meta/config"
            self._exec(cmd)
            logger.info("[gerrit] Push on config for "
                        "repository %s" % self.prj_name)

    def get_raw_acls(self):
        remote = "ssh://%(u)s@%(h)s:%(p)s/%(name)s" % {
            'u': self.conf.admin['name'],
            'h': self.conf.gerrit['host'],
            'p': self.conf.gerrit['ssh_port'],
            'name': self.prj_name,
        }
        if not os.path.isdir(
                os.path.join(self.infos['localcopy_path'], '.git')):
            self._exec('git init .')
        self._exec('git remote add origin %s' % remote)
        cmd = "git fetch origin " + \
              "refs/meta/config:refs/remotes/origin/meta/config"
        self._exec(cmd)
        cmd = "git checkout meta/config"
        self._exec(cmd)
        return os.path.join(self.infos['localcopy_path'],
                            'project.config')

    def push_branch(self, branch, paths):
        logger.info("[gerrit] Prepare push on %s for repository %s" % (
                    branch, self.prj_name))
        cmd = "git checkout %s" % branch
        self._exec(cmd)
        cmd = "git reset --hard origin/%s" % branch
        self._exec(cmd)
        for path, content in paths.items():
            self.add_file(path, content)
        if self._exec('git status -s'):
            cmd = "git commit -a --author '%s' -m'ManageSF commit'" % (
                self.email)
            self._exec(cmd)
            cmd = "git push origin %s" % branch
            self._exec(cmd)
            logger.info("[gerrit] Push on %s for repository %s" % (
                        branch, self.prj_name))

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


class GerritClientError(Exception):
    def __init__(self, resp, action, url):
        self.status_code = resp.status_code
        self.resp = resp
        self.action = action
        self.url = url

    def __str__(self):
        return "%s %s -> %d: %s" % (
            self.action, self.url, self.status_code, self.resp.text)


class GerritClient:
    log = logging.getLogger("managesf.GerritClient")

    def __init__(self, url, auth):
        if url.endswith("/r/"):
            url = url + "a/"
        self.url = url
        self.auth = auth

    # Raw REST API
    def decode(self, resp):
        if not resp.text:
            return None
        try:
            return json.loads(resp.text[4:])
        except ValueError:
            self.log.error("Couldn't decode: [%s]" % resp.text)
            return resp.text

    def request(self, method, url, json_data=None, raw_data=None):
        resp = requests.request(
            method, url, json=json_data, data=raw_data, auth=self.auth)
        self.log.debug("%6s | %s (%s) -> %s" % (method, url, json_data, resp))
        if resp.status_code == 404:
            raise NotFound()
        if not resp.ok:
            raise GerritClientError(resp, method, url)
        return resp

    def get(self, url):
        resp = self.request("get", os.path.join(self.url, url))
        return self.decode(resp)

    def post(self, url, json_data=None, raw_data=None):
        resp = self.request(
            "post", os.path.join(self.url, url), json_data, raw_data)
        return self.decode(resp)

    def delete(self, url, json_data=None):
        resp = self.request("delete", os.path.join(self.url, url), json_data)
        return self.decode(resp)

    def put(self, url, json_data=None):
        resp = self.request("put", os.path.join(self.url, url), json_data)
        return self.decode(resp)

    # Changes API
    def get_open_changes(self):
        return self.get("changes/")

    # Accounts API
    def create_account(self, user, data):
        self.log.info(u"%s: creating account with %s", user, data)
        user = quote_plus(user)
        return self.put("accounts/%s" % user, data)

    def get_account(self, user, details=False):
        user = quote_plus(user)
        if details:
            user = user + "/detail"
        return self.get('accounts/%s' % user)

    def update_account_name(self, user, full_name):
        self.log.debug(u"%s: updating name to %s", user, full_name)
        user = quote_plus(user)
        self.put("accounts/%s/name" % user, {"name": full_name})

    def delete_account_email(self, user, email):
        self.log.info(u"%s: deleting email %s", user, email)
        user = quote_plus(user)
        email = quote_plus(email)
        self.delete("accounts/%s/emails/%s" % (user, email))

    def update_account_preferred_email(self, user, email):
        self.log.info(u"%s: setting preffered email %s", user, email)
        user = quote_plus(user)
        email = quote_plus(email)
        self.put("accounts/%s/emails/%s/preferred" % (user, email))

    def add_account_email(self, user, email):
        self.log.info(u"%s: adding email %s", user, email)
        user = quote_plus(user)
        email = quote_plus(email)
        self.put("accounts/%s/emails/%s" % (user, email),
                 {"preferred": True, "no_confirmation": True})

    def is_account_active(self, user):
        try:
            user = quote_plus(user)
            if self.get("accounts/%s/active" % user) == "ok":
                return True
        except NotFound:
            pass
        return False

    # Pub keys
    def get_pubkeys(self, user):
        user = quote_plus(user)
        return self.get("accounts/%s/sshkeys" % user)

    def del_pubkey(self, index, user='self'):
        self.log.debug("%s: removing pubkey %s", user, index)
        user = quote_plus(user)
        self.delete('accounts/%s/sshkeys/%s' % (user, index))

    def add_pubkey(self, pubkey, user='self'):
        self.log.debug("%s: adding pubkey %s", user, pubkey)
        user = quote_plus(user)
        response = self.post('accounts/%s/sshkeys' % user, raw_data=pubkey)
        return response['seq']

    # Groups
    def get_user_groups(self, user):
        user = quote_plus(user)
        try:
            return self.get("accounts/%s/groups/" % user)
        except NotFound:
            return []

    def get_groups(self):
        return self.get("groups/")

    def get_group_id(self, name):
        try:
            name = quote_plus(name)
            gid = self.get('groups/%s/detail' % name)['id']
            return unquote_plus(gid)
        except NotFound:
            return False

    def get_group_members(self, name):
        name = quote_plus(name)
        return self.get('groups/%s/members/' % name)

    def get_group_group_members(self, group):
        group = quote_plus(group)
        return self.get('groups/%s/groups/' % group)

    def create_group(self, name, description):
        self.log.info(u"%s: creating group (%s)", name, description)
        name = quote_plus(name)
        return self.put("groups/%s" % name, {"description": description})

    def add_group_group_member(self, targetgroup, groupname):
        targetgroup = quote_plus(targetgroup)
        groupname = quote_plus(groupname)
        self.put('groups/%s/groups/%s' % (targetgroup, groupname))

    def delete_group_group_member(self, targetgroup, groupname):
        self.log.info(
            u"%s: deleting group group member %s", targetgroup, groupname)
        targetgroup = quote_plus(targetgroup)
        groupname = quote_plus(groupname)
        self.delete('groups/%s/groups/%s' % (targetgroup, groupname))

    def delete_group_member(self, name, member):
        self.log.info(u"%s: deleting group member %s", name, member)
        name = quote_plus(name)
        member = quote_plus(member)
        return self.delete("groups/%s/members/%s" % (name, member))

    def add_group_member(self, members, name):
        self.log.info(u"%s: adding group member %s", name, members)
        if not isinstance(members, list):
            members = [members]
        name = quote_plus(name)
        return self.post("groups/%s/members" % name, {"members": members})

    def rename_group(self, name, newname):
        self.log.info(u"%s: renaming to %s" % (name, newname))
        return self.put(
            "groups/%s/name" % quote_plus(name),
            {"name": newname}
        )

    # Projects
    def get_projects(self):
        return self.get("projects/")

    def create_project(self, name, description, owners):
        self.log.info(u"%s: creating project (%s)", name, description)
        name = quote_plus(name)
        return self.put("projects/%s" % name, {"description": description,
                                               "owners": owners,
                                               "create_empty_commit": True})

    def delete_project(self, name, force=False):
        self.log.info(u"%s: deleting project", name)
        data = {}
        if force:
            data = {'force': True}
        name = quote_plus(name)
        return self.post("projects/%s/delete-project~delete" % name, data)

    def project_exists(self, name):
        try:
            name = quote_plus(name)
            self.get("projects/%s" % name)
            return True
        except NotFound:
            return False
        except Exception:
            self.log.exception("Couldn't check project %s" % name)
            raise
