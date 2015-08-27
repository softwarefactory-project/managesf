# Copyright (C) 2014 eNovance SAS <licensing@enovance.com>
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

import random
import string
import time

import paramiko
from pecan import conf
from pecan import expose
from pecan import abort
from pecan.rest import RestController
from pecan import request, response
from managesf.controllers import gerrit, redminec
from managesf.controllers import backup, localuser, introspection
import logging
import os.path

import htpasswd

logger = logging.getLogger(__name__)

LOGERRORMSG = "Unable to process client request, failed with "\
              "unhandled error: %s"
CLIENTERRORMSG = "Unable to process your request, failed with "\
                 "unhandled error (server side): %s"

# TODO: add detail (detail arg or abort function) for all abort calls.


def report_unhandled_error(exp):
    logger.exception(LOGERRORMSG % str(exp))
    response.status = 500
    return CLIENTERRORMSG % str(exp)


class ReplicationController(RestController):
    # 'add','rename-section'
    @expose()
    def put(self, section=None, setting=None):
        if not section or ('value' not in request.json):
            abort(400)
        value = request.json['value']
        try:
            gerrit.replication_apply_config(section, setting, value)
        except Exception as e:
            return report_unhandled_error(e)

    # 'unset', 'replace-all', 'remove-section'
    @expose()
    def delete(self, section=None, setting=None):
        if not section:
            abort(400)
        try:
            gerrit.replication_apply_config(section, setting)
        except Exception as e:
            return report_unhandled_error(e)

    # 'get-all', 'list'
    @expose()
    def get(self, *remainder):
        section = None
        setting = None
        if len(remainder) >= 1:
            section = remainder[0]
        if len(remainder) >= 2:
            setting = remainder[1]
        config = None
        try:
            config = gerrit.replication_get_config(section, setting)
        except Exception as e:
            return report_unhandled_error(e)
        if config:
            response.status = 200
            return str(config)
        response.status = 404
        return

    @expose()
    def post(self):
        # A json with wait, url, project can be passed
        inp = request.json if request.content_length else {}
        try:
            gerrit.replication_trigger(inp)
        except Exception as e:
            return report_unhandled_error(e)


class BackupController(RestController):
    @expose()
    def get(self):
        # TODO: avoid using directly /tmp
        filepath = '/tmp/sf_backup.tar.gz'
        try:
            backup.backup_get()
        except Exception as e:
            return report_unhandled_error(e)
        if not os.path.isfile(filepath):
            abort(404)
        response.body_file = open(filepath, 'rb')
        return response

    @expose()
    def post(self):
        try:
            backup.backup_start()
        except Exception as e:
            return report_unhandled_error(e)


class RestoreController(RestController):
    @expose()
    def post(self):
        # TODO: avoid using directly /tmp
        filepath = '/tmp/sf_backup.tar.gz'
        with open(filepath, 'wb+') as f:
            f.write(request.POST['file'].file.read())
        try:
            backup.backup_restore()
        except Exception as e:
            return report_unhandled_error(e)


class MembershipController(RestController):
    @expose("json")
    def get(self):
        try:
            return redminec.get_active_users()
        except Exception as e:
            return report_unhandled_error(e)

    @expose()
    def put(self, project=None, user=None):
        if not project or not user:
            abort(400)
        inp = request.json if request.content_length else {}
        if 'groups' not in inp:
            abort(400)
        if '@' not in user:
            response.status = 400
            return "User must be identified by its email address"
        try:
            # Add/update user for the project groups
            gerrit.add_user_to_projectgroups(project, user, inp['groups'])
            redminec.add_user_to_projectgroups(project, user, inp['groups'])
            response.status = 201
            return "User %s has been added in group(s): %s for project %s" % \
                (user, ", ".join(inp['groups']), project)
        except Exception as e:
            return report_unhandled_error(e)

    @expose()
    def delete(self, project=None, user=None, group=None):
        if not project or not user:
            abort(400)
        if '@' not in user:
            response.status = 400
            return "User must be identified by its email address"
        try:
            # delete user from all project groups
            gerrit.delete_user_from_projectgroups(project, user, group)
            redminec.delete_user_from_projectgroups(project, user, group)
            response.status = 200
            if group:
                return "User %s has been deleted from group %s for project %s." % \
                    (user, group, project)
            else:
                return "User %s has been deleted from all groups for project %s." % \
                    (user, project)
        except Exception as e:
            return report_unhandled_error(e)


class ProjectController(RestController):

    membership = MembershipController()

    def __init__(self):
        self.cache = {}
        self.cache_timeout = 15

    def set_cache(self, values):
        token = request.cookies.get('auth_pubtkt')
        if token:
            self.cache[token] = (time.time(), values)

    def get_cache(self):
        token = request.cookies.get('auth_pubtkt')
        if token:
            last, values = self.cache.get(token, (None, None))
            if last and last + self.cache_timeout > time.time():
                return values
        return {}

    def _reload_cache(self):
        projects = {}

        for p in gerrit.get_projects():
            projects[p] = {'open_reviews': 0,
                           'open_issues': 0,
                           'admin': 0,
                           'groups': {}}
            groups = gerrit.get_project_groups(p)
            for group in groups:
                if group['name'].endswith(('-ptl', '-core', '-dev')):
                    grp = group['name'].split('-')[-1]
                    projects[p]['groups'][grp] = group

        for p in gerrit.get_projects_by_user():
            projects[p]['admin'] = 1

        for issue in redminec.get_open_issues().get('issues'):
            prj = issue.get('project').get('name')
            if prj in projects:
                projects[prj]['open_issues'] += 1

        for review in gerrit.get_open_changes():
            prj = review.get('project')
            if prj in projects:
                projects[prj]['open_reviews'] += 1

        self.set_cache(projects)

    @expose("json")
    def get_all(self):
        projects = self.get_cache()
        if projects:
            return projects

        self._reload_cache()
        return self.get_cache()

    @expose("json")
    def get_one(self, project_id):
        projects = self.get_cache()
        try:
            if projects:
                return projects[project_id]
            self._reload_cache()
            return self.get_cache()[project_id]
        except KeyError as exp:
            logger.exception(exp)
            return abort(400)

    @expose()
    def put(self, name=None):
        if getattr(conf, "project_create_administrator_only", True):
            if not gerrit.user_is_administrator():
                abort(401)

        if not name:
            abort(400)
        try:
            # create project
            inp = request.json if request.content_length else {}
            for gn in ('ptl-group-members', 'core-group-members',
                       'dev-group-members'):
                for u in inp.get(gn, []):
                    if '@' not in u:
                        response.status = 400
                        return "User must be identified by its email address"
            gerrit.init_project(name, inp)
            redminec.init_project(name, inp)
            response.status = 201
            self.set_cache(None)
            return "Project %s has been created." % name
        except Exception as e:
            return report_unhandled_error(e)

    @expose()
    def delete(self, name=None):
        if name == 'config':
            response.status = 400
            return "Deletion of config project denied"
        if not name:
            abort(400)
        try:
            # delete project
            gerrit.delete_project(name)
            redminec.delete_project(name)
            response.status = 200
            self.set_cache(None)
            return "Project %s has been deleted." % name
        except Exception as e:
            return report_unhandled_error(e)


class LocalUserController(RestController):

    @expose("json")
    def post(self, username):
        if request.remote_user is None:
            # remote_user must be set by auth_pubtkt plugin of apache
            # if not there we abort !
            abort(403)
        infos = request.json if request.content_length else {}
        try:
            ret = localuser.update_user(username, infos)
        except localuser.AddUserForbidden as e:
            abort(403, detail=e.message)
        except (localuser.InvalidInfosInput, localuser.BadUserInfos) as e:
            abort(400, detail=e.message)
        except Exception as e:
            return report_unhandled_error(e)
        if isinstance(ret, dict):
            # user created - set correct status code
            response.status = 201
        return ret

    @expose("json")
    def get(self, username):
        if request.remote_user is None:
            # remote_user must be set by auth_pubtkt plugin of apache
            # if not there we abort !
            abort(403)
        try:
            ret = localuser.get_user(username)
        except localuser.GetUserForbidden as e:
            abort(403, detail=e.message)
        except localuser.UserNotFound as e:
            abort(404, detail=e.message)
        except Exception as e:
            return report_unhandled_error(e)
        return ret

    @expose("json")
    def delete(self, username):
        if request.remote_user is None:
            # remote_user must be set by auth_pubtkt plugin of apache
            # if not there we abort !
            abort(403)
        try:
            ret = localuser.delete_user(username)
        except localuser.DeleteUserForbidden as e:
            abort(403, detail=e.message)
        except localuser.UserNotFound as e:
            abort(404, detail=e.message)
        except Exception as e:
            return report_unhandled_error(e)
        return ret


class LocalUserBindController(RestController):

    @expose("json")
    def get(self):
        authorization = request.headers.get('Authorization', None)
        if not authorization:
            abort(401, detail="Authentication header missing")
        try:
            ret = localuser.bind_user(authorization)
        except (localuser.BindForbidden, localuser.UserNotFound) as e:
            abort(401, detail=e.message)
        except Exception as e:
            return report_unhandled_error(e)
        if not ret:
            abort(401, detail="Authentication failed")
        return ret


class HtpasswdController(RestController):
    def __init__(self):
        self.filename = None
        if getattr(conf, "htpasswd", None):
            self.filename = conf.htpasswd.get('filename')
            # Ensure file exists
            open(self.filename, "a").close()

    @expose()
    def put(self):
        if request.remote_user is None:
            abort(403)
        password = ''.join(
            random.SystemRandom().choice(string.letters + string.digits)
            for _ in range(12))
        try:
            with htpasswd.Basic(self.filename) as userdb:
                try:
                    userdb.add(request.remote_user, password)
                except htpasswd.basic.UserExists:
                    pass
                userdb.change_password(request.remote_user, password)
        except IOError:
            abort(406)
        response.status = 201
        return password

    @expose()
    def get(self):
        if request.remote_user is None:
            abort(403)
        response.status = 404
        try:
            with htpasswd.Basic(self.filename) as userdb:
                exists = request.remote_user in userdb.users
                if exists:
                    response.status = 200
        except IOError:
            abort(406)
        return

    @expose()
    def delete(self):
        if request.remote_user is None:
            abort(403)
        try:
            with htpasswd.Basic(self.filename) as userdb:
                userdb.pop(request.remote_user)
        except IOError:
            abort(406)


class SSHConfigController(RestController):
    def __init__(self):
        self.confdir = None
        sshconfig = getattr(conf, "sshconfig", {})
        self.confdir = sshconfig.get('confdir', '/var/www/managesf/sshconfig')
        if not os.path.exists(self.confdir):
            os.makedirs(self.confdir)
        self.filename = os.path.join(self.confdir, "config")
        self.hostname = sshconfig.get('hostname', 'gerrit.tests.dom')
        self.username = sshconfig.get('username', 'gerrit')
        self.key_filename = sshconfig.get(
            'key_filename', '/var/www/managesf/gerrit_admin_rsa')

        self.mapping = {
            'hostname': 'Hostname',
            'identityfile': 'IdentityFile',
            'userknownhostsfile': 'UserKnownHostsFile',
            'preferredauthentications': 'PreferredAuthentications',
            'stricthostkeychecking': 'StrictHostKeyChecking',
            'username': 'Username'
        }

    def _dump_config(self, configdict):
        """ Converts a config dict to a ssh config string """
        content = ""
        keyfiles = []

        for alias, config in configdict.items():
            if alias == "*":
                continue

            # Write the identityfile content to an actual identityfile
            identityfile_content = config.get('identityfile_content')
            if identityfile_content:
                identityfile_content = identityfile_content
                identityfile_name = os.path.join(
                    self.confdir, "%s.key" % alias)
                keyfiles.append(identityfile_name)
                with open(identityfile_name, "w") as id_file:
                    id_file.write(identityfile_content)
                config['identityfile'] = "~/.ssh/%s.key" % alias

            content += 'Host "%s"\n' % alias

            for k in sorted(config.iterkeys()):
                v = config[k]
                if isinstance(v, list):
                    v = str(v[0])
                # Only add known settings
                setting = self.mapping.get(k)
                if setting:
                    content += "    %s %s\n" % (setting, v)
            content += "\n"

        return (content, keyfiles)

    def _read_sshconfig(self, filename):
        """ Reads a ssh config file to a dict """
        c = paramiko.config.SSHConfig()

        # Open new file if not exists, but don't truncate
        with open(self.filename, "a+") as sshfile:
            sshfile.seek(0)
            c.parse(sshfile)
        ret = {}
        for config in c._config:
            host = config.get('host')[0].strip('"')
            conf = config.get('config')
            ret[host] = conf
        return ret

    def _write_config(self, conf):
        sshconfig, keyfiles = self._dump_config(conf)
        with open(self.filename, "w") as conffile:
            conffile.write(sshconfig)
        return keyfiles

    def _copy2gerrit(self, filenames):
        success = True

        known_hosts = os.path.expanduser("~/.ssh/known_hosts")
        cmd = "sudo systemctl restart gerrit.service"

        ssh = paramiko.SSHClient()
        ssh.load_host_keys(known_hosts)

        ssh.connect(self.hostname,
                    username=self.username,
                    key_filename=self.key_filename)

        sftp = ssh.open_sftp()
        for filename in filenames:
            remote_filename = ".ssh/%s" % os.path.basename(filename)
            try:
                sftp.put(filename, remote_filename)
                sftp.chmod(remote_filename, 0600)
            except IOError:
                success = False
        sftp.close()

        (_, stdout, stderr) = ssh.exec_command(cmd)
        if stdout.readlines() or stderr.readlines():
            success = False
        ssh.close()

        return success

    @expose()
    def put(self, name):
        if request.remote_user is None:
            abort(403)

        conf = self._read_sshconfig(self.filename)
        conf[name] = request.json if request.content_length else {}

        filenames = self._write_config(conf)
        filenames.append(self.filename)
        if not self._copy2gerrit(filenames):
            response.status = 500

        response.status = 201

    @expose()
    def get(self, name):
        if request.remote_user is None:
            abort(403)

        conf = self._read_sshconfig(self.filename)

        return conf

    @expose()
    def delete(self, name):
        if request.remote_user is None:
            abort(403)

        conf = self._read_sshconfig(self.filename)
        if name in conf:
            id_file = conf.get(name, {}).get('IdentityFile')
            if id_file:
                os.remove(id_file)
            del conf[name]

        self._write_config(conf)


class TestsController(RestController):
    test_script_template = '''#! /bin/bash\n

echo "Modify this script to run your project's unit tests. "
echo "Until you do this, it will exit in failure !"
exit 1;
    '''

    @expose('json')
    def put(self, project_name=''):
        if not gerrit.user_is_administrator():
            abort(403)

        if not gerrit.get_project(project_name):
            abort(404)

        gerrit.commit_init_tests_scripts(project_name)

        project_scripts = False
        if request.json:
            project_scripts = request.json.get('project-scripts', False)

        if project_scripts:
            project_git = gerrit.GerritRepo(project_name)
            project_git.clone()
            project_git.add_file('run_test.sh', self.test_script_template)
            project_git.review_changes()
        response.status = 201


class RootController(object):
    project = ProjectController()
    replication = ReplicationController()
    backup = BackupController()
    restore = RestoreController()
    user = LocalUserController()
    bind = LocalUserBindController()
    htpasswd = HtpasswdController()
    about = introspection.IntrospectionController()
    sshconfig = SSHConfigController()
    tests = TestsController()
