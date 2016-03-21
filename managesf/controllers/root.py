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

import base64
import time
import logging
import os.path

import paramiko
from pecan import conf
from pecan import expose
from pecan import abort
from pecan.rest import RestController
from pecan import request, response
from stevedore import driver

from managesf.controllers import backup, localuser, introspection, htp, pages
from managesf.services import base, gerrit
from managesf.services import exceptions


logger = logging.getLogger(__name__)

LOGERRORMSG = "Unable to process client request, failed with "\
              "unhandled error: %s"
CLIENTERRORMSG = "Unable to process your request, failed with "\
                 "unhandled error (server side): %s"

# TODO: add detail (detail arg or abort function) for all abort calls.


# instanciate service plugins
SF_SERVICES = []
DEFAULT_SERVICES = ['SFGerrit', 'SFRedmine', 'jenkins']


def load_services():
    try:
        if conf.services:
            services = conf.services
        else:
            services = DEFAULT_SERVICES
            msg = 'No service configured, loading: %s' % DEFAULT_SERVICES
            logger.info(msg)
    except AttributeError:
        services = DEFAULT_SERVICES
        msg = 'Obsolete conf file, loading default: %s' % DEFAULT_SERVICES
        logger.info(msg)

    for service in services:
        try:
            plugin = driver.DriverManager(namespace='managesf.service',
                                          name=service,
                                          invoke_on_load=True,
                                          invoke_args=(conf,)).driver
            SF_SERVICES.append(plugin)
            logger.info('%s plugin loaded successfully' % service)
        except Exception as e:
            logger.error('Could not load service %s: %s' % (service, e))


def _decode_project_name(name):
    if name.startswith('==='):
        try:
            n = base64.urlsafe_b64decode(name.encode()[3:])
            return n.decode('utf8')
        except Exception:
            return name[3:]
    return name


def is_admin(user):
    return base.RoleManager.is_admin(user)


def report_unhandled_error(exp):
    logger.exception(LOGERRORMSG % str(exp))
    response.status = 500
    return CLIENTERRORMSG % str(exp)


class ReplicationController(RestController):
    # 'add','rename-section'
    @expose('json')
    def put(self, section=None, setting=None):
        if not section or ('value' not in request.json):
            abort(400)
        value = request.json['value']
        user = request.remote_user
        try:
            replicators = [s for s in SF_SERVICES
                           if isinstance(s, base.BaseRepositoryServicePlugin)]
            for service in replicators:
                try:
                    service.replication.apply_config(user, section,
                                                     setting, value)
                except exceptions.UnavailableActionError:
                    msg = '[%s] replication not available'
                    logger.debug(msg % (service.service_name, ))
            response.status = 204
        except Exception as e:
            return report_unhandled_error(e)

    # 'unset', 'replace-all', 'remove-section'
    @expose('json')
    def delete(self, section=None, setting=None):
        if not section:
            abort(400)
        user = request.remote_user
        try:
            replicators = [s for s in SF_SERVICES
                           if isinstance(s, base.BaseRepositoryServicePlugin)]
            for service in replicators:
                try:
                    service.replication.apply_config(user, section, setting)
                except exceptions.UnavailableActionError:
                    msg = '[%s] replication not available'
                    logger.debug(msg % (service.service_name, ))
            response.status = 204
        except Exception as e:
            return report_unhandled_error(e)

    # 'get-all', 'list'
    @expose('json')
    def get(self, *remainder):
        section = None
        setting = None
        if len(remainder) >= 1:
            section = remainder[0]
        if len(remainder) >= 2:
            setting = remainder[1]
        config = []
        user = request.remote_user
        try:
            replicators = [s for s in SF_SERVICES
                           if isinstance(s, base.BaseRepositoryServicePlugin)]
            for service in replicators:
                try:
                    config.append(service.replication.get_config(user,
                                                                 section,
                                                                 setting))
                except exceptions.UnavailableActionError:
                    msg = '[%s] replication not available'
                    logger.debug(msg % (service.service_name, ))
        except Exception as e:
            return report_unhandled_error(e)
        if config:
            response.status = 200
            if len(config) == 1:
                return str(config[0])
            else:
                return str(config)
        response.status = 404
        return

    @expose('json')
    def post(self):
        # A json with wait, url, project can be passed
        inp = request.json if request.content_length else {}
        user = request.remote_user
        try:
            replicators = [s for s in SF_SERVICES
                           if isinstance(s, base.BaseRepositoryServicePlugin)]
            for service in replicators:
                try:
                    service.replication.trigger(user, inp)
                except exceptions.UnavailableActionError:
                    msg = '[%s] replication not available'
                    logger.debug(msg % (service.service_name, ))
            response.status = 204
        except Exception as e:
            return report_unhandled_error(e)


class BackupController(RestController):
    @expose('json')
    def get(self):
        filepath = '/var/www/managesf/sf_backup.tar.gz'
        if not os.path.isfile(filepath):
            abort(404)
        response.body_file = open(filepath, 'rb')
        return response

    @expose('json')
    def post(self):
        if not is_admin(request.remote_user):
            abort(401)
        else:
            try:
                for service in SF_SERVICES:
                    try:
                        service.backup.backup()
                    except exceptions.UnavailableActionError:
                        msg = '[%s] backup is not an available action'
                        logger.debug(msg % service.service_name)
                backup.backup_start()
                response.status = 204
            except Exception as e:
                return report_unhandled_error(e)


class RestoreController(RestController):
    @expose('json')
    def post(self):
        filepath = '/var/www/managesf/sf_backup.tar.gz'
        with open(filepath, 'wb+') as f:
            f.write(request.POST['file'].file.read())
        try:
            backup.backup_unpack()
            backup.backup_restore()
            for service in SF_SERVICES:
                try:
                    service.backup.restore()
                except exceptions.UnavailableActionError:
                    msg = '[%s] backup is not an available action'
                    logger.debug(msg % service.service_name)
            response.status = 204
        except Exception as e:
            return report_unhandled_error(e)


class MembershipController(RestController):
    @expose('json')
    def get(self):
        try:
            # TODO(mhu) this must be independent from redmine
            tracker = [s for s in SF_SERVICES
                       if isinstance(s, base.BaseIssueTrackerServicePlugin)][0]
            return tracker.get_active_users()
        except Exception as e:
            return report_unhandled_error(e)

    @expose('json')
    def put(self, project=None, user=None):
        if not project or not user:
            abort(400)
        inp = request.json if request.content_length else {}
        if 'groups' not in inp:
            abort(400)
        if '@' not in user:
            response.status = 400
            return "User must be identified by its email address"
        requestor = request.remote_user
        project = _decode_project_name(project)
        try:
            # Add/update user for the project groups
            for service in SF_SERVICES:
                try:
                    service.membership.create(requestor, user,
                                              project, inp['groups'])
                except exceptions.UnavailableActionError:
                    msg = '[%s] membership creation is not an available action'
                    logger.debug(msg % service.service_name)
            response.status = 201
            return "User %s has been added in group(s): %s for project %s" % \
                (user, ", ".join(inp['groups']), project)
        except Exception as e:
            return report_unhandled_error(e)

    @expose('json')
    def delete(self, project=None, user=None, group=None):
        if not project or not user:
            abort(400)
        if '@' not in user:
            response.status = 400
            return "User must be identified by its email address"
        requestor = request.remote_user
        project = _decode_project_name(project)
        try:
            # delete user from all project groups
            for service in SF_SERVICES:
                try:
                    service.membership.delete(requestor, user, project, group)
                except exceptions.UnavailableActionError:
                    msg = '[%s] membership deletion is not an available action'
                    logger.debug(msg % service.service_name)
            response.status = 200
            if group:
                return ("User %s has been deleted from group %s " +
                        "for project %s.") % (user, group, project)
            else:
                return ("User %s has been deleted from all groups " +
                        "for project %s.") % (user, project)
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

        # TODO(mhu) this must be independent from gerrit
        code_review = [s for s in SF_SERVICES
                       if isinstance(s, base.BaseCodeReviewServicePlugin)][0]
        for p in code_review.project.get():
            projects[p] = {'open_reviews': 0,
                           'open_issues': 0,
                           'admin': 0,
                           'groups': {}}
            groups = code_review.project.get_groups(p)
            for group in groups:
                if group['name'].endswith(('-ptl', '-core', '-dev')):
                    grp = group['name'].split('-')[-1]
                    projects[p]['groups'][grp] = group

        requestor = request.remote_user
        for p in code_review.project.get(requestor=requestor,
                                         by_user=True):
            projects[p]['admin'] = 1

        # This is okay here :)
        tracker = [s for s in SF_SERVICES
                   if isinstance(s, base.BaseIssueTrackerServicePlugin)][0]
        for issue in tracker.get_open_issues().get('issues'):
            prj = issue.get('project').get('name')
            if prj in projects:
                projects[prj]['open_issues'] += 1

        for review in code_review.review.get():
            prj = review.get('project')
            if prj in projects:
                projects[prj]['open_reviews'] += 1

        self.set_cache(projects)

    @expose('json')
    def get_all(self):
        projects = self.get_cache()
        if projects:
            return projects

        self._reload_cache()
        return self.get_cache()

    def _find_project(self, name):
        cache = self.get_cache()
        if not cache:
            self._reload_cache()
            cache = self.get_cache()

        return cache.get(name)

    @expose('json')
    def get_one(self, project_id):
        name = _decode_project_name(project_id)
        project = self._find_project(name)
        if not project:
            logger.exception("Project %s does not exists" % project_id)
            return abort(400)
        return project

    @expose('json')
    def put(self, name):
        if getattr(conf, "project_create_administrator_only", True):
            if not is_admin(request.remote_user):
                abort(401)

        if not name:
            logger.exception("Project name required")
            abort(400)

        name = _decode_project_name(name)
        project = self._find_project(name)
        if project:
            logger.exception("Project %s already exists" % name)
            abort(400)
        try:
            # create project
            inp = request.json if request.content_length else {}
            user = request.remote_user
            for gn in ('ptl-group-members', 'core-group-members',
                       'dev-group-members'):
                for u in inp.get(gn, []):
                    if '@' not in u:
                        response.status = 400
                        return "User must be identified by its email address"

            # Early check of upstream availability
            if 'upstream' in inp:
                ssh_key = None
                if 'upstream-ssh-key' in inp:
                    ssh_key = inp['upstream-ssh-key']
                success, msg = gerrit.utils.GerritRepo.check_upstream(
                    inp["upstream"], ssh_key)
                if not success:
                    response.status = 400
                    return msg

            for service in SF_SERVICES:
                try:
                    service.project.create(name, user, inp)
                except exceptions.UnavailableActionError:
                    msg = '[%s] project creation is not an available action'
                    logger.debug(msg % service.service_name)
            response.status = 201
            self.set_cache(None)
            return "Project %s has been created." % name
        except Exception as e:
            return report_unhandled_error(e)

    @expose('json')
    def delete(self, name):
        name = _decode_project_name(name)
        project = self._find_project(name)
        if name == 'config':
            response.status = 400
            return "Deletion of config project denied"
        if not project:
            logger.exception("Project %s does not exist" % name)
            abort(400)
        user = request.remote_user
        try:
            # delete project
            for service in SF_SERVICES:
                try:
                    service.project.delete(name, user)
                except exceptions.UnavailableActionError:
                    msg = '[%s] project deletion is not an available action'
                    logger.debug(msg % service.service_name)
            response.status = 200
            self.set_cache(None)
            return "Project %s has been deleted." % name
        except Exception as e:
            return report_unhandled_error(e)


class PagesController(RestController):

    @expose('json')
    def post(self, project):
        if request.remote_user is None:
            abort(403)
        user = request.remote_user
        code_review = [s for s in SF_SERVICES
                       if isinstance(s, base.BaseCodeReviewServicePlugin)][0]
        if not code_review.project.user_owns_project(request.remote_user,
                                                     project):
            abort(403, detail="You are not the project owner")
        infos = request.json if request.content_length else {}
        try:
            ret = pages.update_content_url(project, infos)
        except pages.InvalidInfosInput as e:
            abort(400, detail=e.message)
        except pages.PageNotFound as e:
            abort(404, detail=e.message)
        except Exception as e:
            return report_unhandled_error(e)
        if ret:
            retmsg = "The pages target has been created for project %s" \
                     % project
            response.status = 201
        else:
            retmsg = "The pages target has been updated for project %s" \
                     % project
        logger.info("User %s has modified the pages target for project %s" % (
                    user, project))
        return retmsg

    @expose('json')
    def get(self, project):
        if request.remote_user is None:
            abort(403)
        code_review = [s for s in SF_SERVICES
                       if isinstance(s, base.BaseCodeReviewServicePlugin)][0]
        if not code_review.project.user_owns_project(request.remote_user,
                                                     project):
            abort(403, detail="You are not the project owner")
        try:
            ret = pages.get_content_url(project)
        except pages.PageNotFound as e:
            abort(404, detail=e.message)
        except Exception as e:
            return report_unhandled_error(e)
        return ret

    @expose('json')
    def delete(self, project):
        if request.remote_user is None:
            abort(403)
        user = request.remote_user
        code_review = [s for s in SF_SERVICES
                       if isinstance(s, base.BaseCodeReviewServicePlugin)][0]
        if not code_review.project.user_owns_project(request.remote_user,
                                                     project):
            abort(403, detail="You are not the project owner")
        try:
            pages.delete_content_url(project)
        except pages.PageNotFound as e:
            abort(404, detail=e.message)
        except Exception as e:
            return report_unhandled_error(e)
        logger.info("User %s has deleted the pages target for project %s" % (
                    user, project))
        return "The pages target has been deleted for project %s" % project


class LocalUserController(RestController):

    @expose('json')
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

    @expose('json')
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

    @expose('json')
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

    @expose('json')
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


class ServicesUsersController(RestController):

    @expose()
    def post(self):
        if not is_admin(request.remote_user):
            abort(401,
                  detail='Adding users is limited to administrators')
        infos = request.json if request.content_length else {}
        if not infos or not infos.get('username'):
            abort(400, detail='Incomplete user information: %r' % infos)
        try:
            for service in SF_SERVICES:
                try:
                    if service.user.get(username=infos.get('username')) or\
                       service.user.get(username=infos.get('email')):
                        msg = '[%s] user %s exists, skipping creation'
                        logger.debug(msg % (service.service_name,
                                            infos.get('username')))
                        continue
                    service.user.create(username=infos.get('username'),
                                        email=infos.get('email'),
                                        full_name=infos.get('full_name'),
                                        ssh_keys=infos.get('ssh_keys', []))
                except exceptions.UnavailableActionError:
                    msg = '[%s] service has no authenticated user backend'
                    logger.debug(msg % service.service_name)
        except Exception as e:
            return report_unhandled_error(e)
        response.status = 201

    @expose('json')
    def get(self, **kwargs):
        # Allowed for all authenticated users
        if request.remote_user is None:
            abort(403)
        # TODO(mhu) this must be independent from redmine
        tracker = [s for s in SF_SERVICES
                   if isinstance(s, base.BaseIssueTrackerServicePlugin)][0]
        return tracker.user.get(email=kwargs.get('email'),
                                username=kwargs.get('username'))

    @expose()
    def delete(self, email=None, username=None):
        if not is_admin(request.remote_user):
            abort(401,
                  detail='Deleting users is limited to administrators')
        try:
            for service in SF_SERVICES:
                try:
                    service.user.delete(email=email, username=username)
                except exceptions.UnavailableActionError:
                    msg = '[%s] service has no authenticated user backend'
                    logger.debug(msg % service.service_name)
        except Exception as e:
            return report_unhandled_error(e)
        response.status = 204


class HtpasswdController(RestController):
    def __init__(self):
        self.htp = htp.Htpasswd(conf)

    @expose('json')
    def put(self):
        if request.remote_user is None:
            abort(403)
        try:
            password = self.htp.set_api_password(request.remote_user)
        except IOError:
            abort(406)
        response.status = 201
        return password

    @expose('json')
    def get(self):
        if request.remote_user is None:
            abort(403)
        response.status = 404
        try:
            if self.htp.user_has_api_password(request.remote_user):
                response.status = 204
        except IOError:
            abort(406)

    @expose('json')
    def delete(self):
        if request.remote_user is None:
            abort(403)
        try:
            self.htp.delete(request.remote_user)
            response.status = 204
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

    @expose('json')
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

    @expose('json')
    def get(self, name):
        if request.remote_user is None:
            abort(403)

        conf = self._read_sshconfig(self.filename)

        return conf

    @expose('json')
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
        response.status = 204


class HooksController(RestController):

    @expose('json')
    def post(self, hook_name, service_name=None):
        """Trigger hook {hook_name} across all services. If {service_name}
        is set, trigger the hook only for that service."""
        # TODO: maybe we should have a specific user defined to run hooks
        if request.remote_user is None:
            abort(403)
        d = request.json if request.content_length else {}
        hooks_feedback = {}
        unavailable_hooks = 0
        return_code = 200
        if service_name:
            services = [i for i in SF_SERVICES
                        if i.service_name == service_name]
        else:
            services = SF_SERVICES
        if not services:
            return_code = 404
            response.status = return_code
            hooks_feedback['hook_name'] = hook_name
            hooks_feedback[service_name] = 'Unknown service'
            return hooks_feedback
        for s in services:
            try:
                hooks_feedback[s.service_name] = getattr(s.hooks,
                                                         hook_name)(**d)
            except exceptions.UnavailableActionError as e:
                hooks_feedback[s.service_name] = e.message
                unavailable_hooks += 1
                logger.debug('[%s] hook %s is not defined' % (s.service_name,
                                                              hook_name))
            except Exception as e:
                hooks_feedback[s.service_name] = e.message
                return_code = 400
                msg = '[%s] hook %s failed with error: %s'
                logger.debug(msg % (s.service_name,
                                    hook_name,
                                    e.message))
        if len(SF_SERVICES) == unavailable_hooks:
            return_code = 404
        response.status = return_code
        hooks_feedback['hook_name'] = hook_name
        return hooks_feedback


class TestsController(RestController):

    @expose('json')
    def put(self, project_name=''):
        if request.remote_user is None:
            abort(403)
        # TODO(mhu) this must be independent from gerrit
        code_review = [s for s in SF_SERVICES
                       if isinstance(s, base.BaseCodeReviewServicePlugin)][0]
        if not code_review.project.get(project_name=project_name):
            abort(404)

        try:
            msg = 'Configuring job pipelines for project %s'
            logger.debug(msg % project_name)
            code_review.review.propose_test_definition(project_name,
                                                       request.remote_user)
        except Exception as e:
            abort(500, detail=e.message)
        if request.json:
            project_scripts = request.json.get('project-scripts', False)

        if project_scripts:
            try:
                msg = 'Adding tests to config for project %s'
                logger.debug(msg % project_name)
                code_review.review.propose_test_scripts(project_name,
                                                        request.remote_user)
            except Exception as e:
                abort(500, detail=e.message)

        response.status = 201
        return True


class ConfigController(RestController):
    @expose('json')
    def get(self):
        permissions = {}
        user = request.remote_user
        admin = is_admin(user)
        admin_only = bool(getattr(conf, 'project_create_administrator_only',
                                  True))
        if not admin and admin_only:
            permissions['create_projects'] = False
        else:
            permissions['create_projects'] = True
        return permissions

load_services()


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
    services_users = ServicesUsersController()
    hooks = HooksController()
    config = ConfigController()
    pages = PagesController()
