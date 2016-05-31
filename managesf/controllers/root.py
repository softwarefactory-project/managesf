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
import urllib
import logging
import os.path

from pecan import conf
from pecan import expose
from pecan import abort
from pecan.rest import RestController
from pecan import request, response
from stevedore import driver

from managesf.controllers.decorators import admin_login_required
from managesf.controllers.decorators import user_login_required
from managesf.controllers import backup, localuser, introspection, htp, pages
from managesf.controllers import SFuser
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
DEFAULT_SERVICES = ['SFGerrit', 'SFRedmine', 'SFStoryboard', 'jenkins']


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


class SFManager:
    user = SFuser.SFUserManager()


sfmanager = SFManager()


def is_admin(user):
    return base.RoleManager.is_admin(user)


def report_unhandled_error(exp):
    logger.exception(LOGERRORMSG % str(exp))
    response.status = 500
    return CLIENTERRORMSG % str(exp)


class BackupController(RestController):
    @expose('json')
    @admin_login_required
    def get(self):
        filepath = os.path.join(conf.managesf.get('backup_dir',
                                                  '/var/www/managesf/'),
                                'sf_backup.tar.gz')
        if not os.path.isfile(filepath):
            abort(404)
        response.body_file = open(filepath, 'rb')
        return response

    @expose('json')
    @admin_login_required
    def post(self):
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
    @admin_login_required
    def post(self):
        filepath = os.path.join(conf.managesf.get('backup_dir',
                                                  '/var/www/managesf/'),
                                'sf_backup.tar.gz')
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
        return [(x['username'], x['email'], x['fullname'])
                for x in sfmanager.user.all()]

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
        """ Build the cache. This is done by requesting services
        API.
        """
        projects = {}

        # TODO(mhu) this must be independent from gerrit
        code_review = [s for s in SF_SERVICES
                       if isinstance(s, base.BaseCodeReviewServicePlugin)][0]
        requestor = request.remote_user

        # Get my groups (1 request)
        my_groups = code_review.project.get_user_groups(requestor)
        my_groups_id = [g['id'] for g in my_groups]

        # Get the list of projects (1 request)
        projects_list = code_review.project.get()

        # Initiate resp struct by project name
        for p in projects_list:
            projects[p] = {'open_reviews': 0,
                           'open_issues': 0,
                           'admin': 0,
                           'groups': {}}

        # Get list of groups of projects (1 request)
        # This returns all groups id of projects as well as the owner groups
        projects_groups = code_review.project.get_projects_groups_id(
            projects_list)

        # Consult requestor groups list and define projects with admin rights
        # for the requestor
        for p in projects_list:
            # Verify that group is one of those owned by the requestor
            for gid in my_groups_id:
                if gid in projects_groups[p]['owners']:
                    projects[p]['admin'] = 1

        # Filter can be done by name but not by id. So request the full
        # list of groups + members details (1 request)
        all_groups_details = code_review.project.get_groups_details([])

        # Fill group details for projects where user is admin
        for p in projects_list:
            if projects[p]['admin'] == 1:
                pg_ids = projects_groups[p]['owners'] + \
                    projects_groups[p]['others']
                for group_name, details in all_groups_details.items():
                    if details['id'] in pg_ids:
                        if group_name.endswith(('-ptl', '-core', '-dev')):
                            group_type = group_name.split('-')[-1]
                            projects[p]['groups'][group_type] = details

        # This is okay here :)
        tracker = [s for s in SF_SERVICES
                   if isinstance(s, base.BaseIssueTrackerServicePlugin)][0]
        # 1 or more requests (depends on the amount of issue and pagination
        for issue in tracker.get_open_issues().get('issues'):
            prj = issue.get('project').get('name')
            if prj in projects:
                projects[prj]['open_issues'] += 1

        # Done in 1 requests
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


class GroupController(RestController):

    def sort_services(self):
        sorted_services = [s for s in SF_SERVICES
                           if isinstance(s, base.BaseCodeReviewServicePlugin)]
        for service in SF_SERVICES:
            if not isinstance(service,
                              base.BaseCodeReviewServicePlugin):
                sorted_services.append(service)
        return sorted_services

    def check_authorized(self, groupname):
        # Abort and return Forbidden if requestor is not part of
        # of the group.
        user_email = sfmanager.user.get(
            username=request.remote_user).get('email')
        ex_members = self.get(groupname)[groupname]
        if user_email not in [user['email'] for user in ex_members]:
            abort(403, "Requestor is not part of %s" % groupname)

    @user_login_required
    @expose()
    def put(self, groupname):
        groupname = urllib.unquote_plus(groupname)
        infos = request.json if request.content_length else {}
        desc = infos.get('description', None)
        # Force action to be executed on Gerrit first
        sorted_services = self.sort_services()
        # Fetch requestor email
        user_email = sfmanager.user.get(
            username=request.remote_user).get('email')
        for service in sorted_services:
            try:
                if hasattr(service, "group"):
                    service.group.create(groupname, user_email, desc)
            except exceptions.UnavailableActionError:
                msg = '[%s] group create is not an available action'
                logger.debug(msg % service.service_name)
            except exceptions.CreateGroupException, e:
                # Gerrit is the reference, abort if the group
                # can't be create in Gerrit
                if isinstance(service,
                              base.BaseCodeReviewServicePlugin):
                    abort(409, detail=e.message)
                else:
                    # For other services just warn via logs
                    logger.info("group %s create on %s was unsuccessful" % (
                                groupname, service))
            except Exception as e:
                return report_unhandled_error(e)
            response.status = 201

    @user_login_required
    @expose()
    def post(self, groupname):
        groupname = urllib.unquote_plus(groupname)
        infos = request.json if request.content_length else {}
        members = infos.get("members", [])
        # Force action to be executed on Gerrit first
        sorted_services = self.sort_services()

        # Be sure the user is part of that group
        self.check_authorized(groupname)

        for service in sorted_services:
            try:
                if hasattr(service, "group"):
                        service.group.update(groupname, members)
            except exceptions.UnavailableActionError:
                msg = '[%s] group update is not an available action'
                logger.debug(msg % service.service_name)
            except (exceptions.UpdateGroupException,
                    exceptions.GroupNotFoundException), e:
                # Gerrit is the reference, abort if the group
                # can't be updated in Gerrit
                if isinstance(service,
                              base.BaseCodeReviewServicePlugin):
                    abort(404, detail=e.message)
                else:
                    # For other services just warn via logs
                    logger.info("group %s post on %s was unsuccessful" % (
                                groupname, service))
            except Exception as e:
                return report_unhandled_error(e)

    @user_login_required
    @expose('json')
    def get(self, groupname):
        if groupname:
            groupname = urllib.unquote_plus(groupname)
        for service in SF_SERVICES:
            try:
                if isinstance(service,
                              base.BaseCodeReviewServicePlugin):
                    return service.group.get(groupname)
            except exceptions.UnavailableActionError:
                msg = '[%s] group get is not an available action'
                logger.debug(msg % service.service_name)
            except exceptions.GroupNotFoundException, e:
                abort(404, detail=e.message)
            except Exception as e:
                return report_unhandled_error(e)

    @user_login_required
    @expose('json')
    def get_all(self):
        return self.get(None)

    @user_login_required
    @expose()
    def delete(self, groupname):
        groupname = urllib.unquote_plus(groupname)
        # Force action to be executed on Gerrit first
        sorted_services = self.sort_services()

        # Be sure the user is part of that group
        self.check_authorized(groupname)

        for service in sorted_services:
            try:
                if isinstance(service,
                              base.BaseCodeReviewServicePlugin):
                    service.group.get(groupname)
                    service.role.delete(groupname)
                else:
                    if hasattr(service, "group"):
                        service.group.delete(groupname)
            except exceptions.GroupNotFoundException, e:
                if isinstance(service,
                              base.BaseCodeReviewServicePlugin):
                    # Abort if action not possible on Gerrit
                    abort(404, detail=e.message)
                else:
                    # For other services just warn via logs
                    logger.info("group %s delete on %s was unsuccessful" % (
                                groupname, service))
            except exceptions.UnavailableActionError:
                msg = '[%s] group delete is not an available action'
                logger.debug(msg % service.service_name)
            except Exception as e:
                return report_unhandled_error(e)


class PagesController(RestController):

    @expose('json')
    @user_login_required
    def post(self, project):
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
    @user_login_required
    def get(self, project):
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
    @user_login_required
    def delete(self, project):
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
    @user_login_required
    def post(self, username):
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
    @user_login_required
    def get(self, username):
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
    @user_login_required
    def delete(self, username):
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

    def _remove_non_updatable_fields(self, infos):
        forbidden = sum([s.user.check_forbidden_fields(**infos)
                         for s in SF_SERVICES], [])
        msg = 'The following fields cannot be updated: %s, discarding them'
        logger.debug(msg % str(forbidden))
        return dict((u, infos[u]) for u in infos.keys()
                    if u not in forbidden and infos[u])

    def _update(self, user_id, infos):
        sfmanager.user.update(user_id,
                              username=infos.get('username'),
                              email=infos.get('email'),
                              fullname=infos.get('full_name'))
        for service in SF_SERVICES:
            s_id = sfmanager.user.mapping.get_service_mapping(
                service.service_name,
                user_id)
            if s_id:
                try:
                    service.user.update(uid=s_id, **infos)
                except exceptions.UnavailableActionError as e:
                    logger.debug(e)
            else:
                full_name = infos.get('full_name')
                username = infos.get('username')
                ssh_keys = infos.get('ssh_keys', [])
                email = infos.get('email')
                try:
                    s_id = service.user.create(username=username,
                                               email=email,
                                               full_name=full_name,
                                               ssh_keys=ssh_keys,
                                               cauth_id=user_id)
                    sfmanager.user.mapping.set(user_id,
                                               service.service_name,
                                               s_id)
                except exceptions.UnavailableActionError:
                    msg = '[%s] has no authenticated user backend'
                    logger.debug(msg % service.service_name)

    @expose('json')
    def put(self, id=None, email=None, username=None):
        infos = request.json if request.content_length else {}
        # the JSON payload is only for data to update.
        _email = request.GET.get('email')
        _username = request.GET.get('username')
        d_id = request.GET.get('id')
        if not d_id and (_email or _username):
            logger.debug('[update] looking for %s %s ...' % (_email,
                                                             _username))
            d_id = sfmanager.user.get(username=_username,
                                      email=_email).get('id')
            logger.debug('found %s %s with id %s' % (_email, _username, d_id))
        if not d_id:
            response.status = 404
            return
        u = _username or sfmanager.user.get(d_id).get('username')
        if not (is_admin(request.remote_user) or
                u == request.remote_user):
            abort(401,
                  detail='Updates only allowed by self or administrator')
        sanitized = self._remove_non_updatable_fields(infos)
        logger.debug('[update] sanitized request %r to %r' % (infos,
                                                              sanitized))
        if not sanitized:
            if sanitized != infos:
                msg = 'You tried to update immutable fields'
            else:
                msg = 'Nothing to do'
            abort(400,
                  detail=msg)
        try:
            self._update(d_id, sanitized)
            response.status = 200
            return {'updated_fields': sanitized}
        except Exception as e:
            return report_unhandled_error(e)

    @expose('json')
    @admin_login_required
    def post(self):
        infos = request.json if request.content_length else {}
        if not infos or not infos.get('username'):
            abort(400, detail=u'Incomplete user information: %r' % infos)
        try:
            # In this version we cannot lookup just with cauth_id
            known_user = sfmanager.user.get(username=infos['username'],
                                            email=infos['email'],
                                            fullname=infos['full_name'])
            # if we have this user and a bogus cauth_id, update it
            if known_user:
                msg = u'found user #%(id)s %(username)s (%(email)s)'
                logger.debug(msg % known_user)
                e_id = infos.get('external_id')
                if e_id and int(e_id) != int(known_user['cauth_id']):
                    logger.debug('Update cauth ID - This is normal if'
                                 'cauth was reinitialized')
                    sfmanager.user.reset_cauth_id(known_user['id'],
                                                  e_id)
                u = known_user['id']
                clean_infos = self._remove_non_updatable_fields(infos)
                self._update(u, clean_infos)
            # maybe we know this user by cauth_id but her details changed
            elif not known_user and infos.get('external_id', -1) != -1:
                known_user = sfmanager.user.get(cauth_id=infos['external_id'])
                if known_user:
                    msg = (u'found user #%(id)s %(username)s (%(email)s) '
                           u'by cauth ID #%(cauth_id)s, user needs update')
                    logger.debug(msg % known_user)
                    u = known_user['id']
                    clean_infos = self._remove_non_updatable_fields(infos)
                    self._update(u, clean_infos)
            # if we still cannot find it, let's create it
            if not known_user:
                u = sfmanager.user.create(username=infos['username'],
                                          email=infos['email'],
                                          fullname=infos['full_name'],
                                          cauth_id=infos.get('external_id'))
                self._create_user_in_services(u, infos)
        except Exception as e:
            return report_unhandled_error(e)
        # TODO(mhu) later, this should return the local id and the user data
        response.status = 201

    def _create_user_in_services(self, user_id, infos):
        for service in SF_SERVICES:
            try:
                s_id = (service.user.get(username=infos.get('username')) or
                        service.user.get(username=infos.get('email')))
                if s_id:
                    msg = u'[%s] user %s exists, skipping creation'
                    logger.debug(msg % (service.service_name,
                                        infos.get('username')))
                    mapped = sfmanager.user.mapping.get_user_mapping(
                        service.service_name,
                        s_id)
                    if not mapped:
                        sfmanager.user.mapping.set(user_id,
                                                   service.service_name,
                                                   s_id)
                        msg = u'[%s] user %s mapped to id %s'
                        logger.debug(msg % (service.service_name,
                                            infos.get('username'),
                                            s_id))
                else:
                    full_name = infos.get('full_name')
                    username = infos.get('username')
                    ssh_keys = infos.get('ssh_keys', [])
                    email = infos.get('email')
                    s_id = service.user.create(username=username,
                                               email=email,
                                               full_name=full_name,
                                               ssh_keys=ssh_keys,
                                               cauth_id=user_id)
                    # we might have a mapping, but to a wrong user id in the
                    # service (because the user existed before but was removed
                    # directly from the service, for example)
                    mapped = sfmanager.user.mapping.get_service_mapping(
                        service.service_name,
                        user_id)
                    if mapped and mapped != s_id:
                        msg = u'[%s] user %s wrongly mapped to id %s, removing'
                        logger.debug(msg % (service.service_name,
                                            infos.get('username'),
                                            mapped))
                        sfmanager.user.mapping.delete(user_id,
                                                      service.service_name,
                                                      mapped)
                    sfmanager.user.mapping.set(user_id,
                                               service.service_name,
                                               s_id)
                    msg = u'[%s] user %s mapped to %s id %s'
                    logger.debug(msg % (service.service_name,
                                        infos.get('username'),
                                        service.service_name,
                                        s_id))
            except exceptions.UnavailableActionError:
                msg = '[%s] service has no authenticated user backend'
                logger.debug(msg % service.service_name)

    @expose('json')
    @user_login_required
    def get(self, **kwargs):
        return sfmanager.user.get(**kwargs)

    @expose()
    @admin_login_required
    def delete(self, id=None, email=None, username=None):
        d_id = id
        if not d_id and (email or username):
            logger.debug(u'[delete] looking for %s %s' % (email, username))
            d_id = sfmanager.user.get(username=username,
                                      email=email).get('id')
        if not d_id:
            response.status = 404
            return
        logger.debug(u'found %s %s with id %s' % (email, username, d_id))
        try:
            for service in SF_SERVICES:
                try:
                    service.user.delete(email=email, username=username)
                    sfmanager.user.mapping.delete(d_id,
                                                  service.service_name)
                except exceptions.UnavailableActionError:
                    msg = '[%s] service has no authenticated user backend'
                    logger.debug(msg % service.service_name)
            sfmanager.user.delete(id=d_id)
        except Exception as e:
            return report_unhandled_error(e)
        response.status = 204


class HtpasswdController(RestController):
    def __init__(self):
        self.htp = htp.Htpasswd(conf)

    @expose('json')
    @user_login_required
    def put(self):
        try:
            password = self.htp.set_api_password(request.remote_user)
        except IOError:
            abort(406)
        response.status = 201
        return password

    @expose('json')
    @user_login_required
    def get(self):
        response.status = 404
        try:
            if self.htp.user_has_api_password(request.remote_user):
                response.status = 204
        except IOError:
            abort(406)

    @expose('json')
    @user_login_required
    def delete(self):
        try:
            self.htp.delete(request.remote_user)
            response.status = 204
        except IOError:
            abort(406)


class HooksController(RestController):

    @expose('json')
    @user_login_required
    def post(self, hook_name, service_name=None):
        """Trigger hook {hook_name} across all services. If {service_name}
        is set, trigger the hook only for that service."""
        # TODO: maybe we should have a specific user defined to run hooks
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
    @user_login_required
    def put(self, project_name=''):
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
    backup = BackupController()
    restore = RestoreController()
    user = LocalUserController()
    bind = LocalUserBindController()
    group = GroupController()
    htpasswd = HtpasswdController()
    about = introspection.IntrospectionController()
    tests = TestsController()
    services_users = ServicesUsersController()
    hooks = HooksController()
    config = ConfigController()
    pages = PagesController()
