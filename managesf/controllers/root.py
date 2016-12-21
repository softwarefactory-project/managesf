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

from managesf.controllers import backup, localuser, introspection, htp, pages
from managesf.controllers import SFuser
from managesf.services import base, gerrit
from managesf.services import exceptions
from managesf import policy
from managesf.model.yamlbkd.engine import SFResourceBackendEngine


logger = logging.getLogger(__name__)

LOGERRORMSG = "Unable to process client request, failed with "\
              "unhandled error: %s"
CLIENTERRORMSG = "Unable to process your request, failed with "\
                 "unhandled error (server side): %s"

# TODO: add detail (detail arg or abort function) for all abort calls.


# instanciate service plugins
SF_SERVICES = []
DEFAULT_SERVICES = ['SFGerrit', 'SFRedmine', 'SFStoryboard', 'SFJenkins']


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


def authorize(rule_name, target):
    if not request.remote_user:
        request.remote_user = request.headers.get('X-Remote-User')
    credentials = {'username': request.remote_user, 'groups': []}
    # TODO(mhu) this must be independent from gerrit
    if request.remote_user:
        code_review = [s for s in SF_SERVICES
                       if isinstance(s, base.BaseCodeReviewServicePlugin)][0]
        user_groups = code_review.project.get_user_groups(request.remote_user)
        credentials['groups'] = [grp['name'] for grp in user_groups]
    return policy.authorize(rule_name, target, credentials)


class BackupController(RestController):
    @expose('json')
    def get(self):
        _policy = 'managesf.backup:get'
        if not authorize(_policy,
                         target={}):
            return abort(401,
                         detail='Failure to comply with policy %s' % _policy)
        filepath = os.path.join(conf.managesf.get('backup_dir',
                                                  '/var/www/managesf/'),
                                'sf_backup.tar.gz')
        if not os.path.isfile(filepath):
            abort(404)
        response.body_file = open(filepath, 'rb')
        return response

    @expose('json')
    def post(self):
        _policy = 'managesf.backup:create'
        if not authorize(_policy,
                         target={}):
            return abort(401,
                         detail='Failure to comply with policy %s' % _policy)
        try:
            backup.backup_start()
            response.status = 204
        except Exception as e:
            return report_unhandled_error(e)


class MembershipController(RestController):
    @expose('json')
    def get(self):
        # TODO this doesn't do what it is expected
        _policy = 'managesf.membership:get'
        if not authorize(_policy,
                         target={}):
            return abort(401,
                         detail='Failure to comply with policy %s' % _policy)
        return [(x['username'], x['email'], x['fullname'])
                for x in sfmanager.user.all()]

    @expose('json')
    def put(self, project=None, user=None):
        _policy = 'managesf.membership:create'
        if not project or not user:
            msg = "Missing project (%s) or user (%s)" % (project,
                                                         user)
            logger.exception(msg)
            abort(400,
                  detail=msg)

        project = _decode_project_name(project)
        if user:
            user = urllib.unquote_plus(user)
        inp = request.json if request.content_length else {}
        if 'groups' not in inp:
            abort(400)
        if not all(authorize(_policy,
                             target={'project': project,
                                     'user': user,
                                     'group': g}) for g in inp['groups']):
            return abort(401,
                         detail='Failure to comply with policy %s' % _policy)

        is_group = False
        # Check if user or group exists
        if not len(sfmanager.user.get(email=user).keys()):
            # User is unknown so check if it is a group
            code_review = [s for s in SF_SERVICES
                           if isinstance(s,
                                         base.BaseCodeReviewServicePlugin)][0]
            try:
                code_review.group.get(user, discard_pgroups=False)
                is_group = True
            except exceptions.GroupNotFoundException:
                abort(400, "The user or group to add wasn't found")
        requestor = request.remote_user
        try:
            # Add/update user for the project groups
            for service in SF_SERVICES:
                try:
                    service.membership.create(requestor, user,
                                              project, inp['groups'])
                except exceptions.UnavailableActionError:
                    pass
            response.status = 201
            return "%s %s has been added in group(s): %s for project %s" % \
                ("Group" if is_group else "User",
                 user, ", ".join(inp['groups']), project)
        except Exception as e:
            return report_unhandled_error(e)

    @expose('json')
    def delete(self, project=None, user=None, group=None):
        _policy = 'managesf.membership:delete'
        if not project or not user:
            logger.exception("Missing project (%s) or user (%)s" % (project,
                                                                    user))
            abort(400,
                  detail="Missing project (%s) or user (%s)" % (project,
                                                                user))

        project = _decode_project_name(project)
        if user:
            user = urllib.unquote_plus(user)
        if not group:
            grps = ['ptl-group',
                    'core-group',
                    'dev-group', ]
        else:
            grps = [group, ]
        if not all(authorize(_policy,
                             target={'project': project,
                                     'user': user,
                                     'group': g, }) for g in grps):
            return abort(401,
                         detail='Failure to comply with policy %s' % _policy)
        is_group = False
        # Check if user or group exists
        if not len(sfmanager.user.get(email=user).keys()):
            # User is unknown so check if it is a group
            code_review = [s for s in SF_SERVICES
                           if isinstance(s,
                                         base.BaseCodeReviewServicePlugin)][0]
            try:
                code_review.group.get(user, discard_pgroups=False)
                is_group = True
            except exceptions.GroupNotFoundException:
                abort(400, "The user or group to add wasn't found")
        requestor = request.remote_user
        try:
            # delete user from all project groups
            for service in SF_SERVICES:
                try:
                    service.membership.delete(requestor, user, project, group)
                except exceptions.UnavailableActionError:
                    pass
            response.status = 200
            if group:
                return ("%s %s has been deleted from group %s " +
                        "for project %s.") % (
                            "Group" if is_group else "User",
                            user, group, project)
            else:
                return ("%s %s has been deleted from all groups " +
                        "for project %s.") % (
                            "Group" if is_group else "User",
                            user, project)
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

        # Skip this if there is no issue tracker
        tracker = [s for s in SF_SERVICES
                   if isinstance(s, base.BaseIssueTrackerServicePlugin)]
        if tracker:
            tracker = tracker[0]
            # 1 or more requests (depends on issues and pagination)
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
        _policy = 'managesf.project:get_all'
        if not authorize(_policy,
                         target={}):
            return abort(401,
                         detail='Failure to comply with policy %s' % _policy)
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
        _policy = 'managesf.project:get_one'
        if not authorize(_policy,
                         target={}):
            return abort(401,
                         detail='Failure to comply with policy %s' % _policy)
        name = _decode_project_name(project_id)
        project = self._find_project(name)
        if not project:
            logger.exception("Project %s does not exists" % project_id)
            return abort(400)
        return project

    @expose('json')
    def put(self, name):
        _policy = 'managesf.project:create'

        if not name:
            logger.exception("Project name required")
            abort(400)

        name = _decode_project_name(name)
        if not authorize(_policy,
                         target={'project': name}):
            return abort(401,
                         detail='Failure to comply with policy %s' % _policy)
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
                    pass
            response.status = 201
            self.set_cache(None)
            return "Project %s has been created." % name
        except Exception as e:
            return report_unhandled_error(e)

    @expose('json')
    def delete(self, name):
        name = _decode_project_name(name)
        _policy = 'managesf.project:delete'
        if not authorize(_policy,
                         target={'project': name}):
            return abort(401,
                         detail='Failure to comply with policy %s' % _policy)
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
                    pass
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

    @expose()
    def put(self, groupname):
        # TODO put is usually update, post = create, this was mixed here
        _policy = 'managesf.group:create'
        groupname = urllib.unquote_plus(groupname)
        if not authorize(_policy,
                         target={'group': groupname}):
            return abort(401,
                         detail='Failure to comply with policy %s' % _policy)
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
                pass
            except exceptions.CreateGroupException, e:
                # Gerrit is the reference, abort if the group
                # can't be create in Gerrit
                if isinstance(service,
                              base.BaseCodeReviewServicePlugin):
                    abort(409, detail=unicode(e))
                else:
                    # For other services just warn via logs
                    logger.info("group %s create on %s was unsuccessful" % (
                                groupname, service))
            except Exception as e:
                return report_unhandled_error(e)
            response.status = 201

    @expose()
    def post(self, groupname):
        _policy = 'managesf.group:update'
        groupname = urllib.unquote_plus(groupname)
        if not authorize(_policy,
                         target={'group': groupname}):
            return abort(401,
                         detail='Failure to comply with policy %s' % _policy)
        infos = request.json if request.content_length else {}
        members = infos.get("members", [])
        # Force action to be executed on Gerrit first
        sorted_services = self.sort_services()

        for service in sorted_services:
            try:
                if hasattr(service, "group"):
                        service.group.update(groupname, members)
            except exceptions.UnavailableActionError:
                pass
            except (exceptions.UpdateGroupException,
                    exceptions.GroupNotFoundException), e:
                # Gerrit is the reference, abort if the group
                # can't be updated in Gerrit
                if isinstance(service,
                              base.BaseCodeReviewServicePlugin):
                    abort(404, detail=unicode(e))
                else:
                    # For other services just warn via logs
                    logger.info("group %s post on %s was unsuccessful" % (
                                groupname, service))
            except Exception as e:
                return report_unhandled_error(e)

    @expose('json')
    def get(self, groupname):
        _policy = 'managesf.group:get'
        target = {}
        if groupname:
            groupname = urllib.unquote_plus(groupname)
            target['group'] = groupname
        if not authorize(_policy,
                         target=target):
            return abort(401,
                         detail='Failure to comply with policy %s' % _policy)
        for service in SF_SERVICES:
            try:
                if isinstance(service,
                              base.BaseCodeReviewServicePlugin):
                    return service.group.get(groupname)
            except exceptions.UnavailableActionError:
                pass
            except exceptions.GroupNotFoundException, e:
                abort(404, detail=unicode(e))
            except Exception as e:
                return report_unhandled_error(e)

    @expose('json')
    def get_all(self):
        return self.get(None)

    @expose()
    def delete(self, groupname):
        _policy = 'managesf.group:delete'
        groupname = urllib.unquote_plus(groupname)
        if not authorize(_policy,
                         target={'group': groupname}):
            return abort(401,
                         detail='Failure to comply with policy %s' % _policy)
        # Force action to be executed on Gerrit first
        sorted_services = self.sort_services()

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
                    abort(404, detail=unicode(e))
                else:
                    # For other services just warn via logs
                    logger.info("group %s delete on %s was unsuccessful" % (
                                groupname, service))
            except exceptions.UnavailableActionError:
                pass
            except Exception as e:
                return report_unhandled_error(e)


class PagesController(RestController):

    @expose('json')
    def post(self, project):
        user = request.remote_user
        _policy = 'managesf.pages:create'
        if not project:
            logger.exception("Project name required")
            abort(400, detail="Project name required")

        project = _decode_project_name(project)
        if not authorize(_policy,
                         target={'project': project}):
            return abort(401,
                         detail='Failure to comply with policy %s' % _policy)
        infos = request.json if request.content_length else {}
        try:
            ret = pages.update_content_url(project, infos)
        except pages.InvalidInfosInput as e:
            abort(400, detail=unicode(e))
        except pages.PageNotFound as e:
            abort(404, detail=unicode(e))
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
        _policy = 'managesf.pages:get'
        if not project:
            logger.exception("Project name required")
            abort(400, detail="Project name required")

        project = _decode_project_name(project)
        if not authorize(_policy,
                         target={'project': project}):
            return abort(401,
                         detail='Failure to comply with policy %s' % _policy)
        try:
            ret = pages.get_content_url(project)
        except pages.PageNotFound as e:
            abort(404, detail=unicode(e))
        except Exception as e:
            return report_unhandled_error(e)
        return ret

    @expose('json')
    def delete(self, project):
        user = request.remote_user
        _policy = 'managesf.pages:delete'
        if not project:
            logger.exception("Project name required")
            abort(400, detail="Project name required")

        project = _decode_project_name(project)
        if not authorize(_policy,
                         target={'project': project}):
            return abort(401,
                         detail='Failure to comply with policy %s' % _policy)
        try:
            pages.delete_content_url(project)
        except pages.PageNotFound as e:
            abort(404, detail=unicode(e))
        except Exception as e:
            return report_unhandled_error(e)
        logger.info("User %s has deleted the pages target for project %s" % (
                    user, project))
        return "The pages target has been deleted for project %s" % project


class LocalUserController(RestController):

    @expose('json')
    def post(self, username):
        _policy = 'managesf.localuser:create_update'
        if not authorize(_policy,
                         target={'username': username}):
            return abort(401,
                         detail='Failure to comply with policy %s' % _policy)
        infos = request.json if request.content_length else {}
        try:
            ret = localuser.update_user(username, infos)
        except (localuser.InvalidInfosInput, localuser.BadUserInfos) as e:
            abort(400, detail=unicode(e))
        except Exception as e:
            return report_unhandled_error(e)
        if isinstance(ret, dict):
            # user created - set correct status code
            response.status = 201
        return ret

    @expose('json')
    def get(self, username):
        _policy = 'managesf.localuser:get'
        if not authorize(_policy,
                         target={'username': username}):
            return abort(401,
                         detail='Failure to comply with policy %s' % _policy)
        try:
            ret = localuser.get_user(username)
        except localuser.UserNotFound as e:
            abort(404, detail=unicode(e))
        except Exception as e:
            return report_unhandled_error(e)
        return ret

    @expose('json')
    def delete(self, username):
        _policy = 'managesf.localuser:delete'
        if not authorize(_policy,
                         target={'username': username}):
            return abort(401,
                         detail='Failure to comply with policy %s' % _policy)
        try:
            ret = localuser.delete_user(username)
        except localuser.UserNotFound as e:
            abort(404, detail=unicode(e))
        except Exception as e:
            return report_unhandled_error(e)
        return ret


class LocalUserBindController(RestController):

    @expose('json')
    def get(self):
        _policy = 'managesf.localuser:bind'
        authorization = request.headers.get('Authorization', None)
        if not authorization:
            abort(401, detail="Authentication header missing")
        try:
            username, password = localuser.decode(authorization)
            username = unicode(username, encoding='utf8')
        except localuser.DecodeError:
            abort(401, detail="Wrong authorization header")
        if not authorize(_policy,
                         target={'username': username}):
            return abort(401,
                         detail='Failure to comply with policy %s' % _policy)

        try:
            ret = localuser.bind_user(authorization)
        except (localuser.BindForbidden, localuser.UserNotFound) as e:
            abort(401, detail=unicode(e))
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
                    if u not in forbidden and infos[u] is not None)

    def _update(self, user_id, infos):
        sfmanager.user.update(user_id,
                              username=infos.get('username'),
                              email=infos.get('email'),
                              fullname=infos.get('full_name'),
                              idp_sync=infos.get('idp_sync'))
        for service in SF_SERVICES:
            s_id = sfmanager.user.mapping.get_service_mapping(
                service.service_name,
                user_id)
            if s_id:
                try:
                    service.user.update(uid=s_id, **infos)
                except exceptions.UnavailableActionError:
                    pass
            else:
                full_name = infos.get('full_name')
                username = infos.get('username')
                ssh_keys = infos.get('ssh_keys', [])
                email = infos.get('email')
                cauth_id = infos.get('external_id')
                try:
                    s_id = service.user.create(username=username,
                                               email=email,
                                               full_name=full_name,
                                               ssh_keys=ssh_keys,
                                               cauth_id=cauth_id)
                    sfmanager.user.mapping.set(user_id,
                                               service.service_name,
                                               s_id)
                except exceptions.UnavailableActionError:
                    pass

    @expose('json')
    def put(self, id=None, email=None, username=None):
        _policy = 'managesf.user:update'
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
        if not authorize(_policy,
                         target={'username': u}):
            return abort(401,
                         detail='Failure to comply with policy %s' % _policy)
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
    def post(self):
        _policy = 'managesf.user:create'
        infos = request.json if request.content_length else {}
        if not infos or not infos.get('username'):
            abort(400, detail=u'Incomplete user information: %r' % infos)
        if not authorize(_policy,
                         target={'username': infos.get('username')}):
            return abort(401,
                         detail='Failure to comply with policy %s' % _policy)
        try:
            known_user = None
            if infos.get('external_id', -1) != -1:
                known_user = sfmanager.user.get(cauth_id=infos['external_id'])
                if known_user:
                    msg = (u'found user #%(id)s %(username)s (%(email)s) '
                           u'by cauth ID #%(cauth_id)s, user needs update')
                    logger.debug(msg % known_user)
                    u = known_user['id']
                    clean_infos = self._remove_non_updatable_fields(infos)
                    if known_user.get('idp_sync'):
                        self._update(u, clean_infos)
                    else:
                        logger.info("Skipping user information update because"
                                    "idp_sync is disabled")
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
                    cauth_id = infos.get('external_id')
                    s_id = service.user.create(username=username,
                                               email=email,
                                               full_name=full_name,
                                               ssh_keys=ssh_keys,
                                               cauth_id=cauth_id)
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
                pass

    @expose('json')
    def get(self, **kwargs):
        _policy = 'managesf.user:get'
        if not authorize(_policy,
                         target={'username': kwargs.get('username')}):
            return abort(401,
                         detail='Failure to comply with policy %s' % _policy)
        return sfmanager.user.get(**kwargs)

    @expose()
    def delete(self, id=None, email=None, username=None):
        _policy = 'managesf.user:delete'
        if not authorize(_policy,
                         target={'username': username}):
            return abort(401,
                         detail='Failure to comply with policy %s' % _policy)
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
                    pass
            sfmanager.user.delete(id=d_id)
        except Exception as e:
            return report_unhandled_error(e)
        response.status = 204


class HtpasswdController(RestController):
    def __init__(self):
        self.htp = htp.Htpasswd(conf)

    @expose('json')
    def put(self):
        _policy = 'managesf.htpasswd:create_update'
        if not authorize(_policy,
                         target={}):
            return abort(401,
                         detail='Failure to comply with policy %s' % _policy)
        try:
            password = self.htp.set_api_password(request.remote_user)
        except IOError:
            abort(406)
        response.status = 201
        return password

    @expose('json')
    def get(self):
        _policy = 'managesf.htpasswd:get'
        if not authorize(_policy,
                         target={}):
            return abort(401,
                         detail='Failure to comply with policy %s' % _policy)
        response.status = 404
        try:
            if self.htp.user_has_api_password(request.remote_user):
                response.status = 204
        except IOError:
            abort(406)

    @expose('json')
    def delete(self):
        _policy = 'managesf.htpasswd:delete'
        if not authorize(_policy,
                         target={}):
            return abort(401,
                         detail='Failure to comply with policy %s' % _policy)
        try:
            self.htp.delete(request.remote_user)
            response.status = 204
        except IOError:
            abort(406)


class HooksController(RestController):

    @expose('json')
    def post(self, hook_name, service_name=None):
        """Trigger hook {hook_name} across all services. If {service_name}
        is set, trigger the hook only for that service."""
        _policy = 'managesf.hooks:trigger'
        if not authorize(_policy,
                         target={}):
            return abort(401,
                         detail='Failure to comply with policy %s' % _policy)
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
                hooks_feedback[s.service_name] = unicode(e)
                unavailable_hooks += 1
                logger.debug('[%s] hook %s is not defined' % (s.service_name,
                                                              hook_name))
            except Exception as e:
                hooks_feedback[s.service_name] = unicode(e)
                return_code = 400
                msg = u'[%s] hook %s failed with error: %s'
                logger.debug(msg % (s.service_name,
                                    hook_name,
                                    unicode(e)))
        if len(SF_SERVICES) == unavailable_hooks:
            return_code = 404
        response.status = return_code
        hooks_feedback['hook_name'] = hook_name
        return hooks_feedback


class TestsController(RestController):

    @expose('json')
    def put(self, project_name=''):
        _policy = 'managesf.tests:add'
        if not authorize(_policy,
                         target={'project': project_name}):
            return abort(401,
                         detail='Failure to comply with policy %s' % _policy)
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
            abort(500, detail=unicode(e))
        if request.json:
            project_scripts = request.json.get('project-scripts', False)

        if project_scripts:
            try:
                msg = 'Adding tests to config for project %s'
                logger.debug(msg % project_name)
                code_review.review.propose_test_scripts(project_name,
                                                        request.remote_user)
            except Exception as e:
                abort(500, detail=unicode(e))

        response.status = 201
        return True


# TODO obsoleted by policies
# need to be replaced by a policies checker controller
class ConfigController(RestController):
    @expose('json')
    def get(self):
        _policy = 'managesf.config:get'
        if not authorize(_policy,
                         target={}):
            return abort(401,
                         detail='Failure to comply with policy %s' % _policy)
        permissions = {}
        permissions['create_projects'] = authorize('managesf.project:create',
                                                   target={})
        return permissions


class ResourcesController(RestController):
    def check_policy(self, _policy):
        if not authorize(_policy,
                         target={}):
            return abort(401,
                         detail='Failure to comply with policy %s' % _policy)

    @expose('json')
    def get(self, **kwargs):
        self.check_policy('managesf.resources:get')
        eng = SFResourceBackendEngine(
            os.path.join(conf.resources['workdir'], 'read'),
            conf.resources['subdir'])
        if kwargs.get('get_missing_resources', None) == 'true':
            return eng.get_missing_resources(
                conf.resources['master_repo'],
                'master')
        else:
            return eng.get(
                conf.resources['master_repo'],
                'master')

    @expose('json')
    def post(self):
        self.check_policy('managesf.resources:validate')
        infos = request.json if request.content_length else {}
        zuul_url = infos.get('zuul_url', None)
        zuul_ref = infos.get('zuul_ref', None)
        if not all([zuul_url, zuul_ref]):
            abort(400, detail="Request content invalid")
        eng = SFResourceBackendEngine(
            os.path.join(conf.resources['workdir'], 'validate'),
            conf.resources['subdir'])
        status, logs = eng.validate(conf.resources['master_repo'],
                                    'master', zuul_url, zuul_ref)
        if not status:
            response.status = 409
        else:
            response.status = 200
        return logs

    @expose('json')
    def put(self):
        self.check_policy('managesf.resources:apply')
        infos = request.json if request.content_length else {}
        eng = SFResourceBackendEngine(
            os.path.join(conf.resources['workdir'], 'apply'),
            conf.resources['subdir'])
        if not infos:
            status, logs = eng.apply(conf.resources['master_repo'],
                                     'master^1',
                                     conf.resources['master_repo'],
                                     'master')
        else:
            try:
                prev = infos.get('prev', None)
                new = infos.get('new', None)
                if not prev or not new:
                    raise Exception
            except Exception:
                response.status = 400
                return ['Unable to find the "new" and/or "prev" '
                        'keys in the json payload']
            status, logs = eng.direct_apply(prev, new)
        if not status:
            response.status = 409
        else:
            response.status = 201
        return logs


class JobController(RestController):

    class JobLogsController(RestController):
        @expose('json')
        def get(self, job_name, job_id):
            _policy = 'managesf.job:get'
            if not authorize(_policy,
                             target={"job": job_name}):
                msg = 'Failure to comply with policy %s' % _policy
                return abort(401,
                             detail=msg)
            try:
                results = {}
                for jobrunner in JOBRUNNERS:
                    r = jobrunner.job.get_job_logs(job_name,
                                                   job_id)
                    results[jobrunner.service_name] = r
                response.status = 200
                return results
            except Exception as e:
                response.status = 500
                return {'error_description': str(e)}

    class JobParametersController(RestController):
        @expose('json')
        def get(self, job_name, job_id):
            _policy = 'managesf.job:get'
            if not authorize(_policy,
                             target={"job": job_name}):
                msg = 'Failure to comply with policy %s' % _policy
                return abort(401,
                             detail=msg)
            try:
                results = {}
                for jobrunner in JOBRUNNERS:
                    r = jobrunner.job.get_job_parameters(job_name,
                                                         job_id)
                    results[jobrunner.service_name] = r
                response.status = 200
                return results
            except Exception as e:
                response.status = 500
                return {'error_description': str(e)}

    logs = JobLogsController()
    parameters = JobParametersController()

    @expose('json')
    def get(self, job_name, job_id):
        _policy = 'managesf.job:get'
        if not authorize(_policy,
                         target={"job": job_name}):
            return abort(401,
                         detail='Failure to comply with policy %s' % _policy)
        response.status = 400
        if not job_name:
            return {'error_description': 'missing job name'}
        try:
            results = {}
            for jobrunner in JOBRUNNERS:
                r = jobrunner.job.get_job(job_name, job_id)
                results[jobrunner.service_name] = r
            response.status = 200
            return results
        except Exception as e:
            response.status = 500
            return {'error_description': str(e)}

    @expose('json')
    def delete(self, job_name, job_id):
        _policy = 'managesf.job:stop'
        if not authorize(_policy,
                         target={"job": job_name}):
            return abort(401,
                         detail='Failure to comply with policy %s' % _policy)
        if not job_name or not job_id:
            response.status = 400
            return {'error_description': 'missing parameter(s)'}
        try:
            results = {}
            for jobrunner in JOBRUNNERS:
                r = jobrunner.job.stop(job_name, job_id)
                results[jobrunner.service_name] = r
            response.status = 200
            return results
        except Exception as e:
            response.status = 500
            return {'error_description': str(e)}


class JobsController(RestController):

    id = JobController()

    @expose('json')
    def get(self, job_name, **kwargs):
        _policy = 'managesf.job:get'
        if not authorize(_policy,
                         target={"job": job_name}):
            return abort(401,
                         detail='Failure to comply with policy %s' % _policy)
        response.status = 400
        if not job_name:
            return {'error_description': 'missing job name'}
        allowed_filter_opts = ['change', 'patchset']
        # precedence is query args, then json payload
        if not kwargs:
            kwargs = request.json if request.content_length else {}
        for u in kwargs:
            if u not in allowed_filter_opts:
                response.status = 403
                msg = 'Unknown filter option %s - allowed options are %s'
                msg = msg % (u, ', '.join(allowed_filter_opts))
                return {'error_description': msg}
        try:
            results = {}
            for jobrunner in JOBRUNNERS:
                r = jobrunner.job.get_job(job_name, **kwargs)
                results[jobrunner.service_name] = r
            response.status = 200
            return results
        except Exception as e:
            response.status = 500
            return {'error_description': str(e)}

    @expose('json')
    def post(self, job_name):
        _policy = 'managesf.job:run'
        if not authorize(_policy,
                         target={"job": job_name}):
            return abort(401,
                         detail='Failure to comply with policy %s' % _policy)
        if not job_name:
            response.status = 400
            return {'error_description': 'missing job name'}
        parameters = request.json if request.content_length else {}
        try:
            results = {}
            for jobrunner in JOBRUNNERS:
                r = jobrunner.job.run(job_name, parameters)
                results[jobrunner.service_name] = r
            response.status = 201
            return results
        except Exception as e:
            response.status = 500
            return {'error_description': str(e)}


load_services()


JOBRUNNERS = [s for s in SF_SERVICES
              if isinstance(s, base.BaseJobRunnerServicePlugin)]


class RootController(object):
    project = ProjectController()
    backup = BackupController()
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
    resources = ResourcesController()
    jobs = JobsController()
