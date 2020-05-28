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
import logging
from urllib.parse import unquote

from pecan import conf
from pecan import expose
from pecan import abort
from pecan.rest import RestController
from pecan import request, response
from stevedore import driver

from managesf.controllers import localuser, introspection
from managesf.controllers import SFuser
from managesf.services import base
from managesf.services import exceptions
from managesf import policy

from managesf import DEFAULT_SERVICES
from managesf.controllers.api.v2 import resources as v2_resources
from managesf.controllers.api.v2 import configurations as v2_configurations

from managesf.api.v2.managers import resource_manager


logger = logging.getLogger(__name__)

LOGERRORMSG = "Unable to process client request, failed with "\
              "unhandled error: %s"
CLIENTERRORMSG = "Unable to process your request, failed with "\
                 "unhandled error (server side): %s"

# TODO: add detail (detail arg or abort function) for all abort calls.


# instanciate service plugins
SF_SERVICES = []
SERVICES = {}


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
            SERVICES[service] = plugin
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

# TODO move to utils and use resources rather than gerrit for groups


def authorize(rule_name, target):
    if not request.remote_user:
        request.remote_user = request.headers.get('X-Remote-User')
    credentials = {'username': request.remote_user, 'groups': []}
    # OpenID Connect authentication
    if request.headers.get("OIDC_CLAIM_groups", None) is not None:
        for group in request.headers.get('OIDC_CLAIM_groups').split(','):
            # it seems like keycloak prefixes groups with /, remove it
            if group.startswith('/'):
                credentials['groups'].append(group[1:])
            else:
                credentials['groups'].append(group)
    # gerrit based
    else:
        if request.remote_user:
            code_reviews = [s for s in SF_SERVICES
                            if isinstance(s, base.BaseCodeReviewServicePlugin)]
            if code_reviews:
                user_groups = code_reviews[0].project.get_user_groups(
                    request.remote_user)
                credentials['groups'] = [grp['name'] for grp in user_groups]
    return policy.authorize(rule_name, target, credentials)


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
            abort(400, detail=str(e))
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
            abort(404, detail=str(e))
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
            abort(404, detail=str(e))
        except Exception as e:
            return report_unhandled_error(e)
        return ret


class LocalUserBindController(RestController):

    log = logging.getLogger("BindController")

    @expose('json')
    def get(self):
        _policy = 'managesf.localuser:bind'
        authorization = request.headers.get('Authorization', None)
        if not authorization:
            abort(401, detail="Authentication header missing")
        try:
            username, password = localuser.decode(authorization)
        except localuser.DecodeError:
            self.log.warning("Authorization decoding error")
            abort(401, detail="Wrong authorization header")
        if not authorize(_policy,
                         target={'username': username}):
            self.log.error(u"%s: policy error" % username)
            return abort(401,
                         detail='Failure to comply with policy %s' % _policy)

        try:
            ret = localuser.bind_user(authorization)
        except (localuser.BindForbidden, localuser.UserNotFound) as e:
            self.log.warning(u"%s: UserNotFound or Forbidden" % username)
            abort(401, detail=str(e))
        except Exception as e:
            self.log.exception(u"%s: couldn't bind user" % username)
            return report_unhandled_error(e)
        if not ret:
            self.log.exception(u"%s: Authentication failed" % username)
            abort(401, detail="Authentication failed")
        self.log.info(u"%s: binding success" % username)
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
        if _email:
            _email = unquote(_email)
        _username = request.GET.get('username')
        if _username:
            _username = unquote(_username)
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
                s_id = service.user.get(username=infos.get('username'))
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
                    service.user.delete(username=username)
                    sfmanager.user.mapping.delete(d_id,
                                                  service.service_name)
                except exceptions.UnavailableActionError:
                    pass
            sfmanager.user.delete(id=d_id)
        except Exception as e:
            return report_unhandled_error(e)
        response.status = 204


class HooksController(RestController):

    def get_project_by_repo(self, reponame):
        for _, project in resource_manager.resources.get().get(
                'resources', {}).get('projects', {}).items():
            for repo in project.get('source-repositories', []):
                if reponame in repo:
                    return project
        return None

    @expose('json')
    def post(self, hook_name):
        """Trigger hook {hook_name}."""
        _policy = 'managesf.hooks:trigger'
        if not authorize(_policy,
                         target={}):
            return abort(401,
                         detail='Failure to comply with policy %s' % _policy)
        change = request.json if request.content_length else {}
        # Get hook engine configuration for project
        project_name = change.get('project')
        if not project_name:
            return abort(400, detail=u"Hooks: Invalid change %s" % change)
        project = self.get_project_by_repo(project_name)
        if not project:
            logger.info("Hooks: Repository %s is not part of any project" %
                        change.get('project'))
            return abort(204, detail=u"No issue-tracker defined")
        hook = project.get('issue-tracker')

        status = 200
        try:
            msg = getattr(SERVICES[hook].hooks, hook_name)(**change)
        except Exception as e:
            status = 400
            msg = str(e)
            logger.error(u"[%s] hook %s failed with %s" % (
                hook, hook_name, msg))
        response.status = status
        return {'msg': msg}


load_services()


# API v2 - will be in its own file hierarchy once dependencies are sorted out


class V2Controller(object):
    # Mimic api v1 and replace endpoints incrementally
    user = LocalUserController()
    bind = LocalUserBindController()
    about = introspection.IntrospectionController()
    services_users = ServicesUsersController()
    hooks = HooksController()
    resources = v2_resources.ResourcesRootController()
    configurations = v2_configurations.ConfigurationController()


class RootController(object):
    def __init__(self, *args, **kwargs):
        try:
            # just try to get the api config
            _ = conf.api.v2  # noQA
            self.v2 = V2Controller()
        except AttributeError:
            # TODO have a generic blank REST controller that returns
            # 'Not Implemented' error code
            logger.info('API v2 is not configured, skipping endpoint.')
            self.v2 = RestController()

        self.user = LocalUserController()
        self.bind = LocalUserBindController()
        self.about = introspection.IntrospectionController()
        self.services_users = ServicesUsersController()
        self.hooks = HooksController()
