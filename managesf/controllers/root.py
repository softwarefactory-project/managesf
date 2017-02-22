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
import os.path

from pecan import conf
from pecan import expose
from pecan import abort
from pecan.rest import RestController
from pecan import request, response
from stevedore import driver

from managesf.controllers import backup, localuser, introspection, htp
from managesf.controllers import SFuser
from managesf.services import base
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
DEFAULT_SERVICES = ['SFGerrit', 'SFRedmine', 'SFStoryboard', 'SFJenkins',
                    'SFNodepool']
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
        project = ResourcesController().get_project_by_repo(project_name)
        if not project:
            logger.info("Hooks: Repository %s is not part of any project" %
                        change.get('project'))
            # TODO: return here after sf functional test stop depend on redmine
            hook = None
        else:
            hook = project.get('issue-tracker')
        # If no hook, assume internal redmine
        if hook not in ('SFRedmine', 'SFStoryboard'):
            # TODO: fail here after sf functional test stop depend on redmine
            logger.info("Hooks: Unknown hook %s, defaulting to redmine" %
                        hook)
            hook = 'SFRedmine'

        status = 200
        try:
            msg = getattr(SERVICES[hook].hooks, hook_name)(**change)
        except Exception as e:
            status = 400
            msg = unicode(e)
            logger.error("[%s] hook %s failed with %s" % (
                hook, hook_name, msg))
        response.status = status
        return {'msg': msg}


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
        if not infos or 'COMMIT' in infos:
            commit = infos.get('COMMIT', 'master')
            status, logs = eng.apply(conf.resources['master_repo'],
                                     '%s^1' % commit,
                                     conf.resources['master_repo'],
                                     commit)
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

    def get_resources(self):
        return SFResourceBackendEngine(
            os.path.join(conf.resources['workdir'], 'read'),
            conf.resources['subdir']).get(conf.resources['master_repo'],
                                          'master')['resources']

    def get_project_by_repo(self, reponame):
        for _, project in self.get_resources().get('projects', {}).items():
            if reponame in project.get('source-repositories', []):
                return project
        return None


class NodesController(RestController):

    class ImageController(RestController):

        @expose('json')
        def get(self, provider_name=None, image_name=None):
            _policy = 'managesf.node:image-get'
            if not authorize(_policy,
                             target={"image": image_name,
                                     "provider": provider_name}):
                msg = 'Failure to comply with policy %s' % _policy
                return abort(401,
                             detail=msg)
            results = {}
            response.status = 200
            provider = AGENTSPROVIDERS[0]
            try:
                r = provider.image.get(provider_name, image_name)
                results[provider.service_name] = r
            except Exception as e:
                response.status = 500
                d = {'error_description': unicode(e)}
                results[provider.service_name] = d
            return results

    class ImageUpdateController(RestController):
        @expose('json')
        def put(self, provider_name, image_name, **kwargs):
            _policy = 'managesf.node:image-start-update'
            if not authorize(_policy,
                             target={"image": image_name,
                                     "provider": provider_name}):
                msg = 'Failure to comply with policy %s' % _policy
                return abort(401,
                             detail=msg)
            provider = AGENTSPROVIDERS[0]
            try:
                update_id = provider.image.start_update(provider_name,
                                                        image_name)
                response.status = 201
                d = {provider.service_name: {'update_id': update_id}}
            except Exception as e:
                response.status = 500
                desc = {'error_description': unicode(e)}
                d = {provider.service_name: desc}
            finally:
                return d

        @expose('json')
        def get(self, id):
            _policy = 'managesf.node:image-update-status'
            provider = AGENTSPROVIDERS[0]
            info = provider.image.get_update_info(id)
            if not info:
                return abort(404)
            if not authorize(_policy,
                             target={"image": info['image'],
                                     "provider": info['provider']}):
                msg = 'Failure to comply with policy %s' % _policy
                return abort(401,
                             detail=msg)
            response.status = 200
            return {provider.service_name: info}

    class NodeByIdController(RestController):

        class SSHKeyController(RestController):
            @expose('json')
            def post(self, node_id, public_key=None, user=None):
                try:
                    node_id = int(node_id)
                except:
                    response.status = 400
                    return {'error_description': 'Node id must be an integer'}
                _policy = 'managesf.node:add_authorized_key'
                # TODO filtering by node id is impossible. Return there once
                # traceability is much better
                if not authorize(_policy,
                                 target={}):
                    msg = 'Failure to comply with policy %s' % _policy
                    return abort(401,
                                 detail=msg)
                provider = AGENTSPROVIDERS[0]
                if not public_key:
                    infos = request.json if request.content_length else {}
                    public_key = infos.get('public_key')
                if not public_key:
                    return {'error_description': 'No key provided'}
                try:
                    results = {}
                    provider.node.add_authorized_key(node_id,
                                                     public_key,
                                                     user)
                    results[provider.service_name] = 'OK'
                    response.status = 201
                    return results
                except Exception as e:
                    response.status = 500
                    n = provider.service_name
                    d = {n: {'error_description': unicode(e)}}
                    return d

        authorize_key = SSHKeyController()

        @expose('json')
        def get(self, node_id):
            try:
                node_id = int(node_id)
            except:
                response.status = 400
                return {'error_description': 'Node id must be an integer'}
            _policy = 'managesf.node:get'
            if not authorize(_policy,
                             target={}):
                msg = 'Failure to comply with policy %s' % _policy
                return abort(401,
                             detail=msg)
            provider = AGENTSPROVIDERS[0]
            try:
                results = {}
                r = provider.node.get(node_id)
                results[provider.service_name] = r
                response.status = 200
                return results
            except Exception as e:
                response.status = 500
                n = provider.service_name
                d = {n: {'error_description': unicode(e)}}
                return d

        @expose('json')
        def put(self, node_id):
            try:
                node_id = int(node_id)
            except:
                response.status = 400
                return {'error_description': 'Node id must be an integer'}
            _policy = 'managesf.node:hold'
            if not authorize(_policy,
                             target={}):
                msg = 'Failure to comply with policy %s' % _policy
                return abort(401,
                             detail=msg)
            provider = AGENTSPROVIDERS[0]
            try:
                results = {}
                provider.node.hold(node_id)
                results[provider.service_name] = provider.node.get(node_id)
                response.status = 200
                return results
            except Exception as e:
                response.status = 500
                n = provider.service_name
                d = {n: {'error_description': unicode(e)}}
                return d

        @expose('json')
        def delete(self, node_id):
            try:
                node_id = int(node_id)
            except:
                response.status = 400
                return {'error_description': 'Node id must be an integer'}
            _policy = 'managesf.node:delete'
            if not authorize(_policy,
                             target={}):
                msg = 'Failure to comply with policy %s' % _policy
                return abort(401,
                             detail=msg)
            provider = AGENTSPROVIDERS[0]
            try:
                results = {}
                provider.node.delete(node_id)
                results[provider.service_name] = provider.node.get(node_id)
                response.status = 200
                return results
            except Exception as e:
                response.status = 500
                n = provider.service_name
                d = {n: {'error_description': unicode(e)}}
                return d

    images = ImageController()
    images.update = ImageUpdateController()
    id = NodeByIdController()

    @expose('json')
    def get(self):
        _policy = 'managesf.node:get'
        if not authorize(_policy,
                         target={}):
            msg = 'Failure to comply with policy %s' % _policy
            return abort(401,
                         detail=msg)
        provider = AGENTSPROVIDERS[0]
        try:
            results = {}
            r = provider.node.get()
            results[provider.service_name] = r
            response.status = 200
            return results
        except Exception as e:
            response.status = 500
            n = provider.service_name
            d = {n: {'error_description': unicode(e)}}
            return d


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


AGENTSPROVIDERS = [s for s in SF_SERVICES
                   if isinstance(s, base.BaseAgentProviderServicePlugin)]


class RootController(object):
    backup = BackupController()
    user = LocalUserController()
    bind = LocalUserBindController()
    htpasswd = HtpasswdController()
    about = introspection.IntrospectionController()
    services_users = ServicesUsersController()
    hooks = HooksController()
    resources = ResourcesController()
    jobs = JobsController()
    if len(AGENTSPROVIDERS) > 0:
        nodes = NodesController()
