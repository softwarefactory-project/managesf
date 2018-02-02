#
# Copyright (C) 2017 Red Hat
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


import traceback

from pecan import expose
from pecan import request, response, abort

from managesf.controllers.api.v2 import base
from managesf.api.v2.managers import resource_manager as manager


class ACLController(base.APIv2RestController):

    @expose('json')
    def get(self, **kwargs):
        _policy = 'managesf.resources:get'
        if not kwargs:
            kwargs = request.json if request.content_length else {}
        target = dict((k, v) for k, v in kwargs.items()
                      if k not in ['order_by', 'skip', 'limit', ])
        if not base.authorize(_policy,
                              target=target):
            return abort(401,
                         detail='Failure to comply with policy %s' % _policy)
        response.status = 400
        try:
            results = manager.acls.get(**kwargs)
            if results['total'] == 0:
                response.status = 404
            else:
                response.status = 200
            return results
        except NotImplementedError as e:
            response.status = 404
            return {'error_description': str(e)}
        except Exception as e:
            response.status = 500
            self._logger.exception(e)
            return {'error_description': str(e),
                    'traceback': traceback.format_exc()}


class GroupsController(base.APIv2RestController):

    @expose('json')
    def get(self, **kwargs):
        _policy = 'managesf.resources:get'
        if not kwargs:
            kwargs = request.json if request.content_length else {}
        target = dict((k, v) for k, v in kwargs.items()
                      if k not in ['order_by', 'skip', 'limit', ])
        if not base.authorize(_policy,
                              target=target):
            return abort(401,
                         detail='Failure to comply with policy %s' % _policy)
        response.status = 400
        try:
            results = manager.groups.get(**kwargs)
            if results['total'] == 0:
                response.status = 404
            else:
                response.status = 200
            return results
        except NotImplementedError as e:
            response.status = 404
            return {'error_description': str(e)}
        except Exception as e:
            response.status = 500
            self._logger.exception(e)
            return {'error_description': str(e),
                    'traceback': traceback.format_exc()}


class ProjectsController(base.APIv2RestController):

    @expose('json')
    def get(self, **kwargs):
        _policy = 'managesf.resources:get'
        if not kwargs:
            kwargs = request.json if request.content_length else {}
        target = dict((k, v) for k, v in kwargs.items()
                      if k not in ['order_by', 'skip', 'limit', ])
        if not base.authorize(_policy,
                              target=target):
            return abort(401,
                         detail='Failure to comply with policy %s' % _policy)
        response.status = 400
        try:
            results = manager.projects.get(**kwargs)
            if results['total'] == 0:
                response.status = 404
            else:
                response.status = 200
            return results
        except NotImplementedError as e:
            response.status = 404
            return {'error_description': str(e)}
        except Exception as e:
            response.status = 500
            self._logger.exception(e)
            return {'error_description': str(e),
                    'traceback': traceback.format_exc()}


class RepositoriesController(base.APIv2RestController):

    @expose('json')
    def get(self, **kwargs):
        _policy = 'managesf.resources:get'
        if not kwargs:
            kwargs = request.json if request.content_length else {}
        target = dict((k, v) for k, v in kwargs.items()
                      if k not in ['order_by', 'skip', 'limit', ])
        if not base.authorize(_policy,
                              target=target):
            return abort(401,
                         detail='Failure to comply with policy %s' % _policy)
        response.status = 400
        try:
            results = manager.repositories.get(**kwargs)
            if results['total'] == 0:
                response.status = 404
            else:
                response.status = 200
            return results
        except NotImplementedError as e:
            response.status = 404
            return {'error_description': str(e)}
        except Exception as e:
            response.status = 500
            self._logger.exception(e)
            return {'error_description': str(e),
                    'traceback': traceback.format_exc()}


class ResourcesRootController(base.APIv2RestController):

    @expose('json')
    def get(self, **kwargs):
        # TODO change this when group lookup is fixed
        _policy = 'managesf.resources:get'
        if not kwargs:
            kwargs = request.json if request.content_length else {}
        if kwargs.get('get_missing_resources', '').lower() == 'true':
            kwargs['get_missing_resources'] = True
        else:
            kwargs['get_missing_resources'] = False
        target = dict((k, v) for k, v in kwargs.items()
                      if k not in ['order_by', 'skip', 'limit'])
        if not base.authorize(_policy,
                              target=target):
            return abort(401,
                         detail='Failure to comply with policy %s' % _policy)
        response.status = 400
        try:
            results = manager.resources.get(**kwargs)
            response.status = 200
            return results
        except NotImplementedError as e:
            response.status = 404
            return {'error_description': str(e)}
        except Exception as e:
            response.status = 500
            self._logger.exception(e)
            return {'error_description': str(e),
                    'traceback': traceback.format_exc()}

    @expose('json')
    def put(self, **kwargs):
        _policy = 'managesf.resources:apply'
        if not kwargs:
            kwargs = request.json if request.content_length else {}
        if not base.authorize(_policy,
                              target=kwargs):
            return abort(401,
                         detail='Failure to comply with policy %s' % _policy)
        try:
            ret = manager.resources.update(**kwargs)
            if not ret[0]:
                response.status = 409
            else:
                response.status = 201
            if len(ret) == 2:
                # Keep compat
                return ret[1]
            else:
                return ret
        except ValueError as e:
            response.status = 400
            return {'error_description': str(e)}
        except NotImplementedError as e:
            response.status = 404
            return {'error_description': str(e)}
        except Exception as e:
            response.status = 500
            self._logger.exception(e)
            return {'error_description': str(e)}

    @expose('json')
    def post(self, **kwargs):
        _policy = 'managesf.resources:validate'
        if not kwargs:
            kwargs = request.json if request.content_length else {}
        if not base.authorize(_policy,
                              target=kwargs):
            return abort(401,
                         detail='Failure to comply with policy %s' % _policy)
        try:
            status, logs = manager.resources.create(**kwargs)
            if not status:
                response.status = 409
            else:
                response.status = 200
            return logs
        except ValueError as e:
            response.status = 400
            return {'error_description': str(e)}
        except NotImplementedError as e:
            response.status = 404
            return {'error_description': str(e)}
        except Exception as e:
            response.status = 500
            self._logger.exception(e)
            return {'error_description': str(e)}

    @expose('json')
    def delete(self, **kwargs):
        _policy = 'any'
        if not kwargs:
            kwargs = request.json if request.content_length else {}
        if not base.authorize(_policy,
                              target=kwargs):
            return abort(401,
                         detail='Failure to comply with policy %s' % _policy)
        try:
            results = manager.resources.delete(**kwargs)
            response.status = 200
            return results
        except ValueError as e:
            response.status = 400
            return {'error_description': str(e)}
        except NotImplementedError as e:
            response.status = 404
            return {'error_description': str(e)}
        except Exception as e:
            response.status = 500
            self._logger.exception(e)
            return {'error_description': str(e)}
