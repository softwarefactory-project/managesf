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


import logging
import traceback
from datetime import datetime

from pecan import conf
from pecan import expose
from pecan import request, response, abort
from pecan.rest import RestController

from managesf.controllers.api.v2 import base
from managesf.api.v2.base import isotime


logger = logging.getLogger(__name__)


manager = None
try:
    builds_service = conf.api.v2.builds[0]
    manager = base.load_manager('managesf.v2.builds',
                                builds_service)
except AttributeError as e:
    msg = 'Undefined API endpoint, skipping.'
    logger.error(msg)
except IndexError:
    msg = 'No build service defined, skipping.'
    logger.error(msg)
except:
    msg = 'Cannot load build service "%s"' % conf.api['v2']['builds'][0]
    logger.error(msg)


class BuildController(RestController):

    @expose('json')
    def get(self, **kwargs):
        # TODO change this when group lookup is fixed
        _policy = 'any'
        if not kwargs:
            kwargs = request.json if request.content_length else {}
        if 'started_before' in kwargs:
            try:
                kwargs['started_before'] = datetime.strptime(
                    kwargs['started_before'],
                    isotime)
            except:
                response.status = 400
                msg = "timestamp must be formatted as '%s'" % isotime
                return {'error_description': msg,
                        'traceback': traceback.format_exc()}
        if 'started_after' in kwargs:
            try:
                kwargs['started_after'] = datetime.strptime(
                    kwargs['started_after'],
                    isotime)
            except:
                response.status = 400
                msg = "timestamp must be formatted as '%s'" % isotime
                return {'error_description': msg,
                        'traceback': traceback.format_exc()}
        target = dict((k, v) for k, v in kwargs.items()
                      if k not in ['order_by', 'skip', 'limit'])
        if not base.authorize(_policy,
                              target=target):
            return abort(401,
                         detail='Failure to comply with policy %s' % _policy)
        response.status = 400
        try:
            results = manager.builds.get(**kwargs)
            response.status = 200
            # no results -> 404
            if results['total'] == 0:
                response.status = 404
            return results
        except Exception as e:
            response.status = 500
            return {'error_description': str(e),
                    'traceback': traceback.format_exc()}

    @expose('json')
    def post(self, **kwargs):
        _policy = 'any'
        if not kwargs:
            kwargs = request.json if request.content_length else {}
        if not base.authorize(_policy,
                              target=kwargs):
            return abort(401,
                         detail='Failure to comply with policy %s' % _policy)
        try:
            results = manager.builds.create(**kwargs)
            response.status = 201
            return results
        except Exception as e:
            response.status = 500
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
            results = manager.builds.delete(**kwargs)
            response.status = 200
            return results
        except Exception as e:
            response.status = 500
            return {'error_description': str(e)}


class BuildSetController(RestController):

    @expose('json')
    def get(self, **kwargs):
        # TODO change this when group lookup is fixed
        _policy = 'any'
        if not kwargs:
            kwargs = request.json if request.content_length else {}
        target = dict((k, v) for k, v in kwargs.items()
                      if k not in ['order_by', 'skip', 'limit'])
        if not base.authorize(_policy,
                              target=target):
            return abort(401,
                         detail='Failure to comply with policy %s' % _policy)
        response.status = 400
        try:
            results = manager.buildsets.get(**kwargs)
            response.status = 200
            # no results -> 404
            if results['total'] == 0:
                response.status = 404
            return results
        except Exception as e:
            response.status = 500
            return {'error_description': str(e)}

    @expose('json')
    def post(self, **kwargs):
        _policy = 'any'
        if not kwargs:
            kwargs = request.json if request.content_length else {}
        if not base.authorize(_policy,
                              target=kwargs):
            return abort(401,
                         detail='Failure to comply with policy %s' % _policy)
        try:
            results = manager.buildsets.create(**kwargs)
            response.status = 201
            return results
        except Exception as e:
            response.status = 500
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
            results = manager.buildsets.delete(**kwargs)
            response.status = 200
            return results
        except Exception as e:
            response.status = 500
            return {'error_description': str(e)}


if manager:
    builds = BuildController()
    buildsets = BuildSetController()
else:
    # TODO have a generic controller for unimplemented endpoints
    builds = RestController()
    buildsets = RestController()
