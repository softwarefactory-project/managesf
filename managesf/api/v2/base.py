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


import abc
import six
import json


# TODO move exceptions somewhere more generic
from managesf.services import exceptions as exc


def paginate(func):
    """Decorator facility to automatically paginate GET outputs"""
    def _f(*args, **kwargs):
        if 'skip' not in kwargs:
            kwargs['skip'] = 0
        if 'limit' not in kwargs:
            # TODO config param?
            kwargs['limit'] = 25
        if 'order_by' not in kwargs:
            # use first option as default
            kwargs['order_by'] = args[0].ordering_options[0]
        elif kwargs['order_by'] not in args[0].ordering_options:
            msg = 'invalid ordering option, valid ones are: %s'
            raise ValueError(msg % ', '.join(args[0].ordering_options))
        try:
            skipped = int(kwargs['skip'])
        except ValueError:
            raise ValueError('Invalid starting index')
        try:
            limit = int(kwargs['limit'])
        except ValueError:
            raise ValueError('Invalid limit')
        if skipped < 0:
            raise ValueError('Invalid starting index')
        if limit < 0:
            raise ValueError('Invalid limit')
        results = func(**kwargs)
        try:
            results, total = func(*args, **kwargs)
        except ValueError:
            results = func(*args, **kwargs)
            total = len(results)
        if not total:
            total = len(results)
        # results is expected to be ordered in one way or an other
        if len(results) > limit:
            results = results[skipped: skipped + limit]
        return {'total': total,
                'skipped': skipped,
                'limit': limit,
                'results': results}
    return _f


@six.add_metaclass(abc.ABCMeta)
class BaseCRUDManager(object):

    def __init__(self, *args, **kwargs):
        self.ordering_options = []

    def get(self, **kwargs):
        """get one or many items depending on filtering args.
        'Mandatory' args:
        skip (int)
        limit (int)
        order_by (str)"""
        raise NotImplementedError

    def create(self, **kwargs):
        """create an item"""
        raise NotImplementedError

    def update(self, **kwargs):
        """update an item"""
        raise NotImplementedError

    def delete(self, **kwargs):
        """delete an item"""
        raise NotImplementedError


@six.add_metaclass(abc.ABCMeta)
class BaseService(object):
    """Base plugin for a service that can be managed by Software Factory (v2).
    """

    _config_section = "base"
    service_name = "base service"

    def __init__(self, conf):
        self._full_conf = conf
        try:
            self.configure_service(conf)
        except AttributeError:
            raise Exception(repr(conf))

    def configure_service(self, conf):
        try:
            self.conf = getattr(conf, self._config_section, None)
        except KeyError:
            msg = ("The %s service is not available" % self._config_section)
            raise exc.ServiceNotAvailableError(msg)
        if not self.conf:
            msg = ("The %s service is not available" % self._config_section)
            raise exc.ServiceNotAvailableError(msg)


class V2Data(object):
    """Generic class for returned objects that must be JSON-serializable"""

    def to_dict(self):
        raise NotImplementedError

    def __json__(self):
        # pecan shortcut
        return self.to_dict()


class V2DataJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, V2Data):
            return obj.to_dict()
        return json.JSONEncoder.default(self, obj)
