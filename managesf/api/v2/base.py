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
import re
import six
import json
import logging

import paramiko
import sqlalchemy as sa
from stevedore import driver

from pecan import conf

# TODO move exceptions somewhere more generic
from managesf.services import exceptions as exc


logger = logging.getLogger(__name__)


isotime = '%Y-%m-%dT%H:%M:%S'


def load_manager(namespace, service):
    logger.info('loading %s:%s manager' % (namespace, service))
    # hard-coded Dummy service for testing. What could go wrong?
    if service == 'DummyService':
        return None
    try:
        manager = driver.DriverManager(namespace=namespace,
                                       name=service,
                                       invoke_on_load=True,
                                       invoke_args=(conf,)).driver
        logger.info('%s:%s manager loaded successfully' % (namespace,
                                                           service))
        return manager
    except Exception as e:
        msg = 'Could not load manager %s:%s: %s' % (namespace,
                                                    service, e)
        logger.error(msg)
        return None


class Data(object):
    """Generic class for returned objects that must be JSON-serializable"""

    def to_dict(self):
        raise NotImplementedError

    def __json__(self):
        # pecan shortcut
        return self.to_dict()


class DataJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Data):
            return obj.to_dict()
        return json.JSONEncoder.default(self, obj)


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
            msg = 'invalid ordering option %s, valid ones are: %s'
            raise ValueError(msg % (kwargs['order_by'],
                                    ', '.join(args[0].ordering_options)))
        if 'desc' not in kwargs:
            kwargs['desc'] = False
        if isinstance(kwargs['desc'], basestring):
            if kwargs['desc'].lower() == 'true':
                kwargs['desc'] = True
            else:
                kwargs['desc'] = False
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
        r = func(*args, **kwargs)
        try:
            results, total = r
            # if results is a list with 2 elements, this will fail ...
            if not isinstance(results, list):
                raise ValueError
        except ValueError:
            results = r
            total = len(r)
        if total is None:
            total = len(r)
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
        self._logger = logging.getLogger(
            'managesf.api.v2.%s' % self.__class__.__name__)

    @abc.abstractmethod
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


# Generic service utilities


class SQLConnection(object):
    """Generic SQL connector for DB-based services."""
    def __init__(self, connection_name, connection_config):
        try:
            self.dburi = connection_config.get('dburi')
            self.connection_name = connection_name
            self.engine = sa.create_engine(self.dburi)
            self.get_tables()
        except sa.exc.NoSuchModuleError:
            logger.error(
                "The required module for the dburi dialect isn't available. "
                "SQL connection %s will be unavailable." % connection_name)
        except sa.exc.OperationalError:
            msg = "SQL connection %s: Unable to connect to the database."
            logger.error(msg % connection_name)

    def get_tables(self):
        raise NotImplementedError


class SSHConnection(object):
    """Generic connector for remote commands run through SSH"""

    INPUT_FORMAT = re.compile("^[a-zA-Z0-9_-]+$", re.U)

    def __init__(self, connection_config):
        self.key = connection_config.get('ssh_key')
        self.hostname = connection_config.get('ssh_host')
        self.username = connection_config.get('ssh_user')

    def get_connection(self):
        k = paramiko.RSAKey.from_private_key_file(self.key)
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        c.connect(hostname=self.hostname,
                  username=self.username,
                  pkey=k)
        return c

    def validate_input(self, input, format=None):
        f = format or self.INPUT_FORMAT
        return f.match(input)
