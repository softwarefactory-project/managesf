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
import logging

from stevedore import driver

from pecan import conf

# TODO move exceptions somewhere more generic
from managesf.services import exceptions as exc


logger = logging.getLogger(__name__)


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


@six.add_metaclass(abc.ABCMeta)
class BaseCRUDManager(object):

    def __init__(self, *args, **kwargs):
        self.ordering_options = []
        self._logger = logging.getLogger(
            'managesf.api.v2.%s' % self.__class__.__name__)

    @abc.abstractmethod
    def get(self, **kwargs):
        """get one or many items"""
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
