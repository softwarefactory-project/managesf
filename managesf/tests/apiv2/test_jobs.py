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


from unittest import TestCase

from mock import Mock
from managesf.tests import dummy_conf
from webtest import TestApp
from pecan import load_app


c = dummy_conf()
config = {'services': c.services,
          'gerrit': c.gerrit,
          'app': c.app,
          'admin': c.admin,
          'sqlalchemy': c.sqlalchemy,
          'auth': c.auth,
          'htpasswd': c.htpasswd,
          'managesf': c.managesf,
          'storyboard': c.storyboard,
          'mysql': c.mysql,
          'policy': c.policy,
          'resources': c.resources,
          'jenkins': c.jenkins,
          'nodepool': c.nodepool,
          'api': c.api, }
# App must be loaded before we can import v2 managers
TestApp(load_app(config))


from managesf.api.v2.jobs.services import sfzuul  # noQA


class TestZuulJobManager(TestCase):
    @classmethod
    def setupClass(cls):
        # TODO mock DB?
        cls.manager = Mock()
        cls.manager.connection = Mock()
        cls.ZuulJobManager = sfzuul.ZuulJobManager(cls.manager)
