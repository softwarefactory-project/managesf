#!/usr/bin/env python
#
# Copyright (C) 2015 Red Hat <licensing@enovance.com>
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
import time

from pysflib.sfgerrit import GerritUtils
from pysflib.sfauth import get_cookie
from requests.auth import HTTPBasicAuth

from managesf.services import base
from managesf.services.gerrit import membership
from managesf.services.gerrit import project
from managesf.services.gerrit import role
from managesf.services.gerrit import user
from managesf.services.gerrit import review
from managesf.services.gerrit import repository
from managesf.services.gerrit import group

logger = logging.getLogger(__name__)


class Gerrit(base.BaseCodeReviewServicePlugin):
    """Plugin managing the Gerrit Code Review service."""

    _config_section = "gerrit"
    service_name = "gerrit"

    def __init__(self, conf):
        super(Gerrit, self).__init__(conf)
        self.project = None
        self.user = None
        self.membership = None
        self.role = None
        self.repository = None
        self.review = None
        self.group = None

    def get_client(self, cookie=None):
        raise NotImplementedError


ADMIN_COOKIE = None
ADMIN_COOKIE_DATE = 0
COOKIE_VALIDITY = 60


class SoftwareFactoryGerrit(Gerrit):
    """"""

    def __init__(self, conf):
        super(SoftwareFactoryGerrit, self).__init__(conf)
        self.project = project.SFGerritProjectManager(self)
        self.user = user.SFGerritUserManager(self)
        self.membership = membership.SFGerritMembershipManager(self)
        self.role = role.SFGerritRoleManager(self)
        self.repository = repository.SFGerritRepositoryManager(self)
        self.review = review.SFGerritReviewManager(self)
        self.group = group.SFGerritGroupManager(self)

    def get_client(self, cookie=None):
        if not cookie:
            try:
                basic = HTTPBasicAuth(self.conf['admin_user'],
                                      'password')
                msg = '[%s] using direct basic auth to connect to gerrit'
                logger.debug(msg % self.service_name)
                g = GerritUtils(self.conf['url'] + 'api',
                                auth=basic)
                return g
            except Exception as e:
                # if we can't get the admin credentials from the config,
                # let's not panic
                msg = ('[%s] simple auth raised error: %s, '
                       'going with SF cauth-based authentication')
                logger.debug(msg % (self.service_name, e))
            # Use an admin cookie
            if int(time.time()) - globals()['ADMIN_COOKIE_DATE'] > \
                    globals()['COOKIE_VALIDITY']:
                cookie = get_cookie(self._full_conf.auth['host'],
                                    self._full_conf.admin['name'],
                                    self._full_conf.admin['http_password'])
                globals()['ADMIN_COOKIE'] = cookie
                globals()['ADMIN_COOKIE_DATE'] = int(time.time())
            else:
                cookie = globals()['ADMIN_COOKIE']
        return GerritUtils(self.conf['url'],
                           auth_cookie=cookie)
