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

from requests.auth import HTTPBasicAuth

from managesf.services import base
from managesf.services.gerrit import project
from managesf.services.gerrit import user
from managesf.services.gerrit import review
from managesf.services.gerrit import group
from managesf.services.gerrit.utils import GerritClient

logger = logging.getLogger(__name__)


class Gerrit(base.BaseCodeReviewServicePlugin):
    """Plugin managing the Gerrit Code Review service."""

    _config_section = "gerrit"
    service_name = "gerrit"

    def __init__(self, conf):
        super(Gerrit, self).__init__(conf)
        self.project = None
        self.user = None
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
        self.review = review.SFGerritReviewManager(self)
        self.group = group.SFGerritGroupManager(self)

    def get_client(self, cookie=None):
        auth = HTTPBasicAuth("admin", self.conf['password'])
        return GerritClient(self.conf['url'], auth)
