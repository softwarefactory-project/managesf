#!/usr/bin/env python
#
# Copyright (C) 2018 Red Hat
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

from managesf.services import base
from managesf.services.pagure import user


class Pagure(base.BaseServicePlugin):
    """Plugin managing the Pagure service."""

    _config_section = "pagure"
    service_name = "pagure"

    def get_client(self, cookie=None):
        return None


class SoftwareFactoryPagure(Pagure):
    """Plugin managing a Pagure instance deployed with Software Factory,
    thus needing a cauth-issued cookie for authentication."""

    def __init__(self, conf):
        super(SoftwareFactoryPagure, self).__init__(conf)
        self.user = user.PagureUserManager(self)
