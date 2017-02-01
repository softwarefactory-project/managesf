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

from managesf.services import base


logger = logging.getLogger(__name__)


class SFGerritProjectManager(base.ProjectManager):

    def get_user_groups(self, user):
        client = self.plugin.get_client()
        groups = client.get_user_groups(user)
        if isinstance(groups, bool):
            logger.info(u"[%s] Could not find user groups %s: %s" % (
                self.plugin.service_name, user, str(groups)))
            groups = []
        return groups
