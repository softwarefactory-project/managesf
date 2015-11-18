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


from managesf.services import base
from managesf.services import exceptions

heartbeat = 'wget --spider http://localhost:8082/jenkins/'


class DummyJenkinsManager(base.BaseCRUDManager):
    def create(self, *args, **kwargs):
        raise exceptions.UnavailableActionError()

    def update(self, *args, **kwargs):
        raise exceptions.UnavailableActionError()

    def delete(self, *args, **kwargs):
        raise exceptions.UnavailableActionError()

    def get(self, *args, **kwargs):
        raise exceptions.UnavailableActionError()


class Jenkins(base.BaseServicePlugin):
    """Very simple Jenkins plugin only used for backups."""

    _config_section = "jenkins"
    service_name = "jenkins"

    def __init__(self, conf):
        super(Jenkins, self).__init__(conf)
        self.backup = base.BackupManager(self)
        self.project = DummyJenkinsManager(self)
        self.user = DummyJenkinsManager(self)
        self.membership = DummyJenkinsManager(self)
        self.role = DummyJenkinsManager(self)
        self.backup.heartbeat_cmd = heartbeat

    def get_client(self, cookie=None):
        return None
