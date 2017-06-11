#!/usr/bin/env python
#
# Copyright (C) 2017 Red Hat <licensing@enovance.com>
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


from zuul.connection.sql import SQLConnection

from managesf.services import base
from managesf.services.zuul import job


class _Zuul(base.BaseJobRunnerServicePlugin):
    """Plugin managing the Zuul job runner service."""

    _config_section = "zuul"
    service_name = "zuul"

    def __init__(self, conf):
        super(_Zuul, self).__init__(conf)

    def get_client(self, cookie=None):
        raise NotImplementedError


class SoftwareFactoryZuul(_Zuul):
    def __init__(self, conf):
        super(SoftwareFactoryZuul, self).__init__(conf)
        dburi = self.conf.get('dburi')
        self.connection = SQLConnection('managesf',
                                        {'dburi': dburi})
        self.status_url = self.conf.get('status_url')
        self.job = job.SFZuulJobManager(self)

    def get_client(self, type, *args, **kwargs):
        if type == "sql":
            return self.connection
        else:
            raise ValueError("unsupported client type")
