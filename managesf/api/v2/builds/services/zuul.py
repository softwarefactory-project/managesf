#!/usr/bin/env python
#
# Copyright (C) 2016 Red Hat <licensing@enovance.com>
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

from zuul.connection.sql import SQLConnection
# import requests

from managesf.api.v2 import base
from managesf.api.v2 import builds


logger = logging.getLogger(__name__)


class ZuulBuildsManager(builds.BuildServiceManager):

    _config_section = "zuul"
    service_name = "zuul"

    def __init__(self, conf):
        super(builds.BuildServiceManager, self).__init__(conf)
        dburi = self.conf.get('dburi')
        self.connection = SQLConnection('managesf',
                                        {'dburi': dburi})
        self.status_url = self.conf.get('status_url')
        self.builds = ZuulBuildManager(self)
        self.buildsets = ZuulBuildSetManager(self)


class ZuulBuildManager(builds.BuildManager):
    def __init__(self, manager):
        self.manager = manager

    @base.paginate
    def get(self, **kwargs):
        results = []
        results.append(self._get_from_db(**kwargs))
        results.append(self._get_from_status_url(**kwargs))
        return results

    def _get_from_db(self, **kwargs):
        c = self.manager.connection
        bt = c.zuul_build_table
        bst = c.zuul_buildset_table
        with c.engine.begin() as conn:
            query = bt.join(bst).select()
            if 'job_name' in kwargs:
                query = query.where(bt.c.job_name == kwargs['job_name'])
            if 'build_id' in kwargs:
                query = query.where(bt.c.build_id == kwargs['build_id'])
            conn.execute(query).fetchall()
        return []

    def _get_from_status_url(self, **kwargs):
        # TODO
        return []


class ZuulBuildSetManager(builds.BuildSetManager):
    def __init__(self, manager):
        self.manager = manager

    @base.paginate
    def get(self, **kwargs):
        if 'order_by' not in kwargs:
            kwargs['order_by'] = 'id'

        results = []
        results.append(self._get_from_db(**kwargs))
        results.append(self._get_from_status_url(**kwargs))
        return results

    def _get_from_db(self, **kwargs):
        c = self.manager.connection
        with c.engine.begin() as conn:
            query = c.zuul_buildset_table.join(c.zuul_build_table).select()
            conn.execute(query).fetchone()

    def _get_from_status_url(self, **kwargs):
        # TODO
        return []
