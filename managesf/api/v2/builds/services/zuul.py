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
        super(ZuulBuildManager, self).__init__()
        self.manager = manager

    @base.paginate
    def get(self, **kwargs):
        if 'patchset' in kwargs and 'change' not in kwargs:
            raise ValueError('Please specify a change')
        results = []
        results += self._get_from_db(**kwargs)
        results += self._get_from_status_url(**kwargs)
        return results

    def _get_from_db(self, **kwargs):
        c = self.manager.connection
        bt = c.zuul_build_table
        bst = c.zuul_buildset_table
        results = []
        with c.engine.begin() as conn:
            query = bt.join(bst).select()
            if 'build_id' in kwargs:
                query = query.where(bt.c.build_id == kwargs['build_id'])
            if 'buildset_id' in kwargs:
                query = query.where(bt.c.buildset_id == kwargs['buildset_id'])
            if 'job_name' in kwargs:
                query = query.where(bt.c.job_name == kwargs['job_name'])
            if 'result' in kwargs:
                query = query.where(bt.c.result == kwargs['result'])
            if 'started_before' in kwargs:
                query = query.where(bt.c.start_time < kwargs['started_before'])
            if 'started_after' in kwargs:
                query = query.where(bt.c.start_time >= kwargs['started_after'])
            if 'result' in kwargs:
                query = query.where(bt.c.result == kwargs['result'])
            if 'voting' in kwargs:
                query = query.where(bt.c.voting == kwargs['voting'])
            if 'node' in kwargs:
                query = query.like('%' + kwargs['node'] + '%')
            if 'ref' in kwargs:
                query = query.where(bst.c.ref == kwargs['ref'])
            if 'repository' in kwargs:
                query = query.where(bst.c.project == kwargs['repository'])
            if 'change' in kwargs:
                query = query.where(bst.c.change == kwargs['change'])
            if 'patchset' in kwargs:
                query = query.where(bst.c.patchset == kwargs['patchset'])
            if 'score' in kwargs:
                query = query.where(bst.c.score == kwargs['score'])
            # TODO what's the exception for no results again?
            for b in conn.execute(query).fetchall():
                build = builds.Build(build_id=b[0], pipeline=b[12],
                                     repository=b[13], change=b[14],
                                     patchset=b[15], ref=b[16], uuid=b[2],
                                     job_name=b[3], result=b[4],
                                     start_time=b[5], end_time=b[6],
                                     voting=b[7], log_url=b[8],
                                     node_name=b[9], buildset_id=b[1])
                results.append(build)
        return results

    def _get_from_status_url(self, **kwargs):
        # TODO
        return []


class ZuulBuildSetManager(builds.BuildSetManager):
    def __init__(self, manager):
        super(ZuulBuildSetManager, self).__init__()
        self.manager = manager

    @base.paginate
    def get(self, **kwargs):
        if 'order_by' not in kwargs:
            kwargs['order_by'] = 'id'

        results = []
        results += self._get_from_db(**kwargs)
        results += self._get_from_status_url(**kwargs)
        return results

    def _get_from_db(self, **kwargs):
        c = self.manager.connection
        with c.engine.begin() as conn:
            query = c.zuul_buildset_table.join(c.zuul_build_table).select()
            conn.execute(query).fetchone()

    def _get_from_status_url(self, **kwargs):
        # TODO
        return []
