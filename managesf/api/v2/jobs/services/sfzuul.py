#!/usr/bin/env python
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


import logging

from zuul.connection.sql import SQLConnection

from managesf.api.v2 import base
# from managesf.api.v2.managers import build_manager
from managesf.api.v2 import jobs


logger = logging.getLogger(__name__)


class ZuulJobsManager(jobs.JobServiceManager):

    _config_section = "zuul"
    service_name = "zuul"

    def __init__(self, conf):
        super(jobs.JobServiceManager, self).__init__(conf)
        dburi = self.conf.get('dburi')
        self.connection = SQLConnection('managesf-zuul-jobs',
                                        {'dburi': dburi})
        self.jobs = ZuulJobManager(self)


class ZuulJobManager(jobs.JobManager):
    def __init__(self, manager):
        super(ZuulJobManager, self).__init__()
        self.manager = manager

    @base.paginate
    def get(self, **kwargs):
        c = self.manager.connection
        bt = c.zuul_build_table
        bst = c.zuul_buildset_table
        results = []
        with c.engine.begin() as conn:
            # TODO how do you select just the columns you need?
            query = bt.join(bst).select()
            if 'job_name' in kwargs:
                query = query.where(bt.c.job_name == kwargs['job_name'])
            if 'repository' in kwargs:
                query = query.where(bst.c.project == kwargs['repository'])
            if 'pipeline' in kwargs:
                query = query.where(bst.c.pipeline == kwargs['pipeline'])
            query = query.group_by(bst.c.project)
            query = query.group_by(bst.c.pipeline)
            query = query.group_by(bt.c.job_name)
            logger.debug(str(query.compile(
                compile_kwargs={"literal_binds": True})))
            # TODO what's the exception for no results again?
            for j in conn.execute(query).fetchall():
                last_success = None
                last_failure = None
                job = jobs.Job(name=j[3], repository=j[13], pipeline=j[12],
                               last_success=last_success,
                               last_failure=last_failure)
                results.append(job)
        return results
