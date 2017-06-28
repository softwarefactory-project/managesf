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

from sqlalchemy import desc

from managesf.api.v2 import base
from managesf.api.v2.builds.services.sfzuul import ZuulSQLConnection
from managesf.api.v2.managers import build_manager
from managesf.api.v2 import jobs


logger = logging.getLogger(__name__)


class ZuulJobsManager(jobs.JobServiceManager):

    _config_section = "zuul"
    service_name = "zuul"

    def __init__(self, conf):
        super(jobs.JobServiceManager, self).__init__(conf)
        dburi = self.conf.get('dburi')
        self.connection = ZuulSQLConnection('managesf-zuul-jobs',
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
        if 'per_repo' not in kwargs:
            kwargs['per_repo'] = False
        if kwargs['order_by'] == 'repository' and kwargs['per_repo']:
            raise Exception("Jobs must be distinguished per repo in order "
                            "to be ordered per repository")
        with c.engine.begin() as conn:
            # get the pipelines
            query = bst.select().group_by(bst.c.pipeline)
            pipelines = [u[2] for u in conn.execute(query).fetchall()]
            # TODO how do you select just the columns you need?
            query = bt.join(bst).select()
            if 'job_name' in kwargs:
                query = query.where(bt.c.job_name == kwargs['job_name'])
            if 'repository' in kwargs:
                query = query.where(bst.c.project == kwargs['repository'])
            if 'pipeline' in kwargs:
                query = query.where(bst.c.pipeline == kwargs['pipeline'])
            if kwargs['per_repo']:
                query = query.group_by(bst.c.project)
            # query = query.group_by(bst.c.pipeline)
            query = query.group_by(bt.c.job_name)
            count_query = query
            # TODO this is suboptimal, loads all jobs in memory ...
            # must find how SQLAlchemy handles this
            total = len(conn.execute(count_query).fetchall())
            if 'order_by' in kwargs:
                order = {'last_run': desc(bt.c.start_time),
                         'name': bt.c.job_name,
                         'repository': bst.c.project}
                query = query.order_by(order[kwargs['order_by']])
            query = query.limit(kwargs['limit']).offset(kwargs['skip'])
            logger.debug(str(query.compile(
                compile_kwargs={"literal_binds": True})))
            # TODO what's the exception for no results again?
            for j in conn.execute(query).fetchall():
                # get execution count
                c_query = bt.join(bst).select()
                c_query = c_query.where(bt.c.job_name == j[3])
                if kwargs['per_repo']:
                    c_query = c_query.where(bst.c.project == j[13])
                # TODO suboptimal
                exec_count = len(conn.execute(c_query).fetchall())
                last_successes = {}
                last_failures = {}
                for pl in pipelines:
                    s_query = bt.join(bst).select()
                    s_query = s_query.where(bt.c.job_name == j[3])
                    if kwargs['per_repo']:
                        s_query = s_query.where(bst.c.project == j[13])
                    s_query = s_query.where(bst.c.pipeline == pl)
                    s_query = s_query.where(bt.c.result == 'SUCCESS')
                    s_query = s_query.order_by(desc(bt.c.start_time))
                    logger.info(s_query.compile(
                        compile_kwargs={"literal_binds": True}))
                    last_success = conn.execute(s_query).fetchone()
                    logger.info(last_success)
                    if last_success is not None:
                        r = build_manager.builds.get(id=last_success[0])
                        last_successes[pl] = r['results'][0]
                    f_query = bt.join(bst).select()
                    f_query = f_query.where(bt.c.job_name == j[3])
                    if kwargs['per_repo']:
                        f_query = f_query.where(bst.c.project == j[13])
                    f_query = f_query.where(bst.c.pipeline == pl)
                    f_query = f_query.where(bt.c.result == 'FAILURE')
                    f_query = f_query.order_by(desc(bt.c.start_time))
                    last_failure = conn.execute(f_query).fetchone()
                    if last_failure is not None:
                        r = build_manager.builds.get(id=last_failure[0])
                        last_failures[pl] = r['results'][0]
                rep = None
                if kwargs['per_repo']:
                    rep = j[13]
                job = jobs.Job(name=j[3], repository=rep, pipeline=j[12],
                               last_successes=last_successes,
                               last_failures=last_failures,
                               exec_count=exec_count)
                results.append(job)
        return results, total
