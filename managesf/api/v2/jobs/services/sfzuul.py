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

from operator import attrgetter

from sqlalchemy import desc, func
from sqlalchemy.sql import select
from sqlalchemy.sql.expression import alias

from managesf.api.v2 import base
from managesf.api.v2.builds.services.sfzuul import ZuulSQLConnection
from managesf.api.v2.managers import build_manager
from managesf.api.v2 import jobs


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

    @property
    def pipelines(self):
        c = self.manager.connection
        bst = c.zuul_buildset_table
        with c.engine.begin() as conn:
            query = select([bst.c.pipeline]).group_by(bst.c.pipeline)
            pipelines = [u[0] for u in conn.execute(query)]
        return pipelines

    def _get_base_query(self, **kwargs):
        c = self.manager.connection
        bst = c.zuul_buildset_table
        bt = c.zuul_build_table
        to_select = [bt.c.job_name, func.count(bt.c.job_name)]
        if kwargs['per_repo']:
            to_select.append(bst.c.project)
        query = select(to_select).select_from(bt.join(bst))
        if 'job_name' in kwargs:
            query = query.where(bt.c.job_name == kwargs['job_name'])
        if 'repository' in kwargs:
            query = query.where(bst.c.project == kwargs['repository'])
        if 'pipeline' in kwargs:
            query = query.where(bst.c.pipeline == kwargs['pipeline'])
        if kwargs['per_repo']:
            query = query.group_by(bst.c.project)
        query = query.group_by(bt.c.job_name)
        self._logger.debug(str(query.compile(
            compile_kwargs={"literal_binds": True})))
        return query

    def _paginate_query(self, query, **kwargs):
        c = self.manager.connection
        bst = c.zuul_buildset_table
        bt = c.zuul_build_table
        if 'order_by' in kwargs:
            order = {'last_run': func.max(bt.c.start_time),
                     'job_name': bt.c.job_name,
                     'repository': bst.c.project,
                     'exec_count': 'count_1'}
        if kwargs.get('desc'):
            query = query.order_by(desc(order[kwargs['order_by']]))
        else:
            query = query.order_by(order[kwargs['order_by']])
        query = query.limit(kwargs['limit']).offset(kwargs['skip'])
        self._logger.debug(str(query.compile(
            compile_kwargs={"literal_binds": True})))
        return query

    def _get_last_builds(self, pipelines, job_name, repository=None):
        c = self.manager.connection
        bt = c.zuul_build_table
        bst = c.zuul_buildset_table
        last_successes = []
        last_failures = []
        for pl in pipelines:
            s_query = bt.join(bst).select()
            s_query = s_query.where(bt.c.job_name == job_name)
            if repository:
                s_query = s_query.where(bst.c.project == repository)
            s_query = s_query.where(bst.c.pipeline == pl)
            s_query = s_query.where(bt.c.result == 'SUCCESS')
            s_query = s_query.order_by(desc(bt.c.start_time))
            with c.engine.begin() as conn:
                last_success = conn.execute(s_query).fetchone()
            if last_success is not None:
                r = build_manager.builds.get(id=last_success[0])
                last_successes.append(r['results'][0])
            f_query = bt.join(bst).select()
            f_query = f_query.where(bt.c.job_name == job_name)
            if repository:
                f_query = f_query.where(bst.c.project == repository)
            f_query = f_query.where(bst.c.pipeline == pl)
            f_query = f_query.where(bt.c.result == 'FAILURE')
            f_query = f_query.order_by(desc(bt.c.start_time))
            with c.engine.begin() as conn:
                last_failure = conn.execute(f_query).fetchone()
            if last_failure is not None:
                r = build_manager.builds.get(id=last_failure[0])
                last_failures.append(r['results'][0])
        # sort successes and failures by last run
        return (sorted(last_successes, key=attrgetter('start_time'),
                       reverse=True),
                sorted(last_failures, key=attrgetter('start_time'),
                       reverse=True))

    @base.paginate
    def get(self, **kwargs):
        c = self.manager.connection
        results = []
        if 'per_repo' not in kwargs:
            kwargs['per_repo'] = False
        if kwargs['order_by'] == 'repository' and not kwargs['per_repo']:
            raise Exception("Jobs must be distinguished per repo in order "
                            "to be ordered per repository")
        pipelines = self.pipelines
        # prepare queries
        base_query = self._get_base_query(**kwargs)
        # Get the total amount of results
        query_alias = alias(base_query, 'count_alias')
        count = select([func.count('*')]).select_from(query_alias)
        # self._logger.debug(str(count.compile(
        #     compile_kwargs={"literal_binds": True})))
        paginated_query = self._paginate_query(base_query, **kwargs)
        with c.engine.begin() as conn:
            total = conn.execute(count).fetchall()
            if total:
                total = total[0][0]
            else:
                total = 0
            for j in conn.execute(paginated_query):
                exec_count = j[1]
                rep = None
                if kwargs['per_repo']:
                    rep = j[2]
                last_successes, last_failures = self._get_last_builds(
                    pipelines, job_name=j[0], repository=rep)
                job = jobs.Job(name=j[0], repository=rep,
                               last_successes=last_successes,
                               last_failures=last_failures,
                               exec_count=exec_count)
                results.append(job)
        return results, total
