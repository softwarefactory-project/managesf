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


from sqlalchemy import desc, func
from sqlalchemy.sql import select
from sqlalchemy.sql.expression import alias

from managesf.api.v2 import base
from managesf.api.v2.builds.services.sfzuul import ZuulSQLConnection
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

    def _build_last_table(self, last_type=None, **kwargs):
        """build a subquery creating the following table:
        |job_name|last_X_build_id|last_X_start_time|
        last_X_end_time|last_X_duration| where X is 'last_type': 'success',
        'failure' or ''."""
        # 'SUCCESS', 'FAILURE' or None
        if not last_type:
            last_type = ''
        lt = last_type.lower()
        c = self.manager.connection
        bt = c.zuul_build_table.alias('BT_%s' % (lt or 'RUN'))

        def max_join():
            cols = [bt.c.job_name, bt.c.id,
                    func.max(bt.c.start_time).
                    label('last_%s_start_time' % (lt or 'run'))]
            query = select(cols).select_from(bt)
            if lt != '':
                query = query.where(bt.c.result == lt.upper())
            query = query.group_by(bt.c.job_name)
            return query.alias('MAX_%s' % (lt or 'RUN'))

        sq = max_join()
        cols = [bt.c.job_name,
                bt.c.id.label('last_%s_build_id' % (lt or 'run')),
                getattr(sq.c, "last_%s_start_time" % (lt or 'run')),
                bt.c.end_time.label('last_%s_end_time' % (lt or 'run')), ]
        q = select(cols).select_from(bt.join(sq, sq.c.id == bt.c.id))
        return q.alias('LAST_%s' % (lt or 'RUN'))

    def _get_base_query(self, **kwargs):
        c = self.manager.connection
        bt = c.zuul_build_table.alias('JOB_BT')
        job_cols = [bt.c.job_name.label('job'),
                    func.count(bt.c.job_name).label('exec_count')]
        job = select(job_cols).select_from(bt).group_by(bt.c.job_name)
        l_success = self._build_last_table('SUCCESS')
        l_failure = self._build_last_table('FAILURE')
        l_run = self._build_last_table()
        to_select = [job.c.job, job.c.exec_count,
                     # Last success data
                     l_success.c.last_success_build_id,
                     l_success.c.last_success_start_time,
                     l_success.c.last_success_end_time,
                     # Last failure data
                     l_failure.c.last_failure_build_id,
                     l_failure.c.last_failure_start_time,
                     l_failure.c.last_failure_end_time,
                     # Last run data
                     l_run.c.last_run_build_id,
                     l_run.c.last_run_start_time,
                     l_run.c.last_run_end_time, ]
        select_from = job.alias('JOB').outerjoin(
            l_success,
            job.c.job == l_success.c.job_name)
        select_from = select_from.outerjoin(
            l_failure,
            job.c.job == l_failure.c.job_name)
        select_from = select_from.outerjoin(
            l_run,
            job.c.job == l_run.c.job_name)
        if 'repository' in kwargs or 'pipeline' in kwargs:
            rp_bst = c.zuul_buildset_table.alias('RP_BST')
            rp_bt = c.zuul_build_table.alias('RP_BT')
            rp_table = select([rp_bt.c.job_name, rp_bst.c.project,
                               rp_bst.c.pipeline])
            rp_table = rp_table.select_from(rp_bt.join(rp_bst))
            rp_table = (rp_table.group_by(rp_bst.c.pipeline)
                        .group_by(rp_bst.c.project)
                        .group_by(rp_bt.c.job_name)).alias('REPO_PIPE_TBL')
            select_from = select_from.join(
                rp_table,
                job.c.job == rp_table.c.job_name)
        query = select(to_select).select_from(select_from)
        if 'repository' in kwargs:
            query = query.where(rp_table.c.project == kwargs['repository'])
        if 'pipeline' in kwargs:
            query = query.where(rp_table.c.pipeline == kwargs['pipeline'])
        if 'name' in kwargs:
            query = query.where(job.c.job == kwargs['name'])
        query = query.group_by(job.c.job)
        self._logger.debug(str(query.compile(
            compile_kwargs={"literal_binds": True})))
        return query, job, l_success, l_failure, l_run

    def _paginate_query(self, query, job, l_success, l_failure, l_run,
                        **kwargs):
        if 'order_by' in kwargs:
            order = {'last_run': l_run.c.last_run_start_time,
                     'name': job.c.job,
                     'exec_count': job.c.exec_count}
        if kwargs.get('desc'):
            query = query.order_by(desc(order[kwargs['order_by']]))
        else:
            query = query.order_by(order[kwargs['order_by']])
        query = query.limit(kwargs['limit']).offset(kwargs['skip'])
        self._logger.debug(str(query.compile(
            compile_kwargs={"literal_binds": True})))
        with open('/tmp/query', 'w') as f:
            f.write(str(query.compile(
                compile_kwargs={"literal_binds": True})))
        return query

    @base.paginate
    def get(self, **kwargs):
        c = self.manager.connection
        results = []
        # prepare queries
        base_query, job, l_s, l_f, l_run = self._get_base_query(**kwargs)
        # Get the total amount of results
        query_alias = alias(base_query, 'count_alias')
        count = select([func.count('*')]).select_from(query_alias)
        self._logger.debug(str(count.compile(
             compile_kwargs={"literal_binds": True})))
        paginated_query = self._paginate_query(base_query, job, l_s,
                                               l_f, l_run,
                                               **kwargs)
        with c.engine.begin() as conn:
            total = conn.execute(count).fetchall()
            if total:
                total = total[0][0]
            else:
                total = 0
            for j in conn.execute(paginated_query):
                exec_count = j[1]
                s_duration = None
                f_duration = None
                l_duration = None
                if j[4] and j[3]:
                    s_duration = (j[4] - j[3]).seconds
                if j[7] and j[6]:
                    f_duration = (j[7] - j[6]).seconds
                if j[10] and j[9]:
                    l_duration = (j[10] - j[9]).seconds
                job = jobs.Job(name=j[0],
                               last_success={'id': j[2],
                                             'start_time': j[3],
                                             'end_time': j[4],
                                             'duration': s_duration},
                               last_failure={'id': j[5],
                                             'start_time': j[6],
                                             'end_time': j[7],
                                             'duration': f_duration},
                               last_run={'id': j[8],
                                         'start_time': j[9],
                                         'end_time': j[10],
                                         'duration': l_duration},
                               exec_count=exec_count)
                results.append(job)
        return results, total
