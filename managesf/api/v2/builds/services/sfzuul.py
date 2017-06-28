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


from datetime import datetime
import logging
from operator import attrgetter

# from zuul.connection.sql import SQLConnection
import requests
import sqlalchemy as sa

from managesf.api.v2 import base
from managesf.api.v2 import builds


logger = logging.getLogger(__name__)


def compute_ref(change, patchset):
    c, p = str(change), str(patchset)
    if len(c) < 2:
        h = '0' + c
    else:
        h = c[-2:]
    return 'refs/changes/%s/%s/%s' % (h, c, p)


def get_buildsets_from_status_page(url):
    # TODO handle download errors
    status_json = requests.get(url).json()
    _buildsets = []
    pipelines = status_json['pipelines']
    for p in pipelines:
        pipeline = p['name']
        for queue in p['change_queues']:
            # Actual buildset is last of the patch chain
            patch_chain = queue['heads']
            if not patch_chain:
                continue
            _buildset = patch_chain[0][-1]
            _builds = []
            change, patchset = _buildset['id'].split(',')
            for _build in _buildset['jobs']:
                if _build['start_time']:
                    start_time = datetime.fromtimestamp(
                        float(_build['start_time']))
                else:
                    start_time = None
                if _build['end_time']:
                    end_time = datetime.fromtimestamp(
                        float(_build['end_time']))
                else:
                    end_time = None
                b = builds.Build(build_id=None,
                                 buildset_id=None,
                                 pipeline=pipeline,
                                 repository=_buildset['project'],
                                 change=change,
                                 patchset=patchset,
                                 ref=compute_ref(change, patchset),
                                 uuid=_build['uuid'],
                                 job_name=_build['name'],
                                 result=_build.get('result'),
                                 start_time=start_time,
                                 end_time=end_time,
                                 voting=_build['voting'],
                                 log_url=_build.get('report_url'),
                                 node_name=_build['node_name'])
                _builds.append(b)
            bset = builds.BuildSet(buildset_id=None,
                                   zuul_ref=_buildset['zuul_ref'],
                                   pipeline=pipeline,
                                   repository=_buildset['project'],
                                   change=change,
                                   patchset=patchset,
                                   ref=compute_ref(change, patchset),
                                   score=None,
                                   message=None,
                                   builds=_builds)
            _buildsets.append(bset)
    return _buildsets


class ZuulSQLConnection(base.SQLConnection):
    def get_tables(self):
        try:
            metadata = sa.MetaData()

            self.zuul_buildset_table = sa.Table(
                'zuul_buildset', metadata,
                sa.Column('id', sa.Integer, primary_key=True),
                sa.Column('zuul_ref', sa.String(255)),
                sa.Column('pipeline', sa.String(255)),
                sa.Column('project', sa.String(255)),
                sa.Column('change', sa.Integer, nullable=True),
                sa.Column('patchset', sa.Integer, nullable=True),
                sa.Column('ref', sa.String(255)),
                sa.Column('score', sa.Integer),
                sa.Column('message', sa.TEXT()),
            )

            self.zuul_build_table = sa.Table(
                'zuul_build', metadata,
                sa.Column('id', sa.Integer, primary_key=True),
                sa.Column('buildset_id', sa.Integer,
                          sa.ForeignKey("zuul_buildset.id")),
                sa.Column('uuid', sa.String(36)),
                sa.Column('job_name', sa.String(255)),
                sa.Column('result', sa.String(255)),
                sa.Column('start_time', sa.DateTime()),
                sa.Column('end_time', sa.DateTime()),
                sa.Column('voting', sa.Boolean),
                sa.Column('log_url', sa.String(255)),
                sa.Column('node_name', sa.String(255)),
            )
        except sa.exc.OperationalError:
            logger.error(
                "%s: unable to establish tables" % self.connection_name)


class ZuulBuildsManager(builds.BuildServiceManager):

    _config_section = "zuul"
    service_name = "zuul"

    def __init__(self, conf):
        super(builds.BuildServiceManager, self).__init__(conf)
        dburi = self.conf.get('dburi')
        self.connection = ZuulSQLConnection('managesf-zuul-builds',
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
        return sorted(results, key=attrgetter(kwargs['order_by']))

    def _get_from_db(self, **kwargs):
        c = self.manager.connection
        bt = c.zuul_build_table
        bst = c.zuul_buildset_table
        results = []
        with c.engine.begin() as conn:
            query = bt.join(bst).select()
            if 'id' in kwargs:
                query = query.where(bt.c.id == kwargs['id'])
            if 'buildset_id' in kwargs:
                query = query.where(bt.c.buildset_id == kwargs['buildset_id'])
            if 'job_name' in kwargs:
                query = query.where(bt.c.job_name == kwargs['job_name'])
            if 'result' in kwargs:
                query = query.where(bt.c.result == kwargs['result'])
            if 'started_before' in kwargs:
                cmp = kwargs['started_before'].strftime('%Y-%m-%d %H:%M:%S')
                query = query.where(bt.c.start_time < cmp)
            if 'started_after' in kwargs:
                cmp = kwargs['started_after'].strftime('%Y-%m-%d %H:%M:%S')
                query = query.where(bt.c.start_time >= cmp)
            if 'result' in kwargs:
                query = query.where(bt.c.result == kwargs['result'])
            if 'voting' in kwargs:
                query = query.where(bt.c.voting == kwargs['voting'])
            if 'node' in kwargs:
                query = query.where(
                    bt.c.node_name.like('%' + kwargs['node'] + '%'))
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
            if 'pipeline' in kwargs:
                query = query.where(bst.c.pipeline == kwargs['pipeline'])
            logger.debug(str(query.compile(
                compile_kwargs={"literal_binds": True})))
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
        url = self.manager.status_url
        status_buildsets = get_buildsets_from_status_page(url)
        # cannot filter on the following fields because they're not there:
        if any(k in kwargs for k in ['buildset_id', 'id', 'score', 'message']):
            return []
        prd = []
        # Handle no kwargs
        prd.append(lambda x: True)
        # specific tests
        if 'started_before' in kwargs:
            prd.append(
                lambda x: getattr(x, 'start_time') < kwargs['started_before'])
        if 'started_after' in kwargs:
            prd.append(
                lambda x: getattr(x, 'start_time') >= kwargs['started_after'])
        if 'node_name' in kwargs:
            prd.append(
                lambda x: kwargs['node_name'] in getattr(x, 'node_name'))
        # generic tests

        def _f(k):
            return lambda x: getattr(x, k) == kwargs[k]

        for k in ['pipeline', 'repository', 'change', 'patchset',
                  'ref', 'uuid', 'job_name', 'result', 'voting']:
            if k in kwargs:
                print k
                prd.append(_f(k))
        results = []
        for bs in status_buildsets:
            for b in bs.builds:
                if all(f(b) for f in prd):
                    results.append(b)
        return results


class ZuulBuildSetManager(builds.BuildSetManager):
    def __init__(self, manager):
        super(ZuulBuildSetManager, self).__init__()
        self.manager = manager

    @base.paginate
    def get(self, **kwargs):
        if 'patchset' in kwargs and 'change' not in kwargs:
            raise ValueError('Please specify a change')
        results = []
        results += self._get_from_db(**kwargs)
        results += self._get_from_status_url(**kwargs)
        return sorted(results, key=attrgetter(kwargs['order_by']))

    def _get_from_db(self, **kwargs):
        c = self.manager.connection
        bst = c.zuul_buildset_table
        results = []
        with c.engine.begin() as conn:
            query = bst.select()
            if 'id' in kwargs:
                query = query.where(bst.c.id == kwargs['id'])
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
            if 'pipeline' in kwargs:
                query = query.where(bst.c.pipeline == kwargs['pipeline'])
            if 'zuul_ref' in kwargs:
                query = query.where(bst.c.zuul_ref == kwargs['zuul_ref'])
            logger.debug(str(query.compile(
                compile_kwargs={"literal_binds": True})))
            # TODO what's the exception for no results again?
            for bs in conn.execute(query).fetchall():
                _builds = self.manager.builds.get(id=bs[0])['results']
                buildset = builds.BuildSet(buildset_id=bs[0], zuul_ref=bs[1],
                                           pipeline=bs[2], repository=bs[3],
                                           change=bs[4], patchset=bs[5],
                                           ref=bs[6], score=bs[7],
                                           message=bs[8], builds=_builds)
                results.append(buildset)
        return results

    def _get_from_status_url(self, **kwargs):
        url = self.manager.status_url
        status_buildsets = get_buildsets_from_status_page(url)
        # cannot filter on the following fields because they're not there:
        if any(k in kwargs for k in ['id', 'score', 'message']):
            return []
        prd = []
        # Handle no kwargs
        prd.append(lambda x: True)
        # generic tests

        def _f(k):
            return lambda x: getattr(x, k) == kwargs[k]

        for k in ['ref', 'repository', 'change', 'patchset',
                  'pipeline', 'zuul_ref']:
            if k in kwargs:
                print k
                prd.append(_f(k))
        results = []
        for bs in status_buildsets:
            if all(f(bs) for f in prd):
                results.append(bs)
        return results
