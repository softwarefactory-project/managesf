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


from datetime import datetime, timedelta
import logging
from operator import attrgetter

# from zuul.connection.sql import SQLConnection
import requests
import sqlalchemy as sa
from sqlalchemy.sql import select
from sqlalchemy.sql.expression import alias

from managesf.api.v2 import base
from managesf.api.v2 import builds


logger = logging.getLogger(__name__)


def get_time(x, fake_start, attr='start_time'):
    return getattr(x, attr) or fake_start


def compute_ref(change, patchset):
    c, p = str(change), str(patchset)
    if len(c) < 2:
        h = '0' + c
    else:
        h = c[-2:]
    return 'refs/changes/%s/%s/%s' % (h, c, p)


def get_buildsets_from_status_page(url):
    _buildsets = []
    status = requests.get(url)
    if not status.ok:
        logger.info("Could not reach status page: "
                    "query returned %s" % status.status_code)
        return _buildsets
    status_json = status.json()
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
            try:
                change, patchset = _buildset['id'].split(',')
                ref = compute_ref(change, patchset)
            except (ValueError, AttributeError):
                # This is normal with builds post-merge, like the post and tag
                # pipelines (ValueError), and with builds outside of the
                # gerrit workflow, like the periodic pipeline (AttributeError)
                change, patchset = None, None
                ref = _buildset['id']
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
                                 ref=ref,
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


class ZuulSSHConnection(base.SSHConnection):
    def enqueue(self, pipeline, repository, change=None, patchset=None,
                ref=None, oldrev=None, newrev=None):
        """Enqueue a buildset for <repository> on <pipeline>."""
        if change and not patchset:
            patchset = 1
        if change and patchset:
            try:
                xxx = int(change), int(patchset)  # noqa
            except Exception:
                raise ValueError("change, patchset must be integers")
        if (change and ref) or (not change and not ref):
            raise ValueError("enqueueing requires either a patch or a ref")
        if ref and not newrev and not oldrev:
            # use HEAD by default
            newrev = 'HEAD'
        for k in (pipeline, repository, change, patchset, ref, oldrev, newrev):
            if k and not self.validate_input(str(k)):
                raise ValueError("Invalid argument '%s'" % k)
        if not pipeline or not repository:
            raise ValueError(
                "pipeline, repository are mandatory arguments")
        client = self.get_connection()
        CMD = "zuul enqueue"
        if ref:
            CMD += "-ref"
        # TODO uncomment when switching to zuul3 for good
        # Default tenant for SF zuul3 deployment
        # CMD += ' --tenant ""'
        # TODO there should be a specific trigger in zuul's configuration
        # for manually started builds
        CMD += " --trigger gerrit"
        CMD += " --pipeline %s --project %s" % (pipeline, repository)
        if change:
            CMD += " --change %s,%s" % (change, patchset)
        if ref:
            CMD += " --ref %s" % ref
            if oldrev:
                CMD += " --oldrev %s" % oldrev
            if newrev:
                CMD += " --newrev %s" % newrev
        logger.debug("Manual build invoked: %s" % CMD)
        stdin, stdout, stderr = client.exec_command(CMD)
        return_code = int(stdout.channel.recv_exit_status())
        client.close()
        if return_code > 0:
            e = stderr.read()
            m = "Build enqueueing failed with exit code %i: %s"
            m = m % (return_code, e)
            logger.error(m)
            raise Exception(m)


class ZuulBuildsManager(builds.BuildServiceManager):

    _config_section = "zuul"
    service_name = "zuul"

    def __init__(self, conf):
        super(builds.BuildServiceManager, self).__init__(conf)
        dburi = self.conf.get('dburi')
        ssh_host = self.conf.get('ssh_host')
        ssh_key = self.conf.get('ssh_key')
        ssh_user = self.conf.get('ssh_user')
        self.connection = ZuulSQLConnection('managesf-zuul-builds',
                                            {'dburi': dburi})
        self.ssh = ZuulSSHConnection({'ssh_key': ssh_key,
                                      'ssh_host': ssh_host,
                                      'ssh_user': ssh_user, })
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
        total = None
        if kwargs.get('in_progress_only'):
            results = self._get_from_status_url(**kwargs)
        else:
            results, total = self._get_from_db(**kwargs)
        if total is not None:
            return results, total
        else:
            if kwargs['order_by'] in ['start_time', 'end_time']:
                # starting or ending in the future
                fake_time = datetime.now() + timedelta(days=36500)
                return sorted(results,
                              key=lambda x: get_time(x, fake_time,
                                                     kwargs['order_by']),
                              reverse=kwargs['desc'])
            return sorted(results, key=attrgetter(kwargs['order_by']),
                          reverse=kwargs['desc'])

    def _build_query(self, **kwargs):
        c = self.manager.connection
        bt = c.zuul_build_table
        bst = c.zuul_buildset_table
        to_select = [bt.c.id, bst.c.pipeline, bst.c.project, bst.c.change,
                     bst.c.patchset, bst.c.ref, bt.c.uuid, bt.c.job_name,
                     bt.c.result, bt.c.start_time, bt.c.end_time, bt.c.voting,
                     bt.c.log_url, bt.c.node_name, bt.c.buildset_id]
        query = select(to_select).select_from(bt.join(bst))
        if 'id' in kwargs:
            query = query.where(bt.c.id == kwargs['id'])
        if 'uuid' in kwargs:
            query = query.where(bt.c.uuid == kwargs['uuid'])
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
        if 'node_name' in kwargs:
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
        self._logger.debug(str(query.compile(
            compile_kwargs={"literal_binds": True})))
        return query

    def _paginate_db_query(self, query, **kwargs):
        c = self.manager.connection
        bst = c.zuul_buildset_table
        bt = c.zuul_build_table
        if 'order_by' in kwargs:
            order = {'id': bt.c.id,
                     'buildset_id': bt.c.buildset_id,
                     'pipeline': bst.c.pipeline,
                     'change': bst.c.change,
                     'repository': bst.c.project,
                     'result': bt.c.result,
                     'job_name': bt.c.job_name,
                     'start_time': bt.c.start_time,
                     'end_time': bt.c.end_time}
            if kwargs.get('desc'):
                query = query.order_by(sa.desc(order[kwargs['order_by']]))
            else:
                query = query.order_by(order[kwargs['order_by']])
            # order by patchsets within changes
            if kwargs['order_by'] == 'change':
                query = query.order_by(bst.c.patchset)
        query = query.limit(kwargs['limit']).offset(kwargs['skip'])
        self._logger.debug(str(query.compile(
            compile_kwargs={"literal_binds": True})))
        return query

    def _get_from_db(self, **kwargs):
        query = self._build_query(**kwargs)
        query_alias = alias(query, 'count_alias')
        count = select([sa.func.count('*')]).select_from(query_alias)
        query = self._paginate_db_query(query, **kwargs)
        results = []
        c = self.manager.connection
        with c.engine.begin() as conn:
            total = conn.execute(count).fetchall()
            if total:
                total = total[0][0]
            else:
                total = 0
            for b in conn.execute(query):
                build = builds.Build(build_id=b[0], pipeline=b[1],
                                     repository=b[2], change=b[3],
                                     patchset=b[4], ref=b[5], uuid=b[6],
                                     job_name=b[7], result=b[8],
                                     start_time=b[9], end_time=b[10],
                                     voting=b[11], log_url=b[12],
                                     node_name=b[13], buildset_id=b[14])
                results.append(build)
        return results, total

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
            fake_start = datetime.now() + timedelta(days=36500)
            prd.append(
                lambda x: get_time(x, fake_start) < kwargs['started_before'])
        if 'started_after' in kwargs:
            fake_start = datetime.now() - timedelta(days=36500)
            prd.append(
                lambda x: get_time(x, fake_start) >= kwargs['started_after'])
        if 'node_name' in kwargs:
            prd.append(
                lambda x: kwargs['node_name'] in getattr(x, 'node_name'))
        # generic tests

        def _f(k):
            return lambda x: getattr(x, k) == kwargs[k]

        for k in ['job_name', 'ref', 'repository', 'change', 'patchset',
                  'uuid', 'pipeline', 'result', 'voting', ]:
            if k in kwargs:
                prd.append(_f(k))
        results = []
        for bs in status_buildsets:
            for b in bs._builds:
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
        total = None
        if kwargs.get('in_progress_only'):
            results = self._get_from_status_url(**kwargs)
        else:
            results, total = self._get_from_db(**kwargs)
        if total is not None:
            return results, total
        else:
            return sorted(results, key=attrgetter(kwargs['order_by']),
                          reverse=kwargs['desc'])

    def _build_query(self, **kwargs):
        c = self.manager.connection
        bst = c.zuul_buildset_table
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
        self._logger.debug(str(query.compile(
            compile_kwargs={"literal_binds": True})))
        return query

    def _paginate_db_query(self, query, **kwargs):
        c = self.manager.connection
        bst = c.zuul_buildset_table
        if 'order_by' in kwargs:
            order = {'id': bst.c.id,
                     'pipeline': bst.c.pipeline,
                     'change': bst.c.change,
                     'repository': bst.c.project,
                     'score': bst.c.score}
            if kwargs.get('desc'):
                query = query.order_by(sa.desc(order[kwargs['order_by']]))
            else:
                query = query.order_by(order[kwargs['order_by']])
            # order by patchsets within changes
            if kwargs['order_by'] == 'change':
                query = query.order_by(bst.c.patchset)
        query = query.limit(kwargs['limit']).offset(kwargs['skip'])
        self._logger.debug(str(query.compile(
            compile_kwargs={"literal_binds": True})))
        return query

    def _get_from_db(self, **kwargs):
        c = self.manager.connection
        results = []
        query = self._build_query(**kwargs)
        query_alias = alias(query, 'count_alias')
        count = select([sa.func.count('*')]).select_from(query_alias)
        query = self._paginate_db_query(query, **kwargs)
        with c.engine.begin() as conn:
            total = conn.execute(count).fetchall()
            if total:
                total = total[0][0]
            else:
                total = 0
            for bs in conn.execute(query):
                _builds = self.manager.builds.get(buildset_id=bs[0])['results']
                buildset = builds.BuildSet(buildset_id=bs[0], zuul_ref=bs[1],
                                           pipeline=bs[2], repository=bs[3],
                                           change=bs[4], patchset=bs[5],
                                           ref=bs[6], score=bs[7],
                                           message=bs[8], builds=_builds)
                results.append(buildset)
        return results, total

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
                prd.append(_f(k))
        results = []
        for bs in status_buildsets:
            if all(f(bs) for f in prd):
                results.append(bs)
        return results

    def create(self, **kwargs):
        self.manager.ssh.enqueue(**kwargs)
