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


from managesf.api.v2 import base


class BuildSetManager(base.BaseCRUDManager):
    """Buildsets related operations."""

    def __init__(self):
        super(BuildSetManager, self).__init__()
        self.ordering_options = ['id', 'pipeline', 'repository', 'change',
                                 'score']

    def create(self, **kwargs):
        """Not relevant here"""
        # This can be achieved by a "retrigger" in gerrit anyway
        raise NotImplementedError

    def update(self, **kwargs):
        """Not relevant here"""
        raise NotImplementedError

    def delete(self, **kwargs):
        """shortcut to stop all running builds for a given buildset"""
        raise NotImplementedError

    def get(self, **kwargs):
        """lists one or several buildsets depending on filtering with kwargs.
        Possible filtering arguments:
        ref: the git reference of the commit on which the buildset is based
        repository: the git repository from which the ref is taken
        change: the gerrit change, if relevant
        patchset: the patchset version of the change, if relevant
        zuul_ref: an internal zuul reference
        buildset_id: the buildset id (ie its number in chronological order)
        pipeline: the pipeline in which the buildset was triggered
        score: the score of the buildset
        """
        raise NotImplementedError


class BuildSet(base.Data):
    def __init__(self, buildset_id, zuul_ref, pipeline, repository, change,
                 patchset, ref, score, message, builds=[], **kwargs):
        self.id = buildset_id
        self.zuul_ref = zuul_ref
        self.pipeline = pipeline
        self.repository = repository
        self.change = change
        self.patchset = patchset
        self.ref = ref
        self.score = score
        self.message = message
        self.builds = builds

    def to_dict(self):
        return {'id': self.id,
                'zuul_ref': self.zuul_ref,
                'pipeline': self.pipeline,
                'repository': self.repository,
                'change': self.change,
                'patchset': self.patchset,
                'ref': self.ref,
                'score': self.score,
                'message': self.message,
                'builds': [b.to_dict() for b in self.builds]}


class BuildManager(base.BaseCRUDManager):
    """Builds related operations."""

    def __init__(self):
        super(BuildManager, self).__init__()
        self.ordering_options = ['id', 'buildset_id', 'pipeline', 'change',
                                 'repository', 'result', 'job_name',
                                 'start_time', 'end_time', ]

    def delete(self, build_id, **kwargs):
        """stop a running build."""
        raise NotImplementedError

    def get(self, **kwargs):
        """lists one or several builds depending on filtering with kwargs.
        Possible filtering arguments:
        job_name: the name of the job being built
        id: the build id (ie its number in chronological order)
        ref: the git reference of the commit on which the build is based
        repository: the git repository from which the ref is taken
        change: the gerrit change, if relevant
        patchset: the patchset version of the change, if relevant
        zuul_ref: an internal zuul reference
        uuid: the internal zuul uuid for the build
        buildset_id: the build set builds belong to
        pipeline: the pipeline in which the build belongs to
        started_before: build was started before this timestamp
        started_after: build was started after this timestamp
        result: the result of the build
        voting: whether the build is voting or non-voting
        node: find builds on nodes matching '%node%'"""
        raise NotImplementedError

    def create(self, **kwargs):
        """start a build"""
        raise NotImplementedError

    def update(self, **kwargs):
        """Not relevant here"""
        raise NotImplementedError


class Build(base.Data):
    def __init__(self, build_id, pipeline, repository, change,
                 patchset, ref, uuid, job_name, result, start_time, end_time,
                 voting, log_url, node_name, buildset_id=None, **kwargs):
        self.id = build_id
        self.buildset_id = buildset_id
        self.pipeline = pipeline
        self.repository = repository
        self.change = change
        self.patchset = patchset
        self.ref = ref
        self.uuid = uuid
        self.job_name = job_name
        self.result = result
        self.start_time = start_time
        self.end_time = end_time
        self.voting = voting
        self.log_url = log_url
        self.node_name = node_name

    def to_dict(self):
        return {'id': self.id,
                'buildset_id': self.buildset_id,
                'pipeline': self.pipeline,
                'repository': self.repository,
                'change': self.change,
                'patchset': self.patchset,
                'ref': self.ref,
                'uuid': self.uuid,
                'job_name': self.job_name,
                'result': self.result,
                'start_time': self.start_time.strftime(base.isotime),
                'end_time': self.end_time.strftime(base.isotime),
                'voting': self.voting,
                'log_url': self.log_url,
                'node_name': self.node_name}


class BuildServiceManager(base.BaseService):
    # placeholders
    builds = BuildManager()
    buildsets = BuildSetManager()
