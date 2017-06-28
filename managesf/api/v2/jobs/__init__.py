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


class JobManager(base.BaseCRUDManager):
    """Jobs related operations."""

    def __init__(self):
        super(JobManager, self).__init__()
        self.ordering_options = ['name', 'repository', 'pipeline']

    def create(self, **kwargs):
        """Not relevant here"""
        # This can be achieved by a "retrigger" in gerrit anyway
        raise NotImplementedError('Jobs are managed within repositories')

    def update(self, **kwargs):
        """Not relevant here"""
        raise NotImplementedError('Jobs are managed within repositories')

    def delete(self, **kwargs):
        """Not relevant here"""
        raise NotImplementedError('Jobs are managed within repositories')

    def get(self, **kwargs):
        """lists one or several jobs depending on filtering with kwargs.
        Possible filtering arguments:
        name: the name of the job
        repository: the git repository on which the job is built
        pipeline: the pipeline to which the job is built
        """
        raise NotImplementedError


class Job(base.Data):
    def __init__(self, name, repository, pipeline,
                 last_success=None, last_failure=None, **kwargs):
        # since jobs names are potentially not unique, compute a unique id
        # in case we need one
        self.id = "%s/%s" % (repository, name)
        self.name = name
        self.pipeline = pipeline
        self.repository = repository
        # last_success, last_failure are intended to be Build objects
        self.last_success = last_success
        self.last_failure = last_failure

    def to_dict(self):
        d = {'name': self.name,
             'id': self.id,
             'pipeline': self.pipeline,
             'repository': self.repository,
             'last_success': None,
             'last_failure': None, }
        if self.last_success is not None:
            d['last_success'] = self.last_success.to_dict()
        if self.last_failure is not None:
            d['last_failure'] = self.last_failure.to_dict()
        return d


class JobServiceManager(base.BaseService):
    # placeholders
    jobs = JobManager()
