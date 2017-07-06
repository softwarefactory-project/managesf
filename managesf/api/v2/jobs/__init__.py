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


from operator import itemgetter

from managesf.api.v2 import base


class JobManager(base.BaseCRUDManager):
    """Jobs related operations."""

    def __init__(self):
        super(JobManager, self).__init__()
        self.ordering_options = ['last_run', 'job_name',
                                 'repository', 'exec_count']

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
        per_repo: (boolean) if set to True, distinguish jobs per repo, default
          is False
        Possible filtering arguments:
        job_name: the name of the job
        repository: the git repository on which the job is built
        pipeline: the pipeline to which the job is built
        """
        raise NotImplementedError


class Job(base.Data):
    """job info"""
    def __init__(self, name, repository=None,
                 last_successes=None, last_failures=None, exec_count=0,
                 **kwargs):
        if repository:
            self.id = "%s/%s" % (repository, name)
        else:
            self.id = name
        self.name = name
        self.last_successes = last_successes or []
        self.last_failures = last_failures or []
        self.exec_count = exec_count

    def to_dict(self):
        d = {'name': self.name,
             'id': self.id,
             'last_successes': {},
             'last_failures': {},
             'exec_count': self.exec_count, }
        d['last_successes'] = sorted(
            [s.to_dict() for s in self.last_successes],
            key=itemgetter('start_time'), reverse=True)
        d['last_failures'] = sorted(
            [s.to_dict() for s in self.last_failures],
            key=itemgetter('start_time'), reverse=True)
        return d


class JobServiceManager(base.BaseService):
    # placeholders
    jobs = JobManager()
