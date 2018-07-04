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
        self.ordering_options = ['last_run', 'name', 'exec_count']

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
    """job info"""
    def __init__(self, name,
                 last_success=None, last_failure=None,
                 last_run=None,  exec_count=0,
                 **kwargs):
        self.id = name
        self.name = name
        self.last_success = last_success or None
        self.last_run = last_run or None
        self.last_failure = last_failure or None
        self.exec_count = exec_count

    def to_dict(self):
        d = {'name': self.name,
             'id': self.id,
             'last_success': self.last_success,
             'last_failure': self.last_failure,
             'last_run': self.last_run,
             'exec_count': self.exec_count, }
        for l in ['last_success', 'last_failure', 'last_run']:
            if d[l]['start_time']:
                d[l]['start_time'] = d[l]['start_time'].strftime(base.isotime)
            if d[l]['end_time']:
                d[l]['end_time'] = d[l]['end_time'].strftime(base.isotime)
        return d


class JobServiceManager(base.BaseService):
    # placeholders
    jobs = JobManager()