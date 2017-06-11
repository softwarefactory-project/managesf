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


import logging

from managesf.services import base


logger = logging.getLogger(__name__)


class SFZuulJobManager(base.JobManager):
    """Jobs management plugin for Zuul"""
    def __init__(self, plugin):
        super(SFZuulJobManager, self).__init__(plugin)

    def get_job(self, job_name, job_id=None,
                change=None, patchset=None, **kwargs):
        """lists one or several jobs depending on filtering with kwargs."""
        if not job_name:
            raise ValueError("Please specify a job name")
        if job_id and change:
            raise ValueError("Please specify either job or change number")
        if patchset and not change:
            raise ValueError("Please specify a change number")
        if job_id:
            job = self.get_job_status(job_name, int(job_id))
            return [job, ]
        # BLAH

    def get_job_parameters(self, job_name, job_id):
        """For zuul jobs, parameters consist more of jobs details
        as they are stored by the SQL reporter. The following elements
        are fetched:
        pipeline
        project
        change
        patchset
        ref
        buildset_id
        result
        start_time
        end_time
        voting
        logs_url
        node"""

    def get_job_status(self, job_name, job_id):
        """get a job's current status. Does not account for queued jobs"""
        client = self.plugin.get_client()
        with client.engine.begin() as conn:
            query = s.zuul_build_table.join(s.zuul_buildset_table).select()
            conn.execute(query).fetchone()
        status = {'job_name': job_name,
                  'job_id': job_id,
                  'status': None}
        return status

    def get_job_logs(self, job_name, job_id):
        """get logs of a finished job"""
        session = self.plugin.get_client()
        status = {'job_name': job_name,
                  'job_id': job_id,
                  'logs_url': None}
        # BLAH
        return status

    def run(self, job_name, job_parameters=None):
        """run a job"""
        # TODO
        raise NotImplementedError("Cannot start a job with Zuul")


    def stop(self, job_name, job_id):
        """stop a running job"""
        # TODO
        raise NotImplementedError("Cannot start a job with Zuul")
