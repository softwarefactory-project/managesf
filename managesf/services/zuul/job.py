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

from sqlalchemy.orm.exc import NoResultFound, MultipleResultsFound
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, String, DateTime, Unicode
from sqlalchemy import Boolean, Integer, ForeignKey

from managesf.services import base


logger = logging.getLogger(__name__)


Base = declarative_base()


class ZuulBuildSet(Base):
    __tablename__ = 'zuul_buildset'
    id = Column(Integer(), primary_key=True)
    zuul_ref = Column(String(255), unique=True)
    pipeline = Column(Unicode(255))
    project = Column(Unicode(1024))
    change = Column(Integer())
    patchset = Column(Integer())
    ref = Column(String(255))
    score = Column(Integer())
    message = Column(Unicode(1024))


class ZuulBuild(Base):
    __tablename__ = 'zuul_buildset'
    id = Column(Integer(), primary_key=True)
    buildset_id = Column(Integer(), ForeignKey('users.user_id'))
    uuid = Column(String(255), unique=True)
    job_name = Column(String(1024))
    result = Column(String(1024))
    start_time = Column(DateTime())
    end_time = Column(DateTime())
    voting = Column(Boolean())
    log_url = Column(Unicode(1024))
    node_name = Column(String(1024))


class SFZuulJobManager(base.JobManager):
    """Jobs management plugin for Zuul"""
    def __init__(self, plugin):
        super(SFZuulJobManager, self).__init__(plugin)

    def get_job(self, job_name, job_id=None,
                change=None, patchset=None, **kwargs):
        """lists one or several jobs depending on filtering with kwargs."""
        # TODO(mhu) add more filtering options depending on demand and needs
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

    def get_job_status(self, job_name, job_id):
        """get a job's current status. Does not account for queued jobs"""
        session = self.plugin.get_client()
        status = {'job_name': job_name,
                  'job_id': job_id,
                  'status': None}
        # BLAH
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
#        client = self.plugin.get_client()
#        try:
#            build_info = client.get_build_info(job_name, int(next_build))
#            if build_info.get('building'):
#                status['status'] = 'IN_PROGRESS'
#            elif build_info.get('result'):
#                status['status'] = build_info.get('result')
#            else:
#                status['status'] = 'PENDING'
#        except Exception as e:
#            status['status'] = 'PENDING'
#        return status

    def stop(self, job_name, job_id):
        """stop a running job"""
        # TODO
        raise NotImplementedError("Cannot start a job with Zuul")
#        client = self.plugin.get_client()
#        return self.get_job_status(job_name, int(job_id))
