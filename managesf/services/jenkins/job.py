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
import urllib
import urlparse

from managesf.services import base


logger = logging.getLogger(__name__)


GROOVY_JOB_FILTER = """import hudson.model.*
def matchedJobs = Jenkins.instance.items.findAll { job ->
    job.name == "%(JOB_NAME)s"
}

buildIds = ""

matchedJobs.each { item ->

    def builds = item.getBuilds()

    builds.each { build ->
        def params = build.getBuildVariables()
        def status = build.getBuildStatusSummary().message
        def change = params.get('ZUUL_CHANGE')
        def patchset = params.get('ZUUL_PATCHSET')
        if ( %(FILTER_CONDITION)s ) {
            if (buildIds == "") {
                buildIds = "${build.number}"
            } else {
                buildIds = "${buildIds} ${build.number}"
            }
        }
    }
}
return buildIds"""


class SFJenkinsJobManager(base.JobManager):
    """Jobs management plugin

    Note that 'jobs' here should be understood as 'builds' in the Jenkins
    terminology. Jobs management must still be done through the config
    repository."""
    def __init__(self, plugin):
        super(SFJenkinsJobManager, self).__init__(plugin)

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
        # use some filtering
        filter = {"JOB_NAME": job_name, }
        filter_condition = []
        if change:
            filter_condition.append('change == "%s"' % change)
        if patchset:
            filter_condition.append('patchset == "%s"' % patchset)
        if filter_condition:
            filter["FILTER_CONDITION"] = " && ".join(filter_condition)
        else:
            # Get all of the jobs
            filter["FILTER_CONDITION"] = "1 == 1"
        client = self.plugin.get_client()
        msg = u'[%s] querying jobs with filter: %r'
        logger.debug(msg % (self.plugin.service_name,
                            filter))
        script = urllib.quote_plus(GROOVY_JOB_FILTER % filter)
        results = client.run_script(script)
        # strip prefix and trailing \n
        if results.startswith("Result: "):
            if results.endswith('\n'):
                results = results[:-1]
            results = [u for u in results[len("Result: "):].split(" ")
                       if u != '']
        else:
            return []
        return [self.get_job_status(job_name, int(i)) for i in results]

    def get_job_parameters(self, job_name, job_id):
        """get parameters used to run a job"""
        client = self.plugin.get_client()
        try:
            actions = client.get_build_info(job_name, int(job_id))['actions']
            params = {}
            for a in actions:
                if a.get('parameters'):
                    params = a
            return {'job_name': job_name,
                    'job_id': job_id,
                    'parameters': params['parameters']}
        except (KeyError, IndexError) as e:
            msg = u'[%s] job parameters fetching failed for job %s,%s: %s'
            logger.debug(msg % (self.plugin.service_name,
                                job_name,
                                job_id,
                                e.msg))
            return {'job_name': job_name,
                    'job_id': job_id,
                    'parameters': []}
        except Exception as e:
            raise

    def get_job_status(self, job_name, job_id):
        """get a job's current status. Does not account for queued jobs"""
        client = self.plugin.get_client()
        status = {'job_name': job_name,
                  'job_id': job_id,
                  'status': None}
        try:
            build_info = client.get_build_info(job_name, int(job_id))
            if build_info.get('building'):
                status['status'] = 'IN_PROGRESS'
            else:
                status['status'] = build_info.get('result')
        except Exception:
            raise
        return status

    def get_job_logs(self, job_name, job_id):
        """get logs of a finished job"""
        client = self.plugin.get_client()
        status = {'job_name': job_name,
                  'job_id': job_id,
                  'logs_url': None}
        try:
            build_info = client.get_build_info(job_name, int(job_id))
            status['logs_url'] = build_info.get('url')
            if status['logs_url']:
                logs_suffix = "timestamps/?time=MMM+dd+HH:mm:ss.SSS&appendLog"
                status['logs_url'] = urlparse.urljoin(status['logs_url'],
                                                      logs_suffix)
            return status
        except Exception:
            raise

    def run(self, job_name, job_parameters=None):
        """run a job"""
        client = self.plugin.get_client()
        # This seems prone to race conditions, but that's an inherent
        # problem with how Jenkins' API works...
        next_build = client.get_job_info(job_name)['nextBuildNumber']
        try:
            client.build_job(job_name, parameters=job_parameters)
            msg = u'[%s] job started manually: %s/%s'
            logger.debug(msg % (self.plugin.service_name,
                                job_name, next_build))
        except Exception as e:
            msg = u'[%s] job execution failed: %s'
            logger.error(msg % (self.plugin.service_name,
                                e.msg))
            raise
        status = {'job_name': job_name,
                  'job_id': next_build,
                  'status': None}
        try:
            build_info = client.get_build_info(job_name, int(next_build))
            if build_info.get('building'):
                status['status'] = 'IN_PROGRESS'
            elif build_info.get('result'):
                status['status'] = build_info.get('result')
            else:
                status['status'] = 'PENDING'
        # TODO Finer exception handling, this should be only if build not found
        except Exception as e:
            status['status'] = 'PENDING'
        return status

    def stop(self, job_name, job_id):
        """stop a running job"""
        client = self.plugin.get_client()
        client.stop_build(job_name, int(job_id))
        msg = u'[%s] job stopped manually: %s/%s'
        logger.debug(msg % (self.plugin.service_name,
                            job_name, job_id))
        return self.get_job_status(job_name, int(job_id))
