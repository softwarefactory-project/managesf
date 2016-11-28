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


from jenkins import Jenkins

from managesf.services import base
from managesf.services.jenkins import job


class _Jenkins(base.BaseJobRunnerServicePlugin):
    """Plugin managing the Jenkins job runner service."""

    _config_section = "jenkins"
    service_name = "jenkins"

    def __init__(self, conf):
        super(_Jenkins, self).__init__(conf)

    def get_client(self, cookie=None):
        raise NotImplementedError


class SoftwareFactoryJenkins(_Jenkins):

    def __init__(self, conf):
        super(SoftwareFactoryJenkins, self).__init__(conf)
        self.job = job.SFJenkinsJobManager(self)

    def get_client(self, *args, **kwargs):
        return Jenkins(url=self.conf['api_url'],
                       username=self.conf['user'],
                       password=self.conf['password'])
