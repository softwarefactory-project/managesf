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


import logging

from pecan import conf

import base


logger = logging.getLogger(__name__)


build_manager = None
logger.info('Loading builds manager...')
try:
    builds_service = conf.api.v2.builds[0]
    build_manager = base.load_manager('managesf.v2.builds',
                                      builds_service)
except AttributeError as e:
    msg = 'Undefined "builds" API endpoint, skipping.'
    logger.error(msg)
except IndexError:
    msg = 'No build service defined, skipping.'
    logger.error(msg)
except Exception:
    msg = 'Cannot load build service "%s"' % conf.api['v2']['builds'][0]
    logger.error(msg)
    raise


job_manager = None
logger.info('Loading jobs manager...')
try:
    jobs_service = conf.api.v2.jobs[0]
    job_manager = base.load_manager('managesf.v2.jobs',
                                    jobs_service)
except AttributeError as e:
    msg = 'Undefined "jobs" API endpoint, skipping.'
    logger.error(msg)
except IndexError:
    msg = 'No job service defined, skipping.'
    logger.error(msg)
except Exception:
    msg = 'Cannot load job service "%s"' % conf.api['v2']['jobs'][0]
    logger.error(msg)
    raise


resource_manager = None
logger.info('Loading resources manager...')
try:
    resource_manager = base.load_manager('managesf.v2.resources',
                                         'manageSF')
except Exception as e:
    msg = 'Cannot load resource service: %s' % e
    logger.error(msg)
    raise


zuul_proxy = None
logger.info('Configuring zuul API proxy...')

zuul_proxy = base.RESTAPIProxy('https://zuul3.openstack.org/')
