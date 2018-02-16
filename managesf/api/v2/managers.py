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
zuul_api_root_url = None
try:
    zuul_api_root_url = conf['zuul']['api_root_url']
except Exception:
    logger.info('Cannot find zuul API root URL in configuration, '
                'skipping endpoint...')
if not zuul_api_root_url:
    logger.info('No zuul API root URL specified in configuration, '
                'skipping endpoint...')
else:
    logger.info('Configuring zuul API proxy...')
    try:
        zuul_proxy = base.RESTAPIProxy(zuul_api_root_url)
    except Exception as e:
        logger.error('Could not configure zuul API proxy: %s' % e)


zuul_admin_proxy = None
zuul_admin_api_root_url = None
try:
    zuul_admin_api_root_url = conf['zuul']['admin_api_root_url']
except Exception:
    logger.info('Cannot find zuul admin API root URL in configuration, '
                'skipping endpoint...')
if not zuul_admin_api_root_url:
    logger.info('No zuul admin API root URL specified in configuration, '
                'skipping endpoint...')
else:
    logger.info('Configuring zuul admin API proxy...')
    try:
        zuul_admin_proxy = base.RESTAPIProxy(zuul_admin_api_root_url)
    except Exception as e:
        logger.error('Could not configure zuul admin API proxy: %s' % e)


nodepool_proxy = None
nodepool_api_root_url = None
try:
    nodepool_api_root_url = conf['nodepool']['api_root_url']
except Exception:
    logger.info('Cannot find nodepool API root URL in configuration, '
                'skipping endpoint...')
if not nodepool_api_root_url:
    logger.info('No nodepool API root URL specified in configuration, '
                'skipping endpoint...')
else:
    logger.info('Configuring nodepool API proxy...')
    try:
        nodepool_proxy = base.RESTAPIProxy(nodepool_api_root_url)
    except Exception as e:
        logger.error('Could not configure nodepool API proxy: %s' % e)


nodepool_admin_proxy = None
nodepool_admin_api_root_url = None
try:
    nodepool_admin_api_root_url = conf['nodepool']['admin_api_root_url']
except Exception:
    logger.info('Cannot find nodepool admin API root URL in configuration, '
                'skipping endpoint...')
if not nodepool_admin_api_root_url:
    logger.info('No nodepool admin API root URL specified in configuration, '
                'skipping endpoint...')
else:
    logger.info('Configuring nodepool admin API proxy...')
    try:
        nodepool_admin_proxy = base.RESTAPIProxy(nodepool_admin_api_root_url)
    except Exception as e:
        logger.error('Could not configure nodepool admin API proxy: %s' % e)
