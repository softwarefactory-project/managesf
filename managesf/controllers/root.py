# Copyright (C) 2014 eNovance SAS <licensing@enovance.com>
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
from pecan.rest import RestController
from pecan import request, response
from stevedore import driver

from managesf.controllers import introspection
from managesf.services import base
from managesf import policy

from managesf import DEFAULT_SERVICES
from managesf.controllers.api.v2 import resources as v2_resources
from managesf.controllers.api.v2 import configurations as v2_configurations


logger = logging.getLogger(__name__)

LOGERRORMSG = "Unable to process client request, failed with "\
              "unhandled error: %s"
CLIENTERRORMSG = "Unable to process your request, failed with "\
                 "unhandled error (server side): %s"

# TODO: add detail (detail arg or abort function) for all abort calls.


# instanciate service plugins
SF_SERVICES = []
SERVICES = {}


def load_services():
    try:
        if conf.services:
            services = conf.services
        else:
            services = DEFAULT_SERVICES
            msg = 'No service configured, loading: %s' % DEFAULT_SERVICES
            logger.info(msg)
    except AttributeError:
        services = DEFAULT_SERVICES
        msg = 'Obsolete conf file, loading default: %s' % DEFAULT_SERVICES
        logger.info(msg)

    for service in services:
        try:
            plugin = driver.DriverManager(namespace='managesf.service',
                                          name=service,
                                          invoke_on_load=True,
                                          invoke_args=(conf,)).driver
            SF_SERVICES.append(plugin)
            SERVICES[service] = plugin
            logger.info('%s plugin loaded successfully' % service)
        except Exception as e:
            logger.error('Could not load service %s: %s' % (service, e))


def is_admin(user):
    return base.RoleManager.is_admin(user)


def report_unhandled_error(exp):
    logger.exception(LOGERRORMSG % str(exp))
    response.status = 500
    return CLIENTERRORMSG % str(exp)

# TODO move to utils and use resources rather than gerrit for groups


def authorize(rule_name, target):
    if not request.remote_user:
        request.remote_user = request.headers.get('X-Remote-User')
    credentials = {'username': request.remote_user, 'groups': []}
    # OpenID Connect authentication
    if request.headers.get("OIDC_CLAIM_groups", None) is not None:
        for group in request.headers.get('OIDC_CLAIM_groups').split(','):
            # it seems like keycloak prefixes groups with /, remove it
            if group.startswith('/'):
                credentials['groups'].append(group[1:])
            else:
                credentials['groups'].append(group)
    # gerrit based
    else:
        if request.remote_user:
            code_reviews = [s for s in SF_SERVICES
                            if isinstance(s, base.BaseCodeReviewServicePlugin)]
            if code_reviews:
                user_groups = code_reviews[0].project.get_user_groups(
                    request.remote_user)
                credentials['groups'] = [grp['name'] for grp in user_groups]
    return policy.authorize(rule_name, target, credentials)


load_services()


# API v2 - will be in its own file hierarchy once dependencies are sorted out


class V2Controller(object):
    # Mimic api v1 and replace endpoints incrementally
    about = introspection.IntrospectionController()
    resources = v2_resources.ResourcesRootController()
    configurations = v2_configurations.ConfigurationController()


class RootController(object):
    def __init__(self, *args, **kwargs):
        try:
            # just try to get the api config
            _ = conf.api.v2  # noQA
            self.v2 = V2Controller()
        except AttributeError:
            # TODO have a generic blank REST controller that returns
            # 'Not Implemented' error code
            logger.info('API v2 is not configured, skipping endpoint.')
            self.v2 = RestController()

        self.about = introspection.IntrospectionController()
