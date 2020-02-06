#
# Copyright (C) 2016 Red Hat
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
# -*- coding: utf-8 -*-


from pecan import conf
from oslo_policy import policy


RULE_ADMIN_OR_SERVICE = 'rule:admin_or_service'
RULE_ADMIN_API = 'rule:admin_api'
RULE_ANY = 'rule:any'
RULE_NONE = 'rule:none'
RULE_OWNER_API = 'rule:owner_api'
RULE_ADMIN_OR_OWNER = 'rule:admin_or_owner'
RULE_PTL_API = 'rule:ptl_api'
RULE_CORE_API = 'rule:core_api'
RULE_DEV_API = 'rule:dev_api'
RULE_CONTRIBUTOR_API = 'rule:contributor_api'
RULE_AUTHENTICATED_API = 'rule:authenticated_api'

# TODO this value should be in the conf
# TODO keycloak stores usernames in lowercase ...
SERVICE_USER = 'SF_SERVICE_USER'

try:
    admin_account = conf.admin['name']
except AttributeError:
    admin_account = 'admin'


@policy.register('is_authenticated')
class IsAuthenticatedCheck(policy.Check):
    """An explicit check for user authentication."""

    def __call__(self, target, creds, enforcer):
        """Determine whether username is set or not."""

        return bool(creds.get('username'))


@policy.register('group')
class GroupCheck(policy.Check):
    """Check that there is a matching group in the ``creds`` dict."""

    def __call__(self, target, creds, enforcer):
        try:
            match = self.match % target
        except KeyError:
            # While doing RoleCheck if key not
            # present in Target return false
            return False
        if 'groups' in creds:
            return match.lower() in [x.lower() for x in creds['groups']]
        return False


rules = [
    policy.RuleDefault('is_admin', 'username:%s' % admin_account),
    policy.RuleDefault('is_service_upper',
                       'username:%s' % SERVICE_USER),
    policy.RuleDefault('is_service_lower',
                       'username:%s' % SERVICE_USER.lower()),
    policy.RuleDefault('is_service',
                       'rule:is_service_lower or rule:is_service_upper'),
    policy.RuleDefault('admin_or_service',
                       'rule:is_admin or rule:is_service'),
    policy.RuleDefault('admin_api', 'rule:is_admin'),
    policy.RuleDefault('is_owner', 'username:%(username)s'),
    policy.RuleDefault('owner_api', 'rule:is_owner'),
    policy.RuleDefault('admin_or_owner',
                       'rule:is_admin or rule:is_owner'),
    policy.RuleDefault('is_ptl', 'group:%(project)s-ptl'),
    policy.RuleDefault('is_core', 'group:%(project)s-core'),
    policy.RuleDefault('is_dev', 'group:%(project)s-dev'),
    policy.RuleDefault('ptl_api', 'rule:is_ptl'),
    policy.RuleDefault('core_api', 'rule:is_core'),
    policy.RuleDefault('dev_api', 'rule:is_dev'),
    policy.RuleDefault('contributor_api',
                       'rule:ptl_api or rule:core_api or rule:dev_api'),
    policy.RuleDefault('authenticated_api',
                       'is_authenticated:True'),
    policy.RuleDefault('any', '@'),
    policy.RuleDefault('none', '!'),
]


def list_rules():
    return rules
