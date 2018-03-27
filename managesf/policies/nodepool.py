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


from oslo_policy import policy

from managesf.policies import base


BASE_POLICY_NAME = 'nodepool'
POLICY_ROOT = BASE_POLICY_NAME + '.%(endpoint)s:%(action)s'


rules = [
    policy.RuleDefault(
        name=POLICY_ROOT % {'endpoint': 'image', 'action': 'list'},
        check_str=base.RULE_ANY),
    policy.RuleDefault(
        name=POLICY_ROOT % {'endpoint': 'dib-image', 'action': 'list'},
        check_str=base.RULE_ANY),
    policy.RuleDefault(
        name=POLICY_ROOT % {'endpoint': 'node', 'action': 'list'},
        check_str=base.RULE_ANY),
    policy.RuleDefault(
        name=POLICY_ROOT % {'endpoint': 'label', 'action': 'list'},
        check_str=base.RULE_ANY),
    policy.RuleDefault(
        name=POLICY_ROOT % {'endpoint': 'request', 'action': 'list'},
        check_str=base.RULE_ANY),
    # privileged actions
    policy.RuleDefault(
        name=POLICY_ROOT % {'endpoint': 'node', 'action': 'hold'},
        check_str=base.RULE_ADMIN_OR_SERVICE),
    policy.RuleDefault(
        name=POLICY_ROOT % {'endpoint': 'node', 'action': 'delete'},
        check_str=base.RULE_ADMIN_OR_SERVICE),
    policy.RuleDefault(
        name=POLICY_ROOT % {'endpoint': 'image', 'action': 'delete'},
        check_str=base.RULE_ADMIN_OR_SERVICE),
    policy.RuleDefault(
        name=POLICY_ROOT % {'endpoint': 'dib-image', 'action': 'build'},
        check_str=base.RULE_ADMIN_OR_SERVICE),
    policy.RuleDefault(
        name=POLICY_ROOT % {'endpoint': 'dib-image', 'action': 'delete'},
        check_str=base.RULE_ADMIN_OR_SERVICE),
]


def list_rules():
    return rules
