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


"""the policy engine for managesf."""


import logging
import os.path

from pecan import conf
from oslo_policy import policy

from managesf import policies


logger = logging.getLogger(__name__)


_ENFORCER = None


class FakeOsloPolicy:
    def __init__(self, policy_file):
        self.policy_dirs = []
        self.policy_default_rule = None
        self.policy_file = policy_file


class FakeOslo:
    def __init__(self, policy_file):
        self.oslo_policy = FakeOsloPolicy(policy_file)

    def register_opts(self, *arg, **kwarg):
        return

    def find_file(self, *arg, **kwarg):
        return self.oslo_policy.policy_file


def reset():
    global _ENFORCER
    if _ENFORCER:
        _ENFORCER.clear()
        _ENFORCER = None


def init(policy_file=None, rules=None):
    """Init an Enforcer class.
       :param policy_file: Custom policy file to use, if none is specified,
                           `CONF.policy_file` will be used.
       :param rules: Default dictionary / Rules to use. It will be
                     considered just in the first instantiation.
    """

    global _ENFORCER
    if not _ENFORCER:
        _ENFORCER = policy.Enforcer(FakeOslo(policy_file),
                                    policy_file=policy_file,
                                    rules=rules,
                                    use_conf=False)
        _ENFORCER.register_defaults(policies.list_rules())
    if policy_file:
        _ENFORCER.load_rules(force_reload=True)
    register_rules(_ENFORCER)


def register_rules(enforcer):
    if not enforcer.rules:
        # Override defaults with the file rules
        for override in enforcer.file_rules.values():
            enforcer.registered_rules[override.name] = override.check
        for default in enforcer.registered_rules.values():
            if default.name not in enforcer.rules:
                enforcer.rules[default.name] = default.check


def authorize(rule_name, target, credentials):
    reset()
    try:
        policy_file = conf['policy'].get('policy_file')
    except KeyError:
        logger.info('Policy file not defined, going with default rules')
        policy_file = ''
    if not policy_file or not os.path.isfile(policy_file):
        msg = ('Policy file %s not found, initializing default policy '
               'engine (this is normal when bootstrapping '
               'Software Factory)')
        logger.info(msg % policy_file)
        init()
    else:
        init(policy_file=policy_file)
    try:
        result = _ENFORCER.enforce(rule_name, target, credentials,
                                   do_raise=False)
    except policy.PolicyNotRegistered:
        logger.error('Policy %s not registered' % rule_name)
        return -1
    except Exception:
        logger.debug('Policy check for %(rule)s failed with credentials '
                     '%(credentials)s' % {'rule': rule_name,
                                          'credentials': credentials})
        raise
    return result
