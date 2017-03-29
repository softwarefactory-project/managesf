#
# Copyright (c) 2016 Red Hat, Inc.
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

import os
import re
import tempfile
import logging

from git.config import GitConfigParser

from managesf.model.yamlbkd.resource import BaseResource

logger = logging.getLogger(__name__)

KEYS_EXP_GROUP_REGEXS = (
    'owner',
    'read',
    'submit',
    'create',
    'push',
    'label-[^ ]+'
)

KEYS_EXP_BOOLEAN_VALUES = (
    'requireChangeId',
    'mergeContent',
    'requireContributorAgreement',
    'requireSignedOffBy',
)

SUBMIT_ACTION_VALUES = (
    'fast forward only',
    'merge if necessary',
    'rebase if necessary',
    'always merge',
    'cherry pick',
)


class ACLOps(object):

    def __init__(self, conf, new):
        self.conf = conf
        self.new = new

    def extra_validations(self, **kwargs):
        default_groups = ('Non-Interactive Users',
                          'Administrators',
                          'Registered Users',
                          'Anonymous Users')
        logs = []
        acls = kwargs['file']
        groups = kwargs['groups']

        fd, path = tempfile.mkstemp()
        os.close(fd)
        file(path, 'w').write(acls)
        # Validate the file has the right format
        try:
            c = GitConfigParser(path)
            c.read()
        except Exception, e:
            logger.exception("GitConfigParser failed %s" % e)
            logs.append(str(e))
        finally:
            os.unlink(path)

        # Verify the groups mentioned in the ACLs file are known
        group_names = set()
        for group_id in groups:
            name = self.new['resources']['groups'][group_id]['name']
            group_names.add(name)
        sections = [s for s in c.sections() if c != 'project']
        for section_name in sections:
            for k, v in c.items(section_name):
                if k in KEYS_EXP_BOOLEAN_VALUES:
                    if v.lower() not in ('true', 'false'):
                        logs.append(
                            "ACLs file section (%s), key (%s) expects "
                            "a valid boolean value (not: %s)" % (
                                section_name, k, v))
                    continue
                if any([re.match(rex, k) for rex in KEYS_EXP_GROUP_REGEXS]):
                    if k.startswith('label-'):
                        if not re.match('.+ group .+$', v):
                            logs.append(
                                "ACLs file section (%s), key (%s) expects "
                                "a note rule and a group to be specified "
                                "(not: %s)" % (section_name, k, v))
                    else:
                        if not re.match('group .+$', v):
                            logs.append(
                                "ACLs file section (%s), key (%s) expects "
                                "a group to be specified (not: %s)" % (
                                    section_name, k, v))
                if k == 'action' and section_name == 'submit':
                    if v.lower() not in SUBMIT_ACTION_VALUES:
                        logs.append(
                            "ACLs file section (%s), key (%s) expects "
                            "a valid submit strategy (not: %s)" % (
                                section_name, k, v))
                    continue
                m = re.search('.*group (.*)$', v)
                if m:
                    group_name = m.groups()[0]
                    if (group_name not in group_names and
                            group_name not in default_groups):
                        logs.append(
                            "ACLs file section (%s), key (%s) relies on an "
                            "unknown group name: %s" % (
                                section_name, k, group_name))
        return logs


class ACL(BaseResource):

    MODEL_TYPE = 'acl'
    DESCRIPTION = ("The acl resource is used to store a Gerrit ACL. "
                   "The acl can be shared between multiple git repositories. "
                   "Group mentionned inside the acl file key must be "
                   "referenced by their ID under the groups key. Do not "
                   "provide the description entry in the acl file to keep "
                   "them shareable between git repositories if needed.")
    MODEL = {
        'name': (
            str,
            '.*',
            False,
            '',
            False,
            "The ACL name",
        ),
        'file': (
            str,
            '.*',
            True,
            None,
            True,
            "The Gerrit ACL content",
        ),
        'groups': (
            list,
            '.+',
            False,
            [],
            True,
            "The list of groups this ACL depends on",
        ),
    }
    PRIORITY = 30
    PRIMARY_KEY = 'file'
    CALLBACKS = {
        'update': lambda conf, new, kwargs: [],
        'create': lambda conf, new, kwargs: [],
        'delete': lambda conf, new, kwargs: [],
        'extra_validations': lambda conf, new, kwargs:
            ACLOps(conf, new).extra_validations(**kwargs),
        'get_all': lambda conf, new: ([], {}),
    }

    def get_deps(self, keyname=False):
        if keyname:
            return 'groups'
        return {'groups': set(self.resource['groups'])}
