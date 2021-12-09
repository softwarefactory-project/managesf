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
    'rebase',
    'forgeAuthor',
    'create',
    'push',
    'label-[^ ]+',
    'addPatchSet'
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
        default_groups = ('Service Users',
                          'Non-Interactive Users',
                          'Administrators',
                          'Registered Users',
                          'Anonymous Users')
        logs = []
        acls = kwargs['file']
        groups = kwargs['groups']
        name = kwargs['name']

        fd, path = tempfile.mkstemp()
        os.close(fd)
        open(path, 'w').write(acls)
        # Validate the file has the right format
        try:
            c = GitConfigParser(path)
            c.read()
        except Exception as e:
            logger.exception("GitConfigParser failed %s" % e)
            logs.append(str(e))
        finally:
            os.unlink(path)

        # Verify the groups mentioned in the ACLs file are known
        group_names = set()
        for group_id in groups:
            name = self.new['resources']['groups'][group_id]['name']
            group_names.add(name)

        # Verify the validity of the ACL
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
                        if not re.match('(deny group|group) .+$', v):
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

        # Try to detect an ACL that make a repository private
        if ('read = deny group Registered Users' in acls and
                'read = deny group Anonymous Users' in acls):
            # That a private ACLs then make sure repos that use it
            # use the private flag at project level
            # Find repos that use this ACL
            private_repos = []
            for repo, rdata in self.new['resources']['repos'].items():
                if rdata['acl'] == name:
                    private_repos.append(repo)
            # Find repos marked as private in projects
            # and remove them from the private_repos accu
            if private_repos:
                projects = self.new['resources']['projects'].values()
                for project in projects:
                    for sr in project['source-repositories']:
                        if isinstance(sr, dict):
                            sr_name = list(sr.keys())[0]
                            sr_attrs = sr[sr_name]
                            if sr_attrs.get('private') is True:
                                private_repos.remove(sr_name)
            # If some remains in the accu then the 'private' attribute
            # is missing on them
            if private_repos:
                logs.append(
                    "%s repositories use a private Gerrit ACL but are not"
                    " defined as private in a project" % private_repos)

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

    def should_be_updated(self):
        """ An ACL depends on one or more groups
        but a group update does not need to force
        the engine to call the ACL update callback.
        """
        return False
