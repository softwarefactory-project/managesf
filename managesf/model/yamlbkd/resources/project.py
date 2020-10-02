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

import logging

from managesf.model.yamlbkd.resource import BaseResource


logger = logging.getLogger(__name__)


class ProjectOps(object):

    def __init__(self, conf, new):
        self.conf = conf
        self.new = new
        self.client = None

    def create(self, **kwargs):
        logs = []
        return logs

    def update(self, **kwargs):
        logs = []
        return logs

    def delete(self, **kwargs):
        logs = []
        return logs

    def extra_validations(self, **kwargs):
        logs = []
        name = kwargs['name']

        project = self.new['resources']['projects'][name]
        for sr in project['source-repositories']:
            if isinstance(sr, dict):
                sr_name = list(sr.keys())[0]
                sr_attrs = sr[sr_name]
                private = sr_attrs.get('private', False)
            else:
                sr_name = sr
                private = False
            repo = self.new['resources'].get('repos', {}).get(sr_name)
            if not repo:
                continue
            acl = self.new['resources']['acls'][repo['acl']]
            if ('read = deny group Registered Users' in acl['file'] and
                    'read = deny group Anonymous Users' in acl['file']):
                if not private:
                    logs.append(
                        "%s repository use a private Gerrit ACL but are not"
                        " defined as private in the project %s" % (
                            sr_name, name))

        return logs


class Project(BaseResource):

    DESCRIPTION = ("The project resource can be is used to describe a "
                   "project. It can be seen as the top level resource type in "
                   "in this model. You can use it reference multiple Git "
                   "repositories and multiple link to external resources like "
                   "a project website and the issues tracker website.")

    MODEL_TYPE = 'project'
    MODEL = {
        'name': (
            str,
            r'^([a-zA-Z0-9\-_\./])+$',
            False,
            "",
            False,
            "The project name",
        ),
        'description': (
            str,
            '.*',
            True,
            None,
            True,
            "The project description",
        ),
        'tenant': (
            str,
            '.*',
            False,
            "",
            True,
            "The tenant name",
        ),
        'connection': (
            str,
            '.*',
            False,
            "",
            True,
            "The default connection for source-repositories",
        ),
        'website': (
            str,
            '.*',
            False,
            "",
            True,
            "The project web page link",
        ),
        'documentation': (
            str,
            '.*',
            False,
            "",
            True,
            "The project documentation link",
        ),
        'issue-tracker-url': (
            str,
            '.*',
            False,
            "",
            True,
            "The project issue tracker link",
        ),
        'review-dashboard': (
            str,
            r'^([a-zA-Z0-9\-_])*$',
            False,
            "",
            True,
            "A gerrit dashboard name reference",
        ),
        'mailing-lists': (
            list,
            '.+@.+',
            False,
            [],
            True,
            "Email addresses of project mailing lists",
        ),
        'contacts': (
            list,
            '.+@.+',
            False,
            [],
            True,
            "Email addresses of project main contacts",
        ),
        'source-repositories': (
            list,
            (dict, '.+'),
            True,
            None,
            True,
            "Code source repositories related to the project",
        ),
        'options': (
            list,
            '.+',
            False,
            [],
            True,
            "Project options for services",
        ),
    }
    PRIORITY = 10
    PRIMARY_KEY = 'name'
    CALLBACKS = {
        'update': lambda conf, new, kwargs:
            ProjectOps(conf, new).update(**kwargs),
        'create': lambda conf, new, kwargs:
            ProjectOps(conf, new).create(**kwargs),
        'delete': lambda conf, new, kwargs:
            ProjectOps(conf, new).delete(**kwargs),
        'extra_validations': lambda conf, new, kwargs:
            ProjectOps(conf, new).extra_validations(**kwargs),
        'get_all': lambda conf, new: ([], {}),
    }

    def get_deps(self, keyname=False):
        if keyname:
            return 'source-repositories'
        ids = set()
        for sr in self.resource['source-repositories']:
            if isinstance(sr, dict):
                ids.add(list(sr)[0])
            else:
                ids.add(sr)
        return {'repos': ids}

    def is_deps_soft(self):
        return True

    def transform_for_get(self):
        ret = {}
        for key, data in self.resource.items():
            if key == 'source-repositories':
                srs = []
                for sr in data:
                    if isinstance(sr, (str, bytes)):
                        srs.append({sr: {}})
                    else:
                        srs.append(sr)
            else:
                ret[key] = data
        ret['source-repositories'] = srs
        return ret
