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
from managesf.model.yamlbkd.resources.storyboard import StoryboardOps

logger = logging.getLogger(__name__)


class ProjectOps(object):

    def __init__(self, conf, new):
        self.conf = conf
        self.new = new
        self.client = None
        self.stb_ops = StoryboardOps(conf, new)

    def create(self, **kwargs):
        logs = []
        if self.stb_ops.is_activated(**kwargs):
            try:
                self.stb_ops.update_project_groups(**kwargs)
            except Exception, e:
                msg = "Create Storyboard project group : err: %s" % e
                logger.exception(msg)
                logs.append(msg)
        return logs

    def update(self, **kwargs):
        logs = []
        if self.stb_ops.is_activated(**kwargs):
            try:
                self.stb_ops.update_project_groups(**kwargs)
            except Exception, e:
                msg = "Update Storyboard project group: err: %s" % e
                logger.exception(msg)
                logs.append(msg)
        return logs

    def delete(self, **kwargs):
        logs = []
        if self.stb_ops.is_activated(**kwargs):
            try:
                self.stb_ops.delete_project_groups(**kwargs)
            except Exception, e:
                msg = "Delete Storyboard project group: err: %s" % e
                logger.exception(msg)
                logs.append(msg)
        return logs

    def extra_validations(self, **kwargs):
        logs = []
        if self.stb_ops.is_activated(**kwargs):
            logs.extend(self.stb_ops.extra_validations(**kwargs))
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
            '^([a-zA-Z0-9\-_\./])+$',
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
        'issue-tracker': (
            str,
            '^(SFStoryboard|)$',
            False,
            "",
            True,
            "The local issue tracker activated for this project",
        ),
        'review-dashboard': (
            str,
            '^([a-zA-Z0-9\-_])*$',
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
            '.+',
            True,
            None,
            True,
            "Code source repositories related to the project",
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
        return {'repos': set(self.resource['source-repositories'])}
