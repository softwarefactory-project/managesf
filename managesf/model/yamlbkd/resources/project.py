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


from managesf.model.yamlbkd.resource import BaseResource


class Project(BaseResource):

    MODEL_TYPE = 'project'
    MODEL = {
        'name': (
            str,
            '^([a-zA-Z0-9\-_\./])+$',
            True,
            None,
            True,
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
        'issue-tracker': (
            str,
            '.*',
            False,
            "",
            True,
            "The project issue tracker link",
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
        'update': lambda conf, new, kwargs: [],
        'create': lambda conf, new, kwargs: [],
        'delete': lambda conf, new, kwargs: [],
        'extra_validations': lambda conf, new, kwargs: [],
        'get_all': lambda conf, new: ([], {}),
    }

    def get_deps(self, keyname=False):
        if keyname:
            return 'source-repositories'
        return {'repos': set(self.resource['source-repositories'])}
