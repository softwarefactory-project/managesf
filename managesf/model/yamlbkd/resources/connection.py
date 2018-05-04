#
# Copyright (c) 2018 Red Hat, Inc.
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


def prevent_update():
    return ["Connections can't be updated manually, they are managed by "
            "configuration management."]


class Connection(BaseResource):

    DESCRIPTION = ("The connection resource describes Zuul connections.")

    MODEL_TYPE = 'connection'
    MODEL = {
        'name': (
            str,
            '^([a-zA-Z0-9\-_\./])+$',
            False,
            "",
            False,
            "The connection name",
        ),
        'base-url': (
            str,
            '.*',
            True,
            "",
            False,
            "The connection base url",
        ),
        'type': (
            str,
            '^(gerrit|github|git)$',
            True,
            "gerrit",
            True,
            "Connection type [gerrit|github|git]",
        ),
    }
    PRIORITY = 5
    PRIMARY_KEY = 'name'
    CALLBACKS = {
        'update': lambda conf, new, kwargs: prevent_update(),
        'create': lambda conf, new, kwargs: prevent_update(),
        'delete': lambda conf, new, kwargs: prevent_update(),
        'extra_validations': lambda conf, new, kwargs: prevent_update(),
        'get_all': lambda conf, new: ([], {}),
    }
