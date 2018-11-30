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


class Tenant(BaseResource):

    DESCRIPTION = ("The tenant resource can be is used to describe a tenant "
                   "like where is located the config repository of tenant.")

    MODEL_TYPE = 'tenant'
    MODEL = {
        'name': (
            str,
            r'^([a-zA-Z0-9\-_\./])+$',
            False,
            "",
            False,
            "The tenant name",
        ),
        'url': (
            str,
            '.*',
            True,
            None,
            True,
            "The Software Factory managesf URL",
        ),
        'tenant-options': (
            dict,
            ('.+', '.+'),
            False,
            {},
            True,
            "List of tenant options",
        ),
        'default-connection': (
            str,
            '.*',
            False,
            "",
            True,
            "The tenant connection to be used in default Zuul pipelines",
        ),
        'allowed-reporters': (
            list,
            '.+',
            False,
            [],
            True,
            "The list of allowed reporter connections for Zuul",
        ),
        'allowed-triggers': (
            list,
            '.+',
            False,
            [],
            True,
            "The list of allowed trigger connections for Zuul",
        ),
        'description': (
            str,
            '.*',
            False,
            "",
            True,
            "The tenant description",
        ),
    }
    PRIORITY = 5
    PRIMARY_KEY = 'name'
    CALLBACKS = {
        'update': lambda conf, new, kwargs: [],
        'create': lambda conf, new, kwargs: [],
        'delete': lambda conf, new, kwargs: [],
        'extra_validations': lambda conf, new, kwargs: [],
        'get_all': lambda conf, new: ([], {}),
    }
