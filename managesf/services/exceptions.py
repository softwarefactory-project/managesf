#!/usr/bin/env python
#
# Copyright (C) 2015 Red Hat <licensing@enovance.com>
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


class ServiceNotAvailableError(Exception):
    """Raised if a service plugin cannot be configured"""
    pass


class UnavailableActionError(Exception):
    """Raised if a service does not know how to do the requested action"""
    pass


class Unauthorized(Exception):
    """Raised if an action is unauthorized on the service"""
    pass


class CreateGroupException(Exception):
    """Raised if a group creation failed"""
    pass


class UpdateGroupException(Exception):
    """Raised if a group update failed"""
    pass


class GroupNotFoundException(Exception):
    """Raised if a group lookup failed"""
    pass
