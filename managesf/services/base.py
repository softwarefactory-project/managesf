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


import abc
import six

from pecan import conf

from managesf.services import exceptions as exc


@six.add_metaclass(abc.ABCMeta)
class BaseCRUDManager(object):
    def __init__(self, plugin):
        self.plugin = plugin

    def create(self, **kwargs):
        """Creation operation"""

    def get(self, **kwargs):
        """Fetching operation"""

    def update(self, **kwargs):
        """Update operation"""

    def delete(self, **kwargs):
        """Deletion operation"""


@six.add_metaclass(abc.ABCMeta)
class ProjectManager(BaseCRUDManager):
    """Abstract class handling CRUD operations on projects in Software
    Factory, if the service has a notion of projects."""


@six.add_metaclass(abc.ABCMeta)
class UserManager(BaseCRUDManager):
    """Abstract class handling CRUD operations on users in Software
    Factory, if the service has a notion of users."""


@six.add_metaclass(abc.ABCMeta)
class MembershipManager(BaseCRUDManager):
    """Abstract class handling membership operations between users and
    projects in Software Factory"""


@six.add_metaclass(abc.ABCMeta)
class ReplicationManager(BaseCRUDManager):
    """Abstract class handling replication operations if the service can
    handle them (usually, a repository service)"""


@six.add_metaclass(abc.ABCMeta)
class RepositoryManager(BaseCRUDManager):
    """Abstract class handling repository creation and other repository
    related operations"""


@six.add_metaclass(abc.ABCMeta)
class BackupManager(BaseCRUDManager):
    """Abstract class handling backups and data restoration for a given
    service."""
    # more sensible mapping
    def backup(self, **kwargs):
        return self.get(**kwargs)

    def restore(self, **kwargs):
        return self.update(**kwargs)

    def create(self, **kwargs):
        raise NotImplementedError

    def delete(self, **kwargs):
        raise NotImplementedError


@six.add_metaclass(abc.ABCMeta)
class CodeReviewManager(BaseCRUDManager):
    """Abstract class handling code reviews operations for a given
    gerrit-like service."""


@six.add_metaclass(abc.ABCMeta)
class RoleManager(BaseCRUDManager):
    """Abstract class handling roles if the service can handle them"""

    def is_admin(self, user):
        return user == conf.admin['name']


@six.add_metaclass(abc.ABCMeta)
class BaseServicePlugin(object):
    """Base plugin for a service that can be managed by Software Factory.
    """

    _config_section = "base"
    service_name = "base service"

    def __init__(self, conf):
        self._full_conf = conf
        try:
            self.configure_plugin(conf)
        except AttributeError:
            raise Exception(repr(conf))
        # place holders
        self.project = ProjectManager(self)
        self.user = UserManager(self)
        self.membership = MembershipManager(self)
        self.role = RoleManager(self)
        self.backup = BackupManager(self)

    def configure_plugin(self, conf):
        try:
            self.conf = getattr(conf, self._config_section, None)
        except KeyError:
            msg = ("The %s service is not available" % self._config_section)
            raise exc.ServiceNotAvailableError(msg)
        if not self.conf:
            msg = ("The %s service is not available" % self._config_section)
            raise exc.ServiceNotAvailableError(msg)

    def get_client(self, cookie=None):
        """returns a service client to be used by the managers."""


@six.add_metaclass(abc.ABCMeta)
class BaseIssueTrackerServicePlugin(BaseServicePlugin):
    """Base plugin for a service managing issues."""

    def get_open_issues(self):
        """Return the open issues on the tracker"""

    def get_active_users(self):
        """Return a list of active users"""


@six.add_metaclass(abc.ABCMeta)
class BaseRepositoryServicePlugin(BaseServicePlugin):
    """Base plugin for a service managing repositories. This adds repository
    replication and repository operations."""

    def __init__(self, conf):
        super(BaseRepositoryServicePlugin, self).__init__(conf)
        self.replication = ReplicationManager(self)
        self.repository = RepositoryManager(self)


@six.add_metaclass(abc.ABCMeta)
class BaseCodeReviewServicePlugin(BaseRepositoryServicePlugin):
    """Base plugin for a service managing code review systems. This adds
    code review operations like submitting a file for review to a project."""

    def __init__(self, conf):
        super(BaseCodeReviewServicePlugin, self).__init__(conf)
        self.review = CodeReviewManager(self)
