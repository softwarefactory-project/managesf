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
import logging
import six

from pecan import conf as pconf

from managesf.services import exceptions as exc


logger = logging.getLogger(__name__)


@six.add_metaclass(abc.ABCMeta)
class BaseHooksManager(object):
    """Abstract class handling hooks triggered by specific events in the CI
    workflow. These are mainly based on gerrit's own hook events."""
    def __init__(self, plugin):
        self.plugin = plugin

    def patchset_created(self, *args, **kwargs):
        """Called whenever a new patch is submitted. Expected arguments
        based on the gerrit hook with the same name:
        'change', 'is_draft', 'change_url', 'project',
        'branch', 'topic', 'uploader', 'commit', 'patchset',
        'commit_message'
        (The last one will be computed by the local hook script)"""
        raise exc.UnavailableActionError()

    def change_merged(self, *args, **kwargs):
        """Called whenever a new patch is merged into a project's master
        branch. Expected arguments based on the gerrit hook with the same name:
        'change', 'change_url', 'project',
        'branch', 'topic', 'submitter', 'commit', 'commit_message'
        (The last one will be computed by the local hook script)"""
        raise exc.UnavailableActionError()

    def __getattr__(self, hook):
        """Generic behavior for undefined hooks"""
        def _generic_hook(*args, **kwargs):
            msg = "[%s] undefined hook %s" % (self.plugin.service_name,
                                              hook)
            raise exc.UnavailableActionError(msg)
        return _generic_hook


@six.add_metaclass(abc.ABCMeta)
class BaseCRUDManager(object):
    def __init__(self, plugin):
        self.plugin = plugin

    def create(self, *args, **kwargs):
        """Creation operation"""
        raise exc.UnavailableActionError()

    def get(self, *args, **kwargs):
        """Fetching operation"""
        raise exc.UnavailableActionError()

    def update(self, *args, **kwargs):
        """Update operation"""
        raise exc.UnavailableActionError()

    def delete(self, *args, **kwargs):
        """Deletion operation"""
        raise exc.UnavailableActionError()


@six.add_metaclass(abc.ABCMeta)
class ProjectManager(BaseCRUDManager):
    """Abstract class handling CRUD operations on projects in Software
    Factory, if the service has a notion of projects."""


@six.add_metaclass(abc.ABCMeta)
class UserManager(BaseCRUDManager):
    """Abstract class handling CRUD operations on users in Software
    Factory, if the service has a notion of users."""

    # list of fields that cannot be updated. For example, it is not allowed
    # to change the username in gerrit.
    _immutable_fields_ = []

    @classmethod
    def check_forbidden_fields(cls, **kwargs):
        return list(set(cls._immutable_fields_) & set(kwargs.keys()))

    def update(self, uid, *args, **kwargs):
        """Update operation"""
        raise exc.UnavailableActionError()


@six.add_metaclass(abc.ABCMeta)
class GroupManager(BaseCRUDManager):
    """Abstract class handling CRUD operations on groups in Software
    Factory, if the service has a notion of groups."""

    # list of fields that cannot be updated. For example, it is not allowed
    # to change the group name in gerrit.
    _immutable_fields_ = []

    @classmethod
    def check_forbidden_fields(cls, **kwargs):
        return list(set(cls._immutable_fields_) & set(kwargs.keys()))

    def update(self, uid, *args, **kwargs):
        """Update operation"""
        raise exc.UnavailableActionError()


@six.add_metaclass(abc.ABCMeta)
class MembershipManager(BaseCRUDManager):
    """Abstract class handling membership operations between
    users/standalone groups and projects in Software Factory"""


@six.add_metaclass(abc.ABCMeta)
class ReplicationManager(BaseCRUDManager):
    """Abstract class handling replication operations if the service can
    handle them (usually, a repository service)"""
    def get_config(self, **kwargs):
        return self.get(**kwargs)

    def apply_config(self, **kwargs):
        return self.update(**kwargs)

    def trigger(self, **kwargs):
        """Trigger a replication"""
        raise exc.UnavailableActionError()


@six.add_metaclass(abc.ABCMeta)
class RepositoryManager(BaseCRUDManager):
    """Abstract class handling repository creation and other repository
    related operations"""


@six.add_metaclass(abc.ABCMeta)
class CodeReviewManager(BaseCRUDManager):
    """Abstract class handling code reviews operations for a given
    gerrit-like service."""

    def propose_test_definition(self, **kwargs):
        """creates a review adding tests in the zuul pipelines for a project"""
        raise exc.UnavailableActionError()

    def propose_test_scripts(self, **kwargs):
        """creates a review for template tests scripts on a project"""
        raise exc.UnavailableActionError()


@six.add_metaclass(abc.ABCMeta)
class RoleManager(BaseCRUDManager):
    """Abstract class handling roles if the service can handle them"""

    @staticmethod
    def is_admin(user):
        return user == pconf.admin['name']


@six.add_metaclass(abc.ABCMeta)
class JobManager(BaseCRUDManager):
    """Abstract class handling jobs for a "job runner"-type service"""

    def get_job(self, job_name, **kwargs):
        """lists one or several jobs depending on filtering with kwargs"""
        raise exc.UnavailableActionError()

    def get_job_parameters(self, job_name, job_id):
        """get parameters used to run a job"""
        raise exc.UnavailableActionError()

    def get_job_status(self, job_name, job_id):
        """get parameters used to run a job"""
        raise exc.UnavailableActionError()

    def get_job_logs(self, job_name, job_id):
        """get logs of a finished job"""
        raise exc.UnavailableActionError()

    def run(self, job_name, job_parameters):
        """run a job"""
        raise exc.UnavailableActionError()

    def stop(self, job_name, job_id):
        """stop a running job"""
        raise exc.UnavailableActionError()


@six.add_metaclass(abc.ABCMeta)
class NodeManager(BaseCRUDManager):
    """Abstract class handling nodes for an "agent provider"-type service"""

    def get(self, node_id=None, **kwargs):
        """lists one or several nodes depending on filtering with node's
        id or kwargs"""
        raise exc.UnavailableActionError()

    def hold(self, node_id):
        """prevents node node_id from being deleted after a completed job"""
        raise exc.UnavailableActionError()

    def delete(self, node_id):
        """schedules node node_id for deletion"""
        raise exc.UnavailableActionError()

    def add_authorized_key(self, node_id, public_key, user=None):
        """adds public_key as an authorized key on user's account on node_id"""
        raise exc.UnavailableActionError()


@six.add_metaclass(abc.ABCMeta)
class ImageManager(BaseCRUDManager):
    """Abstract class handling image building tasks for an
    "agent provider"-type service"""

    def get(self, provider_name=None, image_name=None, **kwargs):
        """lists one or several images depending on filtering options"""
        raise exc.UnavailableActionError()

    def start_update(self, provider_name, image_name):
        """updates (rebuild) the image image_name on provider provider_name"""
        raise exc.UnavailableActionError()

    def get_update_info(self, id):
        """fetches relevant info on an image update possibly still
        in progress"""
        raise exc.UnavailableActionError()


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
        self.hooks = BaseHooksManager(self)

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
class BaseAgentProviderServicePlugin(BaseServicePlugin):
    """Base plugin for a service used to provide agents on which to run jobs,
    for example Nodepool."""

    def __init__(self, conf):
        super(BaseAgentProviderServicePlugin, self).__init__(conf)
        self.node = NodeManager(self)
        self.image = ImageManager(self)


@six.add_metaclass(abc.ABCMeta)
class BaseJobRunnerServicePlugin(BaseServicePlugin):
    """Base plugin for a service used to execute jobs, for example Jenkins."""

    def __init__(self, conf):
        super(BaseJobRunnerServicePlugin, self).__init__(conf)
        self.job = JobManager(self)


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
