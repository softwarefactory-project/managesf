#
# Copyright (C) 2017 Red Hat
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


from managesf.api.v2 import base
from managesf.model.yamlbkd.resources import project
from managesf.model.yamlbkd.resources import group
from managesf.model.yamlbkd.resources import gitacls
from managesf.model.yamlbkd.resources import gitrepository


RESOURCES_CRUD_ERROR = 'Resources are managed on the "config" repository'


class BaseResourceManager(base.BaseCRUDManager):
    """Resources can only be queried, not modified through the REST API."""

    def create(self, **kwargs):
        """Not relevant here"""
        # This can be achieved by a "retrigger" in gerrit anyway
        raise NotImplementedError(RESOURCES_CRUD_ERROR)

    def update(self, **kwargs):
        """Not relevant here"""
        raise NotImplementedError(RESOURCES_CRUD_ERROR)

    def delete(self, **kwargs):
        """Not relevant here"""
        raise NotImplementedError(RESOURCES_CRUD_ERROR)


class ProjectManager(BaseResourceManager):
    """Projects-related CRUD operations."""

    def __init__(self):
        super(ProjectManager, self).__init__()
        self.ordering_options = ['id', 'name']

    def get(self, **kwargs):
        """lists one or several projects depending on filtering with kwargs.
        Filtering options:
        id: the unique id of the project within the yaml backend
        name: the name of the project
        website: the project's website
        documentation: the project's documentation website
        issue_tracker: the internal reference of the project's issue tracker
        mailing_list: one of the mailing lists of the project
        contact: one of the contact of the project
        repository: one of the repositories within the project
        member_email: if the user is a member of a group used in an ACL applied
            to a repository within the project, return the project"""
        raise NotImplementedError


class ResourceData(base.Data):
    """Base class to make sure the REST data fits with the yamlbkd models."""
    _backend_class = None

    def __init__(self, *args, **kwargs):
        for key in self._backend_class.MODEL:
            obj_key = key.replace('-', '_')
            obj_type = self._backend_class.MODEL[key][0]
            setattr(self,
                    obj_key,
                    kwargs.get(obj_key, obj_type()))

    def to_dict(self):
        d = {}
        for key in self._backend_class.MODEL:
            obj_key = key.replace('-', '_')
            d[obj_key] = getattr(self, obj_key)
        return d


class Project(ResourceData):

    _backend_class = project.Project

    """project info"""
    def __init__(self, id, **kwargs):
        """Project descriptor.
        id: the unique id within the resource backend
        name: the name of the project
        description: a description of the project
        website: the home page of the project
        documentation: the URL of the documentation of the project
        issue_tracker: the reference of the issue tracker of the project, used
            by hooks
        issue_tracker_url: the URL of the issue tracker
        review_dashboard: the URL of the review dashboard for the project
        mailing_lists: the list of mailing lists for the project
        contacts: the list of contact e-mails
        source_repositories: the list of repository ids that form the
            project"""
        self.id = id
        super(Project, self).__init__(**kwargs)


class ACLManager(BaseResourceManager):
    """ACL-related CRUD operations."""

    def __init__(self):
        super(ACLManager, self).__init__()
        self.ordering_options = ['id', ]

    def get(self, **kwargs):
        """lists one or several ACLs depending on filtering with kwargs.
        filtering options:
        id: the unique identifier of the ACL in the yaml backend
        group: a group on which the ACL applies
        member_email: a group member on which the ACL applies
        project: a project hosting a repository on which the ACL applies
        repository: a repository on which the ACL applies
        """
        raise NotImplementedError


class ACL(ResourceData):

    _backend_class = gitacls.ACL

    """ACL info"""
    def __init__(self, id, **kwargs):
        """Access control descriptor.
        id: the unique id of the access control rule in the resource backend
        file: the actual definition of the rule, as consumed by gerrit
        groups: the groups on which the access control rule applies"""
        self.id = id
        super(ACL, self).__init__(**kwargs)


class GroupManager(BaseResourceManager):
    """Groups-related CRUD operations."""

    def __init__(self):
        super(GroupManager, self).__init__()
        self.ordering_options = ['id', 'name']

    def get(self, **kwargs):
        """lists one or several groups depending on filtering with kwargs.
        id: the unique identifier of the group in the yaml backend
        name: the name of the group
        acl: the ACL being applied on the group
        member_email: a group member
        project: a project to which the group belongs
        repository: a repository to which the group belongs
        """
        raise NotImplementedError


class Group(ResourceData):

    _backend_class = group.Group

    """Group info"""
    def __init__(self, id, **kwargs):
        """Group descriptor.
        id: the unique id of the group in the resource backend
        name: the name of the group
        description: a description of the group
        members: the users who belong to this group"""
        self.id = id
        super(Group, self).__init__(**kwargs)

    def to_dict(self):
        d = {'id': self.id,
             'name': self.name,
             'description': self.description,
             'members': []}
        if self.members:
            try:
                d['members'] = [m.to_dict() for m in self.members]
            except AttributeError:
                # members are e-mails or ids, not Users
                d['members'] = self.members
        return d


class RepositoryManager(BaseResourceManager):
    """Repositories-related CRUD operations."""

    def __init__(self):
        super(RepositoryManager, self).__init__()
        self.ordering_options = ['id', 'name']

    def get(self, **kwargs):
        """lists one or several projects depending on filtering with kwargs.
        Filtering options:
        id: the unique id of the repository within the yaml backend
        name: the name of the repository
        project: the project this repository belongs to
        acl: the access control rule applied to the repository
        member_email: if the user is a member of a group used in an ACL applied
            to the repository, return the repository"""
        raise NotImplementedError


class Repository(ResourceData):
    """Repository info"""

    _backend_class = gitrepository.GitRepository

    def __init__(self, id, **kwargs):
        """Repository descriptor.
        id: the unique id of the repository in the resource backend
        name: the name of the repository
        description: a description of the repository
        acl: the access control list applied to the repository
        default_branch: the repository's default branch
        branches: the repository branches"""
        self.id = id
        super(Repository, self).__init__(**kwargs)


# Kept for iso-functionality with v1
class ResourcesManager(base.BaseCRUDManager):
    """Resource tree-related CRUD operations."""

    def __init__(self):
        super(ResourcesManager, self).__init__()
        self.ordering_options = []

    def get(self, **kwargs):
        """get the full tree.
        get_missing_resources: (boolean) if True, returns existing projects
            that are missing from the resources descriptor.
        """
        raise NotImplementedError

    def apply(self, COMMIT=None, prev=None, new=None, **kwargs):
        """Trigger applying the tree and create new resources.
        COMMIT: XXX
        prev: XXX
        new: XXX
        """
        kwargs['COMMIT'] = COMMIT
        kwargs['prev'] = prev
        kwargs['new'] = new
        return self.update(**kwargs)

    def update(self, **kwargs):
        raise NotImplementedError

    def validate(self, zuul_url=None, zuul_ref=None, **kwargs):
        """Validate the tree.
        zuul_url: XXX
        zuul_ref: XXX
        """
        kwargs['zuul_url'] = zuul_url
        kwargs['zuul_ref'] = zuul_ref
        return self.create(**kwargs)

    def create(self, **kwargs):
        raise NotImplementedError


class ResourcesServiceManager(base.BaseService):
    # placeholders
    projects = ProjectManager()
    acls = ACLManager()
    groups = GroupManager()
    repositories = RepositoryManager()
    resources = ResourcesManager()
