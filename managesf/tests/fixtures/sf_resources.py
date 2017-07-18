#!/usr/bin/env python
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


"""Sample resources tree from a test instance."""


SAMPLE_RESOURCES_TREE = {"hash": "1234ab", "resources": {"repos": {"tdpw/reader-ansible": {"acl": "tdpw-acl", "description": "The Ansible role of the Reader server", "name": "tdpw/reader-ansible"}, "dummy_project4": {"description": "Code repository for dummy_project4", "acl": "dummy_project4-acl"}, "dummy_project86": {"description": "Code repository for dummy_project86", "acl": "dummy_project86-acl"}, "config": {"description": "Config repository (Do not delete it)", "acl": "config-acl"}, "dummy_project6": {"description": "Code repository for dummy_project6", "acl": "dummy_project6-acl"}, "tdpw/reader": {"acl": "tdpw-acl", "description": "The Reader server", "name": "tdpw/reader"}, "tdpw/tdpw-installer": {"acl": "tdpw-acl", "description": "The installer for the tdpw RPM Distribution", "name": "tdpw/tdpw-installer"}, "tdpw/python-readerlib-distgit": {"acl": "tdpw-acl", "description": "RPM packaging for python-readerlib", "name": "tdpw/python-readerlib-distgit"}, "tdpw/reader-ansible-distgit": {"acl": "tdpw-acl", "description": "RPM packaging for the Reader Ansible role", "name": "tdpw/reader-ansible-distgit"}, "tdpw/tdpw-info": {"acl": "tdpw-acl", "description": "tdpw Distribution info repository", "name": "tdpw/tdpw-info"}, "tdpw/reader-distgit": {"acl": "tdpw-acl", "description": "RPM packaging for the Reader server", "name": "tdpw/reader-distgit"}, "tdpw/python-readerlib": {"acl": "tdpw-acl", "description": "Python library of the Reader project", "name": "tdpw/python-readerlib"}, "tdpw/tdpw-installer-distgit": {"acl": "tdpw-acl", "description": "RPM packaging for the tdpw Distribution installer", "name": "tdpw/tdpw-installer-distgit"}, "sexbobomb": {"description": "oh yeah", "acl": "config-acl"}, "dummy_project1": {"description": "Code repository for dummy_project1", "acl": "dummy_project1-acl"}, "dummy_project2": {"description": "Code repository for dummy_project2", "acl": "dummy_project2-acl"}, "dummy_project3": {"description": "Code repository for dummy_project3", "acl": "dummy_project3-acl"}}, "acls": {"dummy_project6-acl": {"file": "[access \"refs/*\"]\n  read = group dummy_project6-core\n  owner = group dummy_project6-ptl\n[access \"refs/heads/*\"]\n  label-Verified = -2..+2 group dummy_project6-ptl\n  label-Code-Review = -2..+2 group dummy_project6-core\n  label-Workflow = -1..+1 group dummy_project6-core\n  submit = group dummy_project6-ptl\n  read = group dummy_project6-core\n[access \"refs/meta/config\"]\n  read = group dummy_project6-core\n[receive]\n  requireChangeId = true\n[submit]\n  mergeContent = false\n  action = rebase if necessary\n", "groups": ["dummy_project6-core", "dummy_project6-ptl"]}, "dummy_project1-acl": {"file": "[access \"refs/*\"]\n  read = group dummy_project1-core\n  owner = group dummy_project1-ptl\n[access \"refs/heads/*\"]\n  label-Verified = -2..+2 group dummy_project1-ptl\n  label-Code-Review = -2..+2 group dummy_project1-core\n  label-Workflow = -1..+1 group dummy_project1-core\n  submit = group dummy_project1-ptl\n  read = group dummy_project1-core\n[access \"refs/meta/config\"]\n  read = group dummy_project1-core\n[receive]\n  requireChangeId = true\n[submit]\n  mergeContent = false\n  action = rebase if necessary\n", "groups": ["dummy_project1-core", "dummy_project1-ptl"]}, "dummy_project86-acl": {"file": "[access \"refs/*\"]\n  read = group dummy_project86-core\n  owner = group dummy_project86-ptl\n[access \"refs/heads/*\"]\n  label-Verified = -2..+2 group dummy_project86-ptl\n  label-Code-Review = -2..+2 group dummy_project86-core\n  label-Workflow = -1..+1 group dummy_project86-core\n  submit = group dummy_project86-ptl\n  read = group dummy_project86-core\n[access \"refs/meta/config\"]\n  read = group dummy_project86-core\n[receive]\n  requireChangeId = true\n[submit]\n  mergeContent = false\n  action = rebase if necessary\n", "groups": ["dummy_project86-core", "dummy_project86-ptl"]}, "dummy_project3-acl": {"file": "[access \"refs/*\"]\n  read = group dummy_project3-core\n  owner = group dummy_project3-ptl\n[access \"refs/heads/*\"]\n  label-Verified = -2..+2 group dummy_project3-ptl\n  label-Code-Review = -2..+2 group dummy_project3-core\n  label-Workflow = -1..+1 group dummy_project3-core\n  submit = group dummy_project3-ptl\n  read = group dummy_project3-core\n[access \"refs/meta/config\"]\n  read = group dummy_project3-core\n[receive]\n  requireChangeId = true\n[submit]\n  mergeContent = false\n  action = rebase if necessary\n", "groups": ["dummy_project3-core", "dummy_project3-ptl"]}, "dummy_project4-acl": {"file": "[access \"refs/*\"]\n  read = group dummy_project4-core\n  owner = group dummy_project4-ptl\n[access \"refs/heads/*\"]\n  label-Verified = -2..+2 group dummy_project4-ptl\n  label-Code-Review = -2..+2 group dummy_project4-core\n  label-Workflow = -1..+1 group dummy_project4-core\n  submit = group dummy_project4-ptl\n  read = group dummy_project4-core\n[access \"refs/meta/config\"]\n  read = group dummy_project4-core\n[receive]\n  requireChangeId = true\n[submit]\n  mergeContent = false\n  action = rebase if necessary\n", "groups": ["dummy_project4-core", "dummy_project4-ptl"]}, "tdpw-acl": {"file": "[access \"refs/*\"]\n  read = group tdpw-core\n  owner = group tdpw-ptl\n[access \"refs/heads/*\"]\n    label-Verified = -2..+2 group tdpw-ptl\n    label-Code-Review = -2..+2 group tdpw-core\n    label-Workflow = -1..+1 group tdpw-core\n    rebase = group tdpw-core\n    abandon = group tdpw-core\n    submit = group tdpw-ptl\n    read = group tdpw-core\n[access \"refs/tags/*\"]\n    pushTag = group tdpw-core\n    pushSignedTag = group tdpw-core\n[access \"refs/meta/config\"]\n    read = group tdpw-core\n[receive]\n    requireChangeId = true\n[submit]\n    mergeContent = false\n    action = rebase if necessary\n", "groups": ["tdpw-core", "tdpw-ptl"]}, "config-acl": {"file": "[access \"refs/*\"]\n  read = group config-core\n  owner = group config-ptl\n[access \"refs/heads/*\"]\n  label-Code-Review = -2..+2 group config-core\n  label-Code-Review = -2..+2 group config-ptl\n  label-Verified = -2..+2 group config-ptl\n  label-Workflow = -1..+1 group config-core\n  label-Workflow = -1..+1 group config-ptl\n  label-Workflow = -1..+0 group Registered Users\n  submit = group config-ptl\n  read = group config-core\n  read = group Registered Users\n[access \"refs/meta/config\"]\n  read = group config-core\n  read = group Registered Users\n[receive]\n  requireChangeId = true\n[submit]\n  mergeContent = false\n  action = fast forward only\n", "groups": ["config-ptl", "config-core"]}, "dummy_project2-acl": {"file": "[access \"refs/*\"]\n  read = group dummy_project2-core\n  owner = group dummy_project2-ptl\n[access \"refs/heads/*\"]\n  label-Verified = -2..+2 group dummy_project2-ptl\n  label-Code-Review = -2..+2 group dummy_project2-core\n  label-Workflow = -1..+1 group dummy_project2-core\n  submit = group dummy_project2-ptl\n  read = group dummy_project2-core\n[access \"refs/meta/config\"]\n  read = group dummy_project2-core\n[receive]\n  requireChangeId = true\n[submit]\n  mergeContent = false\n  action = rebase if necessary\n", "groups": ["dummy_project2-core", "dummy_project2-ptl"]}}, "groups": {"dummy_project3-ptl": {"description": "Project team lead for project dummy_project3", "members": ["admin@sftests.com"]}, "dummy_project4-core": {"description": "Core developers for project dummy_project4", "members": ["admin@sftests.com"]}, "dummy_project86-ptl": {"description": "Project team lead for project dummy_project86", "members": ["admin@sftests.com"]}, "dummy_project86-core": {"description": "Core developers for project dummy_project86", "members": ["admin@sftests.com"]}, "dummy_project2-core": {"description": "Core developers for project dummy_project2", "members": ["admin@sftests.com"]}, "dummy_project4-ptl": {"description": "Project team lead for project dummy_project4", "members": ["admin@sftests.com"]}, "dummy_project6-core": {"description": "Core developers for project dummy_project6", "members": ["admin@sftests.com"]}, "dummy_project2-ptl": {"description": "Project team lead for project dummy_project2", "members": ["admin@sftests.com"]}, "dummy_project6-ptl": {"description": "Project team lead for project dummy_project6", "members": ["admin@sftests.com"]}, "dummy_project3-core": {"description": "Core developers for project dummy_project3", "members": ["admin@sftests.com"]}, "config-core": {"description": "Team core for the config repo", "members": []}, "dummy_project1-ptl": {"description": "Project team lead for project dummy_project1", "members": ["admin@sftests.com"]}, "tdpw-ptl": {"description": "Project team lead for project tdpw", "members": ["alead@softwarefactory-project.io"], "name": "tdpw-ptl"}, "dummy_project1-core": {"description": "Core developers for project dummy_project1", "members": ["admin@sftests.com"]}, "config-ptl": {"description": "Team lead for the config repo", "members": ["admin@sftests.com"]}, "tdpw-core": {"description": "Core developers for project tdpw", "members": ["adev@softwarefactory-project.io", "alead@softwarefactory-project.io"], "name": "tdpw-core"}}, "projects": {"tdpw-project": {"issue-tracker": "SFStoryboard", "source-repositories": ["tdpw/python-readerlib", "tdpw/python-readerlib-distgit", "tdpw/reader", "tdpw/reader-distgit", "tdpw/reader-ansible", "tdpw/reader-ansible-distgit", "tdpw/tdpw-installer", "tdpw/tdpw-installer-distgit", "tdpw/tdpw-info"], "description": "The is a demo RPM distribution project to experiment", "name": "tdpw", "review-dashboard": "default"}, "internal": {"issue-tracker": "SFStoryboard", "source-repositories": ["config"], "description": "Internal configuration project"}, "dummy_project2": {"issue-tracker": "SFStoryboard", "source-repositories": ["dummy_project2"], "description": "Project dummy_project2"}, "dummy_project86": {"issue-tracker": "SFStoryboard", "source-repositories": ["dummy_project86"], "description": "Project dummy_project86"}, "dummy_project4": {"issue-tracker": "SFStoryboard", "source-repositories": ["dummy_project4"], "description": "Project dummy_project4"}, "dummy_project6": {"issue-tracker": "SFStoryboard", "source-repositories": ["dummy_project6"], "description": "Project dummy_project6"}, "dummy_project1": {"issue-tracker": "SFStoryboard", "source-repositories": ["dummy_project1"], "description": "Project dummy_project1"}, "my_project": {"documentation": "http://doc.project.com", "website": "http://project.com", "contacts": ["boss@project.com"], "mailing-lists": ["ml@project.com"], "issue-tracker": "SFStoryboard", "source-repositories": ["sexbobomb"], "description": "plop"}, "dummy_project3": {"issue-tracker": "SFStoryboard", "source-repositories": ["dummy_project3"], "description": "Project dummy_project3"}}}}  # noqa


# if somebody want to read this blob...

if __name__ == '__main__':
    import pprint
    pprint.pprint(SAMPLE_RESOURCES_TREE)
