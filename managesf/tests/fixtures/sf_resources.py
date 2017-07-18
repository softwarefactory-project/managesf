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


SAMPLE_RESOURCES_TREE = {
 'hash': '1234ab',
 'resources': {'acls': {'config-acl': {'file': '[...]',
                                       'groups': ['config-ptl',
                                                  'config-core']},
                        'dummy_project1-acl': {'file': '[...]',
                                               'groups': ['dummy_project1-core',  # noqa
                                                          'dummy_project1-ptl']},  # noqa
                        'dummy_project2-acl': {'file': '[...]',
                                               'groups': ['dummy_project2-core',  # noqa
                                                          'dummy_project2-ptl']},  # noqa
                        'dummy_project3-acl': {'file': '[...]',
                                               'groups': ['dummy_project3-core',  # noqa
                                                          'dummy_project3-ptl']},  # noqa
                        'dummy_project4-acl': {'file': '[...]',
                                               'groups': ['dummy_project4-core',  # noqa
                                                          'dummy_project4-ptl']},  # noqa
                        'dummy_project6-acl': {'file': '[...]',
                                               'groups': ['dummy_project6-core',  # noqa
                                                          'dummy_project6-ptl']},  # noqa
                        'dummy_project86-acl': {'file': '[...]',
                                                'groups': ['dummy_project86-core',  # noqa
                                                           'dummy_project86-ptl']},  # noqa
                        'tdpw-acl': {'file': '[...]',
                                     'groups': ['tdpw-core', 'tdpw-ptl']}},
               'groups': {'config-core': {'description': 'Team core for the config repo',  # noqa
                                          'members': []},
                          'config-ptl': {'description': 'Team lead for the config repo',  # noqa
                                         'members': ['admin@sftests.com']},
                          'dummy_project1-core': {'description': 'Core developers for project dummy_project1',  # noqa
                                                  'members': ['admin@sftests.com']},  # noqa
                          'dummy_project1-ptl': {'description': 'Project team lead for project dummy_project1',  # noqa
                                                 'members': ['admin@sftests.com']},  # noqa
                          'dummy_project2-core': {'description': 'Core developers for project dummy_project2',  # noqa
                                                  'members': ['admin@sftests.com']},  # noqa
                          'dummy_project2-ptl': {'description': 'Project team lead for project dummy_project2',  # noqa
                                                 'members': ['admin@sftests.com']},  # noqa
                          'dummy_project3-core': {'description': 'Core developers for project dummy_project3',  # noqa
                                                  'members': ['admin@sftests.com']},  # noqa
                          'dummy_project3-ptl': {'description': 'Project team lead for project dummy_project3',  # noqa
                                                 'members': ['admin@sftests.com']},  # noqa
                          'dummy_project4-core': {'description': 'Core developers for project dummy_project4',  # noqa
                                                  'members': ['admin@sftests.com']},  # noqa
                          'dummy_project4-ptl': {'description': 'Project team lead for project dummy_project4',  # noqa
                                                 'members': ['admin@sftests.com']},  # noqa
                          'dummy_project6-core': {'description': 'Core developers for project dummy_project6',  # noqa
                                                  'members': ['admin@sftests.com']},  # noqa
                          'dummy_project6-ptl': {'description': 'Project team lead for project dummy_project6',  # noqa
                                                 'members': ['admin@sftests.com']},  # noqa
                          'dummy_project86-core': {'description': 'Core developers for project dummy_project86',  # noqa
                                                   'members': ['admin@sftests.com']},  # noqa
                          'dummy_project86-ptl': {'description': 'Project team lead for project dummy_project86',  # noqa
                                                  'members': ['admin@sftests.com']},  # noqa
                          'tdpw-core': {'description': 'Core developers for project tdpw',  # noqa
                                        'members': ['adev@softwarefactory-project.io',  # noqa
                                                    'alead@softwarefactory-project.io'],  # noqa
                                        'name': 'tdpw-core'},
                          'tdpw-ptl': {'description': 'Project team lead for project tdpw',  # noqa
                                       'members': ['alead@softwarefactory-project.io'],  # noqa
                                       'name': 'tdpw-ptl'}},
               'projects': {'dummy_project1': {'description': 'Project dummy_project1',  # noqa
                                               'issue-tracker': 'SFStoryboard',
                                               'source-repositories': ['dummy_project1']},  # noqa
                            'dummy_project2': {'description': 'Project dummy_project2',  # noqa
                                               'issue-tracker': 'SFStoryboard',
                                               'source-repositories': ['dummy_project2']},  # noqa
                            'dummy_project3': {'description': 'Project dummy_project3',  # noqa
                                               'issue-tracker': 'SFStoryboard',
                                               'source-repositories': ['dummy_project3']},  # noqa
                            'dummy_project4': {'description': 'Project dummy_project4',  # noqa
                                               'issue-tracker': 'SFStoryboard',
                                               'source-repositories': ['dummy_project4']},  # noqa
                            'dummy_project6': {'description': 'Project dummy_project6',  # noqa
                                               'issue-tracker': 'SFStoryboard',
                                               'source-repositories': ['dummy_project6']},  # noqa
                            'dummy_project86': {'description': 'Project dummy_project86',  # noqa
                                                'issue-tracker': 'SFStoryboard',  # noqa
                                                'source-repositories': ['dummy_project86']},  # noqa
                            'internal': {'description': 'Internal configuration project',  # noqa
                                         'issue-tracker': 'SFStoryboard',
                                         'source-repositories': ['config']},
                            'my_project': {'contacts': ['boss@project.com'],
                                           'description': 'plop',
                                           'documentation': 'http://doc.project.com',  # noqa
                                           'issue-tracker': 'SFStoryboard',
                                           'mailing-lists': ['ml@project.com'],
                                           'source-repositories': ['sexbobomb'],  # noqa
                                           'website': 'http://project.com'},
                            'tdpw-project': {'description': 'The is a demo RPM distribution project to experiment',  # noqa
                                             'issue-tracker': 'SFStoryboard',
                                             'name': 'tdpw',
                                             'review-dashboard': 'default',
                                             'source-repositories': ['tdpw/python-readerlib',  # noqa
                                                                     'tdpw/python-readerlib-distgit',  # noqa
                                                                     'tdpw/reader',  # noqa
                                                                     'tdpw/reader-distgit',  # noqa
                                                                     'tdpw/reader-ansible',  # noqa
                                                                     'tdpw/reader-ansible-distgit',  # noqa
                                                                     'tdpw/tdpw-installer',  # noqa
                                                                     'tdpw/tdpw-installer-distgit',  # noqa
                                                                     'tdpw/tdpw-info']}},  # noqa
               'repos': {'config': {'acl': 'config-acl',
                                    'description': 'Config repository (Do not delete it)'},  # noqa
                         'dummy_project1': {'acl': 'dummy_project1-acl',
                                            'description': 'Code repository for dummy_project1'},  # noqa
                         'dummy_project2': {'acl': 'dummy_project2-acl',
                                            'description': 'Code repository for dummy_project2'},  # noqa
                         'dummy_project3': {'acl': 'dummy_project3-acl',
                                            'description': 'Code repository for dummy_project3'},  # noqa
                         'dummy_project4': {'acl': 'dummy_project4-acl',
                                            'description': 'Code repository for dummy_project4'},  # noqa
                         'dummy_project6': {'acl': 'dummy_project6-acl',
                                            'description': 'Code repository for dummy_project6'},  # noqa
                         'dummy_project86': {'acl': 'dummy_project86-acl',
                                             'description': 'Code repository for dummy_project86'},  # noqa
                         'sexbobomb': {'acl': 'config-acl',
                                       'description': 'oh yeah'},
                         'tdpw/python-readerlib': {'acl': 'tdpw-acl',
                                                   'description': 'Python library of the Reader project',  # noqa
                                                   'name': 'tdpw/python-readerlib'},  # noqa
                         'tdpw/python-readerlib-distgit': {'acl': 'tdpw-acl',
                                                           'description': 'RPM packaging for python-readerlib',  # noqa
                                                           'name': 'tdpw/python-readerlib-distgit'},  # noqa
                         'tdpw/reader': {'acl': 'tdpw-acl',
                                         'description': 'The Reader server',
                                         'name': 'tdpw/reader'},
                         'tdpw/reader-ansible': {'acl': 'tdpw-acl',
                                                 'description': 'The Ansible role of the Reader server',  # noqa
                                                 'name': 'tdpw/reader-ansible'},  # noqa
                         'tdpw/reader-ansible-distgit': {'acl': 'tdpw-acl',
                                                         'description': 'RPM packaging for the Reader Ansible role',  # noqa
                                                         'name': 'tdpw/reader-ansible-distgit'},  # noqa
                         'tdpw/reader-distgit': {'acl': 'tdpw-acl',
                                                 'description': 'RPM packaging for the Reader server',  # noqa
                                                 'name': 'tdpw/reader-distgit'},  # noqa
                         'tdpw/tdpw-info': {'acl': 'tdpw-acl',
                                            'description': 'tdpw Distribution info repository',  # noqa
                                            'name': 'tdpw/tdpw-info'},
                         'tdpw/tdpw-installer': {'acl': 'tdpw-acl',
                                                 'description': 'The installer for the tdpw RPM Distribution',  # noqa
                                                 'name': 'tdpw/tdpw-installer'},  # noqa
                         'tdpw/tdpw-installer-distgit': {'acl': 'tdpw-acl',
                                                         'description': 'RPM packaging for the tdpw Distribution installer',  # noqa
                                                         'name': 'tdpw/tdpw-installer-distgit'}}}  # noqa
}
