# -*- coding: utf-8 -*-
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


from unittest import TestCase
from mock import patch
from contextlib import nested

from managesf.model.yamlbkd import engine


class EngineRealResourcesTest(TestCase):
    def test_group_validation(self):
        patches = [
            patch('managesf.model.yamlbkd.engine.'
                  'SFResourceBackendEngine._load_resources_data'),
            patch('os.path.isdir'),
            patch('os.mkdir'),
            patch('managesf.model.yamlbkd.resources.group.'
                  'GroupOps.extra_validations'),
        ]
        master = {
            'resources': {
                'groups': {
                    'sf/g1': {
                        'description': 'This is a group',
                        'members': [
                            'user1@sftests.com',
                            'user2@sftests.com',
                            ]
                        }
                    }
                }
            }
        new = {
            'resources': {
                'groups': {
                    'sf/g1': {
                        'description': 'This is a cool group',
                        'members': [
                            'user1@sftests.com',
                            'user2@sftests.com',
                            ]
                        }
                    }
                }
            }

        with nested(*patches) as (l, i, m, xv):
            l.return_value = (master, new)
            xv.return_value = []
            eng = engine.SFResourceBackendEngine('fake', 'resources')
            valid, logs = eng.validate(None, None, None, None)
            self.assertTrue(valid)
            self.assertIn(
                'Resource [type: groups, ID: sf/g1] is going to be updated.',
                logs)
            self.assertEqual(len(logs), 1)

        master = {
            'resources': {
                'groups': {}
                }
            }
        new = {
            'resources': {
                'groups': {
                    'sf/g1': {
                        'description': 'This is a cool group',
                        'members': [
                            'user1@sftests.com',
                            'user2@sftests.com',
                            ]
                        }
                    }
                }
            }

        with nested(*patches) as (l, i, m, xv):
            l.return_value = (master, new)
            xv.return_value = []
            eng = engine.SFResourceBackendEngine('fake', 'resources')
            valid, logs = eng.validate(None, None, None, None)
            self.assertTrue(valid)
            self.assertIn(
                'Resource [type: groups, ID: sf/g1] is going to be created.',
                logs)
            self.assertEqual(len(logs), 1)

        master = {
            'resources': {
                'groups': {
                    'sf/g1': {
                        'description': 'This is a group',
                        'members': [
                            'user1@sftests.com',
                            'user2@sftests.com',
                            ]
                        }
                    }
                }
            }
        new = {
            'resources': {
                'groups': {
                    'sf/g1': {
                        'description': 'This is a group',
                        'members': [
                            'user2@sftests.com',
                            ]
                        }
                    }
                }
            }
        with nested(*patches) as (l, i, m, xv):
            l.return_value = (master, new)
            xv.return_value = []
            eng = engine.SFResourceBackendEngine('fake', 'resources')
            valid, logs = eng.validate(None, None, None, None)
            self.assertTrue(valid)
            self.assertIn(
                'Resource [type: groups, ID: sf/g1] is going to be updated.',
                logs)
            self.assertEqual(len(logs), 1)

        master = {
            'resources': {
                'groups': {
                    'sf/g1': {
                        'description': 'This is a group',
                        'members': [
                            'user1@sftests.com',
                            'user2@sftests.com',
                            ]
                        }
                    }
                }
            }
        new = {
            'resources': {
                'groups': {
                    'sf/g2': {
                        'description': 'This is a group',
                        'members': [
                            'user4@sftests.com',
                            ]
                        }
                    }
                }
            }
        with nested(*patches) as (l, i, m, xv):
            l.return_value = (master, new)
            xv.return_value = []
            eng = engine.SFResourceBackendEngine('fake', 'resources')
            valid, logs = eng.validate(None, None, None, None)
            self.assertTrue(valid)
            self.assertIn(
                'Resource [type: groups, ID: sf/g1] is going to be deleted.',
                logs)
            self.assertIn(
                'Resource [type: groups, ID: sf/g2] is going to be created.',
                logs)
            self.assertEqual(len(logs), 2)

        master = {
            'resources': {
                'groups': {},
                }
            }
        new = {
            'resources': {
                'groups': {
                    'sf/g1': {
                        'description': 'This is a cool group',
                        'members': [
                            'notfound@sftests.com'
                            ]
                        }
                    }
                }
            }
        with nested(*patches) as (l, i, m, xv):
            l.return_value = (master, new)
            xv.return_value = ['Check group members [notfound@sftests.com '
                               'does not exists]: err API unable to find '
                               'the member']
            eng = engine.SFResourceBackendEngine('fake', 'resources')
            valid, logs = eng.validate(None, None, None, None)
            # The member is not known
            self.assertFalse(valid)
            self.assertIn(
                "Check group members [notfound@sftests.com does not exists]: "
                "err API unable to find the member",
                logs)
            self.assertIn(
                "Resource [type: groups, ID: sf/g1] extra validations failed",
                logs)
            self.assertEqual(len(logs), 2)

        patches = [
            patch('managesf.model.yamlbkd.engine.'
                  'SFResourceBackendEngine._load_resources_data'),
            patch('os.path.isdir'),
            patch('os.mkdir'),
            patch('managesf.model.yamlbkd.resources.group.GroupOps.'
                  'check_account_members'),
        ]

        master = {
            'resources': {
                'groups': {}
                }
            }
        new = {
            'resources': {
                'groups': {
                    'Administrators': {
                        'description': 'This is the Admin group',
                        'members': [
                            'user1@sftests.com',
                            'user2@sftests.com',
                            ]
                        }
                    }
                }
            }

        with nested(*patches) as (l, i, m, cam):
            l.return_value = (master, new)
            cam.return_value = []
            eng = engine.SFResourceBackendEngine('fake', 'resources')
            valid, logs = eng.validate(None, None, None, None)
            self.assertFalse(valid)
            self.assertIn(
                'Check group name [Administrators in not managed '
                'by this API]', logs)
            self.assertIn(
                'Resource [type: groups, ID: Administrators] extra '
                'validations failed', logs)
            self.assertEqual(len(logs), 2)

    def test_acls_validation(self):
        patches = [
            patch('managesf.model.yamlbkd.engine.'
                  'SFResourceBackendEngine._load_resources_data'),
            patch('os.path.isdir'),
            patch('os.mkdir'),
            patch('managesf.model.yamlbkd.resources.gitacls.'
                  'ACLOps.extra_validations'),
        ]
        master = {
            'resources': {
                'acls': {}
                }
            }
        new = {
            'resources': {
                'acls': {
                    'a1': {
                        'file': "this is a\nfake acls",
                        'groups': ['g1'],
                        }
                    }
                }
            }

        with nested(*patches) as (l, i, m, xv):
            l.return_value = (master, new)
            xv.return_value = []
            eng = engine.SFResourceBackendEngine('fake', 'resources')
            valid, logs = eng.validate(None, None, None, None)
            # The group on which the ACLs depends on is missing
            self.assertFalse(valid)
            self.assertIn(
                'Resource [type: acls, ID: a1] depends on an unknown '
                'resource [type: groups, ID: g1]',
                logs)
            self.assertEqual(len(logs), 1)

        master = {
            'resources': {
                'acls': {},
                'groups': {
                    'sf/g1': {
                        'description': 'This is a group',
                        'members': [
                            'user1@sftests.com',
                            'user2@sftests.com',
                            ]
                        }
                    }
                }
            }
        new = {
            'resources': {
                'acls': {
                    'a1': {
                        'file': "this is a\nfake acls",
                        'groups': ['sf/g1'],
                        }
                    },
                'groups': {
                    'sf/g1': {
                        'description': 'This is a group',
                        'members': [
                            'user1@sftests.com',
                            'user2@sftests.com',
                            ]
                        }
                    }
                }
            }
        with nested(*patches) as (l, i, m, xv):
            l.return_value = (master, new)
            xv.return_value = []
            eng = engine.SFResourceBackendEngine('fake', 'resources')
            valid, logs = eng.validate(None, None, None, None)
            self.assertTrue(valid)
            self.assertIn(
                'Resource [type: acls, ID: a1] is going to be created.',
                logs)
            self.assertEqual(len(logs), 1)

        master = {
            'resources': {
                'acls': {
                    'a1': {
                        'file': "this is a\nfake acls",
                        'groups': ['g1'],
                        }
                    },
                'groups': {
                    'sf/g1': {
                        'description': 'This is a group',
                        'members': [
                            'user1@sftests.com',
                            'user2@sftests.com',
                            ]
                        }
                    }
                }
            }
        new = {
            'resources': {
                'acls': {},
                'groups': {
                    'sf/g1': {
                        'description': 'This is a group',
                        'members': [
                            'user1@sftests.com',
                            'user2@sftests.com',
                            ]
                        }
                    }
                }
            }
        with nested(*patches) as (l, i, m, xv):
            l.return_value = (master, new)
            xv.return_value = []
            eng = engine.SFResourceBackendEngine('fake', 'resources')
            valid, logs = eng.validate(None, None, None, None)
            self.assertTrue(valid)
            self.assertIn(
                'Resource [type: acls, ID: a1] is going to be deleted.',
                logs)
            self.assertEqual(len(logs), 1)

        master = {
            'resources': {
                'acls': {
                    'a1': {
                        'file': "this is a\nfake acls",
                        'groups': ['sf/g1'],
                        }
                    },
                'groups': {
                    'sf/g1': {
                        'description': 'This is a group',
                        'members': [
                            'user1@sftests.com',
                            'user2@sftests.com',
                            ]
                        }
                    }
                }
            }
        new = {
            'resources': {
                'acls': {
                    'a1': {
                        'file': "this is a\nfake acls",
                        'groups': ['sf/g1'],
                        }
                    },
                'groups': {},
                }
            }
        with nested(*patches) as (l, i, m, xv):
            l.return_value = (master, new)
            xv.return_value = []
            eng = engine.SFResourceBackendEngine('fake', 'resources')
            valid, logs = eng.validate(None, None, None, None)
            # The group on which the ACLs depends on is missing because
            # it has been removed between master and new
            self.assertFalse(valid)
            self.assertIn(
                'Resource [type: acls, ID: a1] depends on an unknown '
                'resource [type: groups, ID: sf/g1]',
                logs)
            self.assertEqual(len(logs), 1)

        patches = [
            patch('managesf.model.yamlbkd.engine.'
                  'SFResourceBackendEngine._load_resources_data'),
            patch('os.path.isdir'),
            patch('os.mkdir'),
            # Re-enable the ACLs extra validation but mock
            # the group one
            patch('managesf.model.yamlbkd.resources.group.'
                  'GroupOps.extra_validations'),
        ]

        master = {
            'resources': {
                'acls': {},
                'groups': {
                    'sf/g1': {
                        'description': 'This is a group',
                        'members': [
                            'user1@sftests.com',
                            'user2@sftests.com',
                            ]
                        },
                    }
                }
            }
        new = {
            'resources': {
                'acls': {
                    'a1': {
                        'file': """[project]
    description = A description
[access "refs/*"]
    read = group sf/g1
    owner = group sf/g1
[access "refs/heads/*"]
    label-Code-Review = -2..+2 group sf/g1
    label-Verified = -2..+2 group sf/g1
    label-Workflow = -1..+1 group sf/g1
    submit = group sf/g1
    read = group sf/g1
""",
                        'groups': ['sf/g1'],
                        }
                    },
                'groups': {
                    'sf/g1': {
                        'description': 'This is a group',
                        'members': [
                            'user1@sftests.com',
                            'user2@sftests.com',
                            ]
                        },
                    }
                }
            }

        with nested(*patches) as (l, i, m, xv):
            l.return_value = (master, new)
            xv.return_value = []
            eng = engine.SFResourceBackendEngine('fake', 'resources')
            valid, logs = eng.validate(None, None, None, None)
            self.assertTrue(valid)
            self.assertIn(
                'Resource [type: acls, ID: a1] is going to be created.',
                logs)
            self.assertEqual(len(logs), 1)

        master = {
            'resources': {
                'acls': {},
                'groups': {
                    'sf/g1': {
                        'description': 'This is a group',
                        'members': [
                            'user1@sftests.com',
                            'user2@sftests.com',
                            ]
                        },
                    }
                }
            }
        new = {
            'resources': {
                'acls': {
                    'a1': {
                        'file': """This ACL is
wrong ! This string won't be accepted by Gerrit !
""",
                        'groups': ['sf/g1'],
                        }
                    },
                'groups': {
                    'sf/g1': {
                        'description': 'This is a group',
                        'members': [
                            'user1@sftests.com',
                            'user2@sftests.com',
                            ]
                        },
                    }
                }
            }

        with nested(*patches) as (l, i, m, xv):
            l.return_value = (master, new)
            xv.return_value = []
            eng = engine.SFResourceBackendEngine('fake', 'resources')
            valid, logs = eng.validate(None, None, None, None)
            # The ACLs is not a valid Git Style config file
            self.assertFalse(valid)
            self.assertTrue(logs[0].startswith(
                "File contains no section headers."))
            self.assertIn(
                'Resource [type: acls, ID: a1] extra validations failed',
                logs)
            self.assertEqual(len(logs), 2)

        master = {
            'resources': {
                'acls': {},
                'groups': {
                    'sf/g1': {
                        'description': 'This is a group',
                        'members': [
                            'user1@sftests.com',
                            'user2@sftests.com',
                            ]
                        },
                    }
                }
            }
        new = {
            'resources': {
                'acls': {
                    'a1': {
                        'file': """[project]
    description = A description
[access "refs/*"]
    read = group sf/g1
    owner = group sf/g1
[access "refs/heads/*"]
    label-Code-Review = -2..+2 group sf/g1
    label-Verified = -2..+2 group sf/g1
    label-Workflow = -1..+1 group sf/g1
    submit = group sf/g2
    read = group sf/g1
""",
                        'groups': ['sf/g1'],
                        }
                    },
                'groups': {
                    'sf/g1': {
                        'description': 'This is a group',
                        'members': [
                            'user1@sftests.com',
                            'user2@sftests.com',
                            ]
                        },
                    }
                }
            }

        with nested(*patches) as (l, i, m, xv):
            l.return_value = (master, new)
            xv.return_value = []
            eng = engine.SFResourceBackendEngine('fake', 'resources')
            valid, logs = eng.validate(None, None, None, None)
            # sf/g2 is not a known group
            self.assertFalse(valid)
            self.assertIn('ACLs file section (access "refs/heads/*"), key '
                          '(submit) relies on an unknown group name: sf/g2',
                          logs)
            self.assertIn('Resource [type: acls, ID: a1] extra validations '
                          'failed', logs)
            self.assertEqual(len(logs), 2)

        new = {
            'resources': {
                'acls': {
                    'a1': {
                        'file': """[project]
    description = A description
[access "refs/*"]
    read = group sf/g1
    owner = group sf/g1
[access "refs/heads/*"]
    label-Code-Review = -2..+2 group sf/g1
    label-Verified = -2..+2 group sf/g1
    label-Workflow = -1..+1 group sf/g1
    submit = group sf/g2
    read = group sf/g1
""",
                        'groups': ['sf/g1', 'others/g2'],
                        }
                    },
                'groups': {
                    'sf/g1': {
                        'description': 'This is a group',
                        'members': [
                            'user1@sftests.com',
                            'user2@sftests.com',
                            ]
                        },
                    'others/g2': {
                        'description': 'This is a group',
                        'members': [
                            'user1@sftests.com',
                            'user2@sftests.com',
                            ]
                        },
                    }
                }
            }
        with nested(*patches) as (l, i, m, xv):
            l.return_value = (master, new)
            xv.return_value = []
            eng = engine.SFResourceBackendEngine('fake', 'resources')
            valid, logs = eng.validate(None, None, None, None)
            # others/g2 is not a known group
            self.assertFalse(valid)
            self.assertIn('ACLs file section (access "refs/heads/*"), key '
                          '(submit) relies on an unknown group name: sf/g2',
                          logs)
            self.assertIn('Resource [type: acls, ID: a1] extra validations '
                          'failed', logs)

        new = {
            'resources': {
                'acls': {
                    'a1': {
                        'file': """[project]
    description = A description
[access "refs/*"]
    read = group sf/g1
    owner = group sf/g1
[access "refs/heads/*"]
    label-Code-Review = -2..+2 group sf/g1
    label-Verified = -2..+2 group sf/g1
    label-Workflow = -1..+1 group sf/g1
    submit = group g2
    read = group sf/g1
""",
                        'groups': ['sf/g1', 'g2'],
                        }
                    },
                'groups': {
                    'sf/g1': {
                        'description': 'This is a group',
                        'members': [
                            'user1@sftests.com',
                            'user2@sftests.com',
                            ]
                        },
                    'g2': {
                        'description': 'This is a group',
                        'members': [
                            'user1@sftests.com',
                            'user2@sftests.com',
                            ]
                        },
                    }
                }
            }
        with nested(*patches) as (l, i, m, xv):
            l.return_value = (master, new)
            xv.return_value = []
            eng = engine.SFResourceBackendEngine('fake', 'resources')
            valid, logs = eng.validate(None, None, None, None)

    def test_gitrepo_validation(self):
        patches = [
            patch('managesf.model.yamlbkd.engine.'
                  'SFResourceBackendEngine._load_resources_data'),
            patch('os.path.isdir'),
            patch('os.mkdir'),
            patch('managesf.model.yamlbkd.resources.gitacls.'
                  'ACLOps.extra_validations'),
        ]
        master = {
            'resources': {
                'acls': {
                    'a1': {
                        'file': 'fake',
                        }
                    },
                'repos': {},
                }
            }
        new = {
            'resources': {
                'repos': {
                    'sf/r1': {
                        'description': 'This is a GIT repo',
                        'acl': 'a1'
                        }
                    },
                'acls': {
                    'a1': {
                        'file': 'fake',
                        }
                    }
                }
            }

        with nested(*patches) as (l, i, m, xv):
            l.return_value = (master, new)
            xv.return_value = []
            eng = engine.SFResourceBackendEngine('fake', 'resources')
            valid, logs = eng.validate(None, None, None, None)
            self.assertTrue(valid)
            self.assertIn('Resource [type: repos, ID: sf/r1] is going to '
                          'be created.',
                          logs)
            self.assertEqual(len(logs), 1)

        master = {
            'resources': {
                'repos': {
                    'sf/r1': {
                        'description': 'This is a GIT repo',
                        'acl': 'a1'
                        }
                    },
                'acls': {
                    'a1': {
                        'file': 'fake',
                        }
                    },
                }
            }
        new = {
            'resources': {
                'repos': {
                    'sf/r1': {
                        'description': 'This is a GIT repo',
                        'acl': 'a1'
                        }
                    },
                'acls': {
                    'a1': {
                        'file': 'fake2',
                        }
                    }
                }
            }

        with nested(*patches) as (l, i, m, xv):
            l.return_value = (master, new)
            xv.return_value = []
            eng = engine.SFResourceBackendEngine('fake', 'resources')
            valid, logs = eng.validate(None, None, None, None)
            self.assertTrue(valid)
            self.assertIn('Resource [type: acls, ID: a1] is going to '
                          'be updated.', logs)
            self.assertIn('Resource [type: repos, ID: sf/r1] need a refresh '
                          'as at least one of its dependencies has been '
                          'updated', logs)
            self.assertEqual(len(logs), 2)

        master = {
            'resources': {
                'repos': {
                    'sf/r1': {
                        'description': 'This is a GIT repo',
                        'acl': 'a1'
                        }
                    },
                'acls': {
                    'a1': {
                        'file': 'fake',
                        }
                    },
                }
            }

        new = {
            'resources': {
                'repos': {
                    'sf/r1': {
                        'description': 'This is a GIT repo',
                        'acl': 'a1'
                        }
                    },
                'acls': {},
                }
            }
        with nested(*patches) as (l, i, m, xv):
            l.return_value = (master, new)
            xv.return_value = []
            eng = engine.SFResourceBackendEngine('fake', 'resources')
            # GIT repository relie on an unknown ACL
            valid, logs = eng.validate(None, None, None, None)
            self.assertFalse(valid)
            self.assertIn('Resource [type: repos, ID: sf/r1] depends on '
                          'an unknown resource [type: acls, ID: a1]', logs)
            self.assertEqual(len(logs), 1)

    def test_project_validation(self):
        patches = [
            patch('managesf.model.yamlbkd.engine.'
                  'SFResourceBackendEngine._load_resources_data'),
            patch('os.path.isdir'),
            patch('os.mkdir'),
            patch('managesf.model.yamlbkd.resources.gitacls.'
                  'ACLOps.extra_validations'),
            patch('managesf.model.yamlbkd.resources.group.'
                  'GroupOps.extra_validations'),
        ]
        master = {
            'resources': {
                'projects': {},
                'groups': {},
                'acls': {
                    'a1': {
                        'file': 'fake',
                        }
                    },
                'repos': {
                    'r1': {
                        'name': 'sf/r1',
                        'description': 'This is a GIT repo',
                        'acl': 'a1'
                        }
                    }
                }
            }
        new = {
            'resources': {
                'projects': {
                    'p1': {
                        'name': 'p1',
                        'description': 'An awesome project',
                        'source-repositories': ['r1'],
                    },
                },
                'groups': {},
                'repos': {
                    'r1': {
                        'name': 'sf/r1',
                        'description': 'This is a GIT repo',
                        'acl': 'a1'
                        }
                    },
                'acls': {
                    'a1': {
                        'file': 'fake',
                        }
                    }
                }
            }

        with nested(*patches) as (l, i, m, xv, xv2):
            l.return_value = (master, new)
            xv.return_value = []
            eng = engine.SFResourceBackendEngine('fake', 'resources')
            valid, logs = eng.validate(None, None, None, None)
            self.assertTrue(valid)
            self.assertIn('Resource [type: projects, ID: p1] is going to '
                          'be created.', logs)
            self.assertEqual(len(logs), 1)

        new = {
            'resources': {
                'projects': {
                    'p1': {
                        'name': 'p1',
                        'description': 'An awesome project',
                        'source-repositories': ['r1', 'r2'],
                    },
                },
                'groups': {},
                'repos': {
                    'r1': {
                        'name': 'sf/r1',
                        'description': 'This is a GIT repo',
                        'acl': 'a1'
                        }
                    },
                'acls': {
                    'a1': {
                        'file': 'fake',
                        }
                    }
                }
            }
        with nested(*patches) as (l, i, m, xv, xv2):
            l.return_value = (master, new)
            xv.return_value = []
            eng = engine.SFResourceBackendEngine('fake', 'resources')
            valid, logs = eng.validate(None, None, None, None)
            # Project depends on an unknown r2 resource
            self.assertFalse(valid)
            self.assertIn('Resource [type: projects, ID: p1] depends on '
                          'an unknown resource [type: repos, ID: r2]',
                          logs)
            self.assertEqual(len(logs), 1)

        master = {
            'resources': {
                'projects': {
                    'p1': {
                        'name': 'p1',
                        'description': 'An awesome project',
                        'source-repositories': ['r1'],
                    },
                },
                'groups': {},
                'acls': {
                    'a1': {
                        'file': 'fake',
                        }
                    },
                'repos': {
                    'r1': {
                        'name': 'sf/r1',
                        'description': 'This is a GIT repo',
                        'acl': 'a1'
                        }
                    }
                }
            }
        new = {
            'resources': {
                'projects': {
                    'p1': {
                        'name': 'p1',
                        'description': 'An awesome project',
                        'source-repositories': ['r1'],
                    },
                },
                'repos': {
                    'r1': {
                        'name': 'sf/r1',
                        'description': 'This is a GIT repo',
                        'acl': 'a1'
                        }
                    },
                'acls': {
                    'a1': {
                        'file': 'fake',
                        'groups': ['g1'],
                        }
                    },
                'groups': {
                    'g1': {
                        'name': 'sf/g1',
                        'members': [],
                    },
                }
            }
        }
        with nested(*patches) as (l, i, m, xv, xv2):
            l.return_value = (master, new)
            xv.return_value = []
            xv2.return_value = []
            eng = engine.SFResourceBackendEngine('fake', 'resources')
            valid, logs = eng.validate(None, None, None, None)
            self.assertTrue(valid)
            self.assertIn('Resource [type: acls, ID: a1] is going '
                          'to be updated.', logs)
            self.assertIn('Resource [type: projects, ID: p1] need a '
                          'refresh as at least one of its dependencies '
                          'has been updated', logs)
            self.assertIn('Resource [type: groups, ID: g1] is '
                          'going to be created.', logs)
            self.assertIn('Resource [type: repos, ID: r1] need a '
                          'refresh as at least one of its dependencies '
                          'has been updated', logs)
            self.assertEqual(len(logs), 4)

    def test_get_missing_resources(self):
        patches = [
            patch('managesf.model.yamlbkd.engine.'
                  'SFResourceBackendEngine.get'),
            patch('managesf.model.yamlbkd.resources.gitrepository.'
                  'GitRepositoryOps.get_all'),
            patch('managesf.model.yamlbkd.resources.group.'
                  'GroupOps.get_all'),
        ]
        eng = engine.SFResourceBackendEngine(None, None)
        current_resources = {
            'resources': {
                'projects': {
                    'p1': {
                        'description': 'An awesome project',
                        'source-repositories': ['r1'],
                    },
                },
                'groups': {
                    'g1': {
                        'members': ['user2@sftests.com'],
                    },
                    'g2': {
                        'members': ['user3@sftests.com'],
                    },
                },
                'repos': {
                    'sf/r1': {
                        'acl': 'a1',
                    },
                    'sf/r2': {
                        'acl': 'a1',
                    },
                },
                'acls': {
                    'a1': {
                        'file': 'fake',
                        'groups': [],
                    }
                }
            }
        }
        gr_reality = {
            'repos': {
                'sf/r1': {
                    'acl': 'hash77',
                },
                'sf/r2': {
                    'acl': 'hash77',
                },
                'sf/r3': {
                    'acl': 'hash77',
                },
            },
            'acls': {
                'hash77': {
                    'file': 'fake',
                    'groups': [],
                },
                'hash78': {
                    'file': 'fake2',
                    'groups': [],
                },
            },
        }
        g_reality = {
            'groups': {
                'g3': {
                    'members': ['user3@sftests.com'],
                },
            },
        }
        expected = {
            'resources': {
                'groups': {
                    'g3': {
                        'members': ['user3@sftests.com']
                    },
                },
                'repos': {
                    'sf/r3': {
                        'acl': 'a1',
                    }
                },
                'acls': {
                    'hash78': {
                        'groups': [],
                        'file': 'fake2',
                    }
                },
            }
        }

        with nested(*patches) as (g, gar, gag):
            gar.return_value = ([], gr_reality)
            gag.return_value = ([], g_reality)
            g.return_value = current_resources
            logs, tree = eng.get_missing_resources(None, None)
            self.assertListEqual(logs, [])
            self.assertDictEqual(tree, expected)
