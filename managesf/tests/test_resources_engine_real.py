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

from managesf.tests import dummy_conf

from managesf.model.yamlbkd import engine


class EngineRealResourcesTest(TestCase):

    @classmethod
    def setupClass(cls):
        cls.conf = dummy_conf()
        engine.conf = cls.conf

    def test_unknown_resources(self):
        master = {
            'resources': {}
        }
        new = {
            'resources': {
                'abc': {
                }
            }
        }

        with patch('managesf.model.yamlbkd.engine.'
                   'SFResourceBackendEngine._load_resources_data') as lrd, \
                patch('os.path.isdir'), \
                patch('os.mkdir'):
            lrd.return_value = (master, new)
            eng = engine.SFResourceBackendEngine('fake', 'resources')
            valid, logs = eng.validate(None, None, None, None)
            self.assertFalse(valid)
            self.assertEqual(len(logs), 1)
            self.assertIn('Resources type: abc not exists', logs)

    def test_group_validation(self):
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

        with patch('managesf.model.yamlbkd.engine.'
                   'SFResourceBackendEngine._load_resources_data') as lrd, \
                patch('os.path.isdir'), \
                patch('os.mkdir'), \
                patch('managesf.model.yamlbkd.resources.group.'
                      'GroupOps.extra_validations') as xv:
            lrd.return_value = (master, new)
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

        with patch('managesf.model.yamlbkd.engine.'
                   'SFResourceBackendEngine._load_resources_data') as lrd, \
                patch('os.path.isdir'), \
                patch('os.mkdir'), \
                patch('managesf.model.yamlbkd.resources.group.'
                      'GroupOps.extra_validations') as xv:
            lrd.return_value = (master, new)
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
        with patch('managesf.model.yamlbkd.engine.'
                   'SFResourceBackendEngine._load_resources_data') as lrd, \
                patch('os.path.isdir'), \
                patch('os.mkdir'), \
                patch('managesf.model.yamlbkd.resources.group.'
                      'GroupOps.extra_validations') as xv:
            lrd.return_value = (master, new)
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
        with patch('managesf.model.yamlbkd.engine.'
                   'SFResourceBackendEngine._load_resources_data') as lrd, \
                patch('os.path.isdir'), \
                patch('os.mkdir'), \
                patch('managesf.model.yamlbkd.resources.group.'
                      'GroupOps.extra_validations') as xv:
            lrd.return_value = (master, new)
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
        with patch('managesf.model.yamlbkd.engine.'
                   'SFResourceBackendEngine._load_resources_data') as lrd, \
                patch('os.path.isdir'), \
                patch('os.mkdir'), \
                patch('managesf.model.yamlbkd.resources.group.'
                      'GroupOps.extra_validations') as xv:
            lrd.return_value = (master, new)
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

        with patch('managesf.model.yamlbkd.engine.'
                   'SFResourceBackendEngine._load_resources_data') as lrd, \
                patch('os.path.isdir'), \
                patch('os.mkdir'), \
                patch('managesf.model.yamlbkd.resources.group.GroupOps.'
                      'check_account_members') as cam:
            lrd.return_value = (master, new)
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

    def test_deps_inheritage(self):
        # Verifiy a group update does not trigger a full chain update
        master = {
            'resources': {
                'groups': {
                    'sf/g1': {
                        'description': 'This is a group',
                        'members': [
                            'user1@sftests.com',
                            ]
                        }
                    },
                'acls': {
                    'a1': {
                        'file': "this is a\nfake acls",
                        'groups': ['sf/g1'],
                        }
                    },
                'repos': {
                    'r1': {
                        'name': 'sf/r1',
                        'description': 'This is a GIT repo',
                        'acl': 'a1'
                        }
                    },
                'projects': {
                    'p1': {
                        'name': 'p1',
                        'description': 'An awesome project',
                        'source-repositories': ['r1'],
                    },
                }
            }
        }
        new = {
            'resources': {
                'groups': {
                    'sf/g1': {
                        'description': 'This is a group',
                        'members': [
                            'user1@sftests.com',
                            'user2@sftests.com',
                            ]
                        }
                    },
                'acls': {
                    'a1': {
                        'file': "this is a\nfake acls",
                        'groups': ['sf/g1'],
                        }
                    },
                'repos': {
                    'r1': {
                        'name': 'sf/r1',
                        'description': 'This is a GIT repo',
                        'acl': 'a1'
                        }
                    },
                'projects': {
                    'p1': {
                        'name': 'p1',
                        'description': 'An awesome project',
                        'source-repositories': ['r1'],
                    },
                }
            }
        }

        # Verify the ACL update trigger the dependency chain update
        with patch('managesf.model.yamlbkd.engine.'
                   'SFResourceBackendEngine._load_resources_data') as lrd, \
                patch('os.path.isdir'), \
                patch('os.mkdir'), \
                patch('managesf.model.yamlbkd.resources.gitacls.'
                      'ACLOps.extra_validations') as xv, \
                patch('managesf.model.yamlbkd.resources.group.'
                      'GroupOps.extra_validations') as xv2:
            lrd.return_value = (master, new)
            xv.return_value = []
            xv2.return_value = []
            eng = engine.SFResourceBackendEngine('fake', 'resources')
            valid, logs = eng.validate(None, None, None, None)
            self.assertTrue(valid)
            self.assertIn(
                'Resource [type: groups, ID: sf/g1] is going to be updated.',
                logs)
            self.assertEqual(len(logs), 1)

        new = {
            'resources': {
                'groups': {
                    'sf/g1': {
                        'description': 'This is a group',
                        'members': [
                            'user1@sftests.com',
                            ]
                        }
                    },
                'acls': {
                    'a1': {
                        'file': "this is a modified\nfake acls",
                        'groups': ['sf/g1'],
                        }
                    },
                'repos': {
                    'r1': {
                        'name': 'sf/r1',
                        'description': 'This is a GIT repo',
                        'acl': 'a1'
                        }
                    },
                'projects': {
                    'p1': {
                        'name': 'p1',
                        'description': 'An awesome project',
                        'source-repositories': ['r1'],
                    },
                }
            }
        }
        with patch('managesf.model.yamlbkd.engine.'
                   'SFResourceBackendEngine._load_resources_data') as lrd, \
                patch('os.path.isdir'), \
                patch('os.mkdir'), \
                patch('managesf.model.yamlbkd.resources.gitacls.'
                      'ACLOps.extra_validations') as xv, \
                patch('managesf.model.yamlbkd.resources.group.'
                      'GroupOps.extra_validations') as xv2:
            lrd.return_value = (master, new)
            xv.return_value = []
            xv2.return_value = []
            eng = engine.SFResourceBackendEngine('fake', 'resources')
            valid, logs = eng.validate(None, None, None, None)
            self.assertTrue(valid)
            self.assertIn(
                'Resource [type: acls, ID: a1] is going to be updated.',
                logs)
            self.assertIn(
                'Resource [type: repos, ID: r1] need a refresh as at least '
                'one of its dependencies has been updated',
                logs)
            self.assertIn(
                'Resource [type: projects, ID: p1] need a refresh as at least '
                'one of its dependencies has been updated',
                logs)
            self.assertEqual(len(logs), 3)

    def test_acls_validation(self):
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
        with patch('managesf.model.yamlbkd.engine.'
                   'SFResourceBackendEngine._load_resources_data') as lrd, \
                patch('os.path.isdir'), \
                patch('os.mkdir'), \
                patch('managesf.model.yamlbkd.resources.gitacls.'
                      'ACLOps.extra_validations') as xv:
            lrd.return_value = (master, new)
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
        with patch('managesf.model.yamlbkd.engine.'
                   'SFResourceBackendEngine._load_resources_data') as lrd, \
                patch('os.path.isdir'), \
                patch('os.mkdir'), \
                patch('managesf.model.yamlbkd.resources.gitacls.'
                      'ACLOps.extra_validations') as xv:
            lrd.return_value = (master, new)
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
        with patch('managesf.model.yamlbkd.engine.'
                   'SFResourceBackendEngine._load_resources_data') as lrd, \
                patch('os.path.isdir'), \
                patch('os.mkdir'), \
                patch('managesf.model.yamlbkd.resources.gitacls.'
                      'ACLOps.extra_validations') as xv:
            lrd.return_value = (master, new)
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
        with patch('managesf.model.yamlbkd.engine.'
                   'SFResourceBackendEngine._load_resources_data') as lrd, \
                patch('os.path.isdir'), \
                patch('os.mkdir'), \
                patch('managesf.model.yamlbkd.resources.group.'
                      'GroupOps.extra_validations') as xv:
            lrd.return_value = (master, new)
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
[access "refs/for/*"]
    addPatchSet = group sf/g1
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

        with patch('managesf.model.yamlbkd.engine.'
                   'SFResourceBackendEngine._load_resources_data') as lrd, \
                patch('os.path.isdir'), \
                patch('os.mkdir'), \
                patch('managesf.model.yamlbkd.resources.group.'
                      'GroupOps.extra_validations') as xv:
            lrd.return_value = (master, new)
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

        with patch('managesf.model.yamlbkd.engine.'
                   'SFResourceBackendEngine._load_resources_data') as lrd, \
                patch('os.path.isdir'), \
                patch('os.mkdir'), \
                patch('managesf.model.yamlbkd.resources.group.'
                      'GroupOps.extra_validations') as xv:
            lrd.return_value = (master, new)
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
        with patch('managesf.model.yamlbkd.engine.'
                   'SFResourceBackendEngine._load_resources_data') as lrd, \
                patch('os.path.isdir'), \
                patch('os.mkdir'), \
                patch('managesf.model.yamlbkd.resources.group.'
                      'GroupOps.extra_validations') as xv:
            lrd.return_value = (master, new)
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
        with patch('managesf.model.yamlbkd.engine.'
                   'SFResourceBackendEngine._load_resources_data') as lrd, \
                patch('os.path.isdir'), \
                patch('os.mkdir'), \
                patch('managesf.model.yamlbkd.resources.group.'
                      'GroupOps.extra_validations') as xv:
            lrd.return_value = (master, new)
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
        with patch('managesf.model.yamlbkd.engine.'
                   'SFResourceBackendEngine._load_resources_data') as lrd, \
                patch('os.path.isdir'), \
                patch('os.mkdir'), \
                patch('managesf.model.yamlbkd.resources.group.'
                      'GroupOps.extra_validations') as xv:
            lrd.return_value = (master, new)
            xv.return_value = []
            eng = engine.SFResourceBackendEngine('fake', 'resources')
            valid, logs = eng.validate(None, None, None, None)
            self.assertTrue(valid)
            self.assertIn(
                'Resource [type: acls, ID: a1] is going to be created.',
                logs)

        master = {
            'resources': {
                'acls': {
                    'a1': {
                        'file': """[project]
    description = A description
[access "refs/*"]
    read = group Registered Users
    read = group Anonymous Users
""",
                        'groups': [],
                        }
                    },
                'groups': {},
                'projects': {},
                'repos': {
                    'r1': {
                        'acl': 'a1',
                    }
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
    read = deny group Registered Users
    read = deny group Anonymous Users
""",
                        'groups': [],
                        }
                    },
                'groups': {},
                'projects': {},
                'repos': {
                    'r1': {
                        'acl': 'a1',
                        }
                    }
                }
            }
        with patch('managesf.model.yamlbkd.engine.'
                   'SFResourceBackendEngine._load_resources_data') as lrd, \
                patch('os.path.isdir'), \
                patch('os.mkdir'), \
                patch('managesf.model.yamlbkd.resources.group.'
                      'GroupOps.extra_validations') as xv:
            lrd.return_value = (master, new)
            xv.return_value = []
            eng = engine.SFResourceBackendEngine('fake', 'resources')
            valid, logs = eng.validate(None, None, None, None)
            self.assertFalse(valid)
            self.assertIn(
                "['r1'] repositories use a private Gerrit ACL but are not "
                "defined as private in a project", logs)
            self.assertIn(
                'Resource [type: acls, ID: a1] extra validations failed', logs)

        new = {
            'resources': {
                'acls': {
                    'a1': {
                        'file': """[project]
    description = A description
    [access "refs/*"]
    read = deny group Registered Users
    read = deny group Anonymous Users
    """,
                        'groups': [],
                        }
                    },
                'groups': {},
                'projects': {
                    'p1': {
                        'description': 'desc',
                        'source-repositories': [
                            {'r1': {'private': True}},
                        ]
                    }
                },
                'repos': {
                    'r1': {
                        'acl': 'a1',
                        }
                    }
                }
            }
        with patch('managesf.model.yamlbkd.engine.'
                   'SFResourceBackendEngine._load_resources_data') as lrd, \
                patch('os.path.isdir'), \
                patch('os.mkdir'), \
                patch('managesf.model.yamlbkd.resources.group.'
                      'GroupOps.extra_validations') as xv:
            lrd.return_value = (master, new)
            xv.return_value = []
            eng = engine.SFResourceBackendEngine('fake', 'resources')
            valid, logs = eng.validate(None, None, None, None)
            self.assertTrue(valid)
            self.assertEqual(len(logs), 4)

        master = {
            'resources': {
                'acls': {
                    'public': {
                        'file': """[project]
    description = A description
[access "refs/*"]
    read = group Registered Users
    read = group Anonymous Users
""",
                        'groups': [],
                        },
                    'private': {
                        'file': """[project]
    description = A description
[access "refs/*"]
    read = deny group Registered Users
    read = deny group Anonymous Users
""",
                        'groups': [],
                        }
                    },
                'groups': {},
                'projects': {},
                'repos': {
                    'r1': {
                        'acl': 'public',
                    }
                }
            }
        }

        new = {
            'resources': {
                'acls': {
                    'public': {
                        'file': """[project]
    description = A description
[access "refs/*"]
    read = group Registered Users
    read = group Anonymous Users
""",
                        'groups': [],
                        },
                    'private': {
                        'file': """[project]
    description = A description
[access "refs/*"]
    read = deny group Registered Users
    read = deny group Anonymous Users
""",
                        'groups': [],
                        }
                    },
                'groups': {},
                'projects': {},
                'repos': {
                    'r1': {
                        'acl': 'private',
                    }
                }
            }
        }

        with patch('managesf.model.yamlbkd.engine.'
                   'SFResourceBackendEngine._load_resources_data') as lrd, \
                patch('os.path.isdir'), \
                patch('os.mkdir'), \
                patch('managesf.model.yamlbkd.resources.group.'
                      'GroupOps.extra_validations') as xv:
            lrd.return_value = (master, new)
            xv.return_value = []
            eng = engine.SFResourceBackendEngine('fake', 'resources')
            valid, logs = eng.validate(None, None, None, None)
            self.assertFalse(valid)
            self.assertIn(
                "r1 repository use a private Gerrit ACL but are not "
                "defined as private in a project", logs)
            self.assertIn(
                'Resource [type: repos, ID: r1] extra validations failed',
                logs)

        new = {
            'resources': {
                'acls': {
                    'public': {
                        'file': """[project]
    description = A description
[access "refs/*"]
    read = group Registered Users
    read = group Anonymous Users
""",
                        'groups': [],
                        },
                    'private': {
                        'file': """[project]
    description = A description
[access "refs/*"]
    read = deny group Registered Users
    read = deny group Anonymous Users
""",
                        'groups': [],
                        }
                    },
                'groups': {},
                'projects': {
                    'p1': {
                        'description': 'desc',
                        'source-repositories': [
                            {'r1': {'private': True}},
                        ]
                    }
                },
                'repos': {
                    'r1': {
                        'acl': 'private',
                    }
                }
            }
        }

        with patch('managesf.model.yamlbkd.engine.'
                   'SFResourceBackendEngine._load_resources_data') as lrd, \
                patch('os.path.isdir'), \
                patch('os.mkdir'), \
                patch('managesf.model.yamlbkd.resources.group.'
                      'GroupOps.extra_validations') as xv:
            lrd.return_value = (master, new)
            xv.return_value = []
            eng = engine.SFResourceBackendEngine('fake', 'resources')
            valid, logs = eng.validate(None, None, None, None)
            self.assertTrue(valid)

        master = {
            'resources': {
                'acls': {
                    'public': {
                        'file': """[project]
    description = A description
[access "refs/*"]
    read = group Registered Users
    read = group Anonymous Users
""",
                        'groups': [],
                        },
                    'private': {
                        'file': """[project]
    description = A description
[access "refs/*"]
    read = deny group Registered Users
    read = deny group Anonymous Users
""",
                        'groups': [],
                        }
                    },
                'groups': {},
                'projects': {},
                'repos': {
                    'r1': {
                        'acl': 'private',
                    }
                }
            }
        }

        new = {
            'resources': {
                'acls': {
                    'public': {
                        'file': """[project]
    description = A description
[access "refs/*"]
    read = group Registered Users
    read = group Anonymous Users
""",
                        'groups': [],
                        },
                    'private': {
                        'file': """[project]
    description = A description
[access "refs/*"]
    read = deny group Registered Users
    read = deny group Anonymous Users
""",
                        'groups': [],
                        }
                    },
                'groups': {},
                'projects': {
                    'p1': {
                        'description': 'desc',
                        'source-repositories': [
                            {'r1': {}}
                        ]
                    }
                },
                'repos': {
                    'r1': {
                        'acl': 'private',
                    }
                }
            }
        }

        with patch('managesf.model.yamlbkd.engine.'
                   'SFResourceBackendEngine._load_resources_data') as lrd, \
                patch('os.path.isdir'), \
                patch('os.mkdir'), \
                patch('managesf.model.yamlbkd.resources.group.'
                      'GroupOps.extra_validations') as xv:
            lrd.return_value = (master, new)
            xv.return_value = []
            eng = engine.SFResourceBackendEngine('fake', 'resources')
            valid, logs = eng.validate(None, None, None, None)
            self.assertFalse(valid)
            self.assertIn(
                "r1 repository use a private Gerrit ACL but are not "
                "defined as private in the project p1", logs)
            self.assertIn(
                'Resource [type: projects, ID: p1] extra validations failed',
                logs)

        new = {
            'resources': {
                'acls': {
                    'public': {
                        'file': """[project]
    description = A description
[access "refs/*"]
    read = group Registered Users
    read = group Anonymous Users
""",
                        'groups': [],
                        },
                    'private': {
                        'file': """[project]
    description = A description
[access "refs/*"]
    read = deny group Registered Users
    read = deny group Anonymous Users
""",
                        'groups': [],
                        }
                    },
                'groups': {},
                'projects': {
                    'p1': {
                        'description': 'desc',
                        'source-repositories': [
                            {'r1': {'private': True}}
                        ]
                    }
                },
                'repos': {
                    'r1': {
                        'acl': 'private',
                    }
                }
            }
        }

        with patch('managesf.model.yamlbkd.engine.'
                   'SFResourceBackendEngine._load_resources_data') as lrd, \
                patch('os.path.isdir'), \
                patch('os.mkdir'), \
                patch('managesf.model.yamlbkd.resources.group.'
                      'GroupOps.extra_validations') as xv:
            lrd.return_value = (master, new)
            xv.return_value = []
            eng = engine.SFResourceBackendEngine('fake', 'resources')
            valid, logs = eng.validate(None, None, None, None)
            self.assertTrue(valid)

    def test_gitrepo_validation(self):
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
        with patch('managesf.model.yamlbkd.engine.'
                   'SFResourceBackendEngine._load_resources_data') as lrd, \
                patch('os.path.isdir'), \
                patch('os.mkdir'), \
                patch('managesf.model.yamlbkd.resources.gitacls.'
                      'ACLOps.extra_validations') as xv:
            lrd.return_value = (master, new)
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

        with patch('managesf.model.yamlbkd.engine.'
                   'SFResourceBackendEngine._load_resources_data') as lrd, \
                patch('os.path.isdir'), \
                patch('os.mkdir'), \
                patch('managesf.model.yamlbkd.resources.gitacls.'
                      'ACLOps.extra_validations') as xv:
            lrd.return_value = (master, new)
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
        with patch('managesf.model.yamlbkd.engine.'
                   'SFResourceBackendEngine._load_resources_data') as lrd, \
                patch('os.path.isdir'), \
                patch('os.mkdir'), \
                patch('managesf.model.yamlbkd.resources.gitacls.'
                      'ACLOps.extra_validations') as xv:
            lrd.return_value = (master, new)
            xv.return_value = []
            eng = engine.SFResourceBackendEngine('fake', 'resources')
            # GIT repository relie on an unknown ACL
            valid, logs = eng.validate(None, None, None, None)
            self.assertFalse(valid)
            self.assertIn('Resource [type: repos, ID: sf/r1] depends on '
                          'an unknown resource [type: acls, ID: a1]', logs)
            self.assertEqual(len(logs), 1)

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
                        'acl': 'a1',
                        'branches': {
                            'br1': 'aa65de9c3eb5496e3119a73f732ebb142753ed54'
                            }
                        }
                    },
                'acls': {
                    'a1': {
                        'file': 'fake',
                        }
                    }
                }
            }
        with patch('managesf.model.yamlbkd.engine.'
                   'SFResourceBackendEngine._load_resources_data') as lrd, \
                patch('os.path.isdir'), \
                patch('os.mkdir'), \
                patch('managesf.model.yamlbkd.resources.gitacls.'
                      'ACLOps.extra_validations') as xv:
            lrd.return_value = (master, new)
            xv.return_value = []
            eng = engine.SFResourceBackendEngine('fake', 'resources')
            valid, logs = eng.validate(None, None, None, None)
            self.assertTrue(valid)
            self.assertIn('Resource [type: repos, ID: sf/r1] is going to '
                          'be created.',
                          logs)
            self.assertEqual(len(logs), 1)

    def test_project_validation(self):
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
                        'tenant': 'local',
                        'connection': 'github.com',
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

        with patch('managesf.model.yamlbkd.engine.'
                   'SFResourceBackendEngine._load_resources_data') as lrd, \
                patch('os.path.isdir'), \
                patch('os.mkdir'), \
                patch('managesf.model.yamlbkd.resources.gitacls.'
                      'ACLOps.extra_validations') as xv, \
                patch('managesf.model.yamlbkd.resources.group.'
                      'GroupOps.extra_validations') as xv2:
            lrd.return_value = (master, new)
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
        with patch('managesf.model.yamlbkd.engine.'
                   'SFResourceBackendEngine._load_resources_data') as lrd, \
                patch('os.path.isdir'), \
                patch('os.mkdir'), \
                patch('managesf.model.yamlbkd.resources.gitacls.'
                      'ACLOps.extra_validations') as xv, \
                patch('managesf.model.yamlbkd.resources.group.'
                      'GroupOps.extra_validations') as xv2:
            lrd.return_value = (master, new)
            xv.return_value = []
            eng = engine.SFResourceBackendEngine('fake', 'resources')
            valid, logs = eng.validate(None, None, None, None)
            # Project depends on an unknown r2 resource but soft deps is
            # set to True for project type so no deps check is performed
            # between projects and repos.
            self.assertTrue(valid)

        master = {
            'resources': {
                'projects': {},
                }
            }

        new = {
            'resources': {
                'projects': {
                    'p1': {
                        'name': 'p1',
                        'description': 'An awesome project',
                        'options': [
                            'repoxplorer/skip',
                        ],
                        'source-repositories': [
                            {'config': {
                                'zuul/config-project': True
                            }},
                            'sf-jobs',
                            'zuul-jobs',
                        ],
                    }
                }
            }
        }

        with patch('managesf.model.yamlbkd.engine.'
                   'SFResourceBackendEngine._load_resources_data') as lrd, \
                patch('os.path.isdir'), \
                patch('os.mkdir'), \
                patch('managesf.model.yamlbkd.resources.gitacls.'
                      'ACLOps.extra_validations') as xv, \
                patch('managesf.model.yamlbkd.resources.group.'
                      'GroupOps.extra_validations') as xv2:
            lrd.return_value = (master, new)
            xv.return_value = []
            eng = engine.SFResourceBackendEngine('fake', 'resources')
            valid, logs = eng.validate(None, None, None, None)
            self.assertTrue(valid)
            self.assertIn('Resource [type: projects, ID: p1] is going to '
                          'be created.', logs)

        master = {
            'resources': {
                'projects': {
                    'p1': {
                        'name': 'p1',
                        'description': 'An awesome project',
                        'source-repositories': [
                            {'config': {
                                'zuul/config-project': True
                            }},
                            'sf-jobs',
                            'zuul-jobs',
                        ],
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
                        'source-repositories': [
                            {'config2': {
                                'zuul/config-project': True
                            }},
                            'sf-jobs',
                            'zuul-jobs',
                        ],
                    }
                }
            }
        }

        with patch('managesf.model.yamlbkd.engine.'
                   'SFResourceBackendEngine._load_resources_data') as lrd, \
                patch('os.path.isdir'), \
                patch('os.mkdir'), \
                patch('managesf.model.yamlbkd.resources.gitacls.'
                      'ACLOps.extra_validations') as xv, \
                patch('managesf.model.yamlbkd.resources.group.'
                      'GroupOps.extra_validations') as xv2:
            lrd.return_value = (master, new)
            xv.return_value = []
            eng = engine.SFResourceBackendEngine('fake', 'resources')
            valid, logs = eng.validate(None, None, None, None)
            self.assertTrue(valid)
            self.assertIn('Resource [type: projects, ID: p1] is going to '
                          'be updated.', logs)

        new = {
            'resources': {
                'projects': {
                    'p1': {
                        'name': 'p1',
                        'description': 'An awesome project',
                        'source-repositories': [
                            {'config': {
                                'zuul/config-project': True,
                                'default-branch': ['devel', 'stable-2.4'],
                            }},
                            'sf-jobs',
                            'zuul-jobs',
                        ],
                    }
                }
            }
        }

        with patch('managesf.model.yamlbkd.engine.'
                   'SFResourceBackendEngine._load_resources_data') as lrd, \
                patch('os.path.isdir'), \
                patch('os.mkdir'), \
                patch('managesf.model.yamlbkd.resources.gitacls.'
                      'ACLOps.extra_validations') as xv, \
                patch('managesf.model.yamlbkd.resources.group.'
                      'GroupOps.extra_validations') as xv2:
            lrd.return_value = (master, new)
            xv.return_value = []
            eng = engine.SFResourceBackendEngine('fake', 'resources')
            valid, logs = eng.validate(None, None, None, None)
            self.assertTrue(valid)
            self.assertIn('Resource [type: projects, ID: p1] is going to '
                          'be updated.', logs)

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
        with patch('managesf.model.yamlbkd.engine.'
                   'SFResourceBackendEngine._load_resources_data') as lrd, \
                patch('os.path.isdir'), \
                patch('os.mkdir'), \
                patch('managesf.model.yamlbkd.resources.gitacls.'
                      'ACLOps.extra_validations') as xv, \
                patch('managesf.model.yamlbkd.resources.group.'
                      'GroupOps.extra_validations') as xv2:
            lrd.return_value = (master, new)
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

    def test_tenant_validation(self):
        master = {
            'resources': {
                'tenants': {}
            }
        }
        new = {
            'resources': {
                'tenants': {
                    'kimchi': {
                        'url': 'https://kimchi.sftests.com/manage',
                        'tenant-options': {
                            'zuul/default-jobs-timeout': 3600,
                            'zuul/exclude-unprotected-branches': True,
                            'zuul/default-parent': 'myparent',
                            }
                        },
                    'natto': {
                        'url': 'https://natto.sftests.com/manage',
                        'description': 'The natto tenant',
                        'default-connection': 'gerrit',
                        'allowed-triggers': ['gerrit1', 'gerrit2'],
                        'allowed-reporters': ['review.openstack.org'],
                        },
                    }
                }
            }

        with patch('managesf.model.yamlbkd.engine.'
                   'SFResourceBackendEngine._load_resources_data') as lrd, \
                patch('os.path.isdir'), \
                patch('os.mkdir'):
            lrd.return_value = (master, new)
            eng = engine.SFResourceBackendEngine('fake', 'resources')
            valid, logs = eng.validate(None, None, None, None)
            self.assertTrue(valid)
            self.assertIn('Resource [type: tenants, ID: kimchi] is going to '
                          'be created.', logs)
            self.assertIn('Resource [type: tenants, ID: natto] is going to '
                          'be created.', logs)
            self.assertEqual(len(logs), 2)

    def test_connection_validation(self):
        master = {
            'resources': {
                'connections': {
                    'local': {
                        'base-url': 'https://sftests.com/r/',
                        'type': 'gerrit',
                        },
                    }
            }
        }
        new = {
            'resources': {
                'connections': {
                    'local': {
                        'base-url': 'https://sftests.com/r/',
                        'type': 'gerrit',
                        },
                    'github.com': {
                        'github-app-name': 'softwarefactory-project-zuul',
                        'github-label': 'zuulit',
                        'type': 'github'
                        },
                    }
                }
            }

        with patch('managesf.model.yamlbkd.engine.'
                   'SFResourceBackendEngine._load_resources_data') as lrd, \
                patch('os.path.isdir'), \
                patch('os.mkdir'):
            lrd.return_value = (master, new)
            eng = engine.SFResourceBackendEngine('fake', 'resources')
            valid, logs = eng.validate(None, None, None, None)
            self.assertFalse(valid)
            self.assertIn("Connections can't be updated manually, they are "
                          "managed by configuration management.", logs)
            self.assertEqual(len(logs), 2)

    def test_get_missing_resources(self):
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
        with patch('managesf.model.yamlbkd.engine.'
                   'SFResourceBackendEngine.get') as g, \
                patch('managesf.model.yamlbkd.resources.gitrepository.'
                      'GitRepositoryOps.get_all') as gar, \
                patch('managesf.model.yamlbkd.resources.group.'
                      'GroupOps.get_all') as gag:
            gar.return_value = ([], gr_reality)
            gag.return_value = ([], g_reality)
            g.return_value = current_resources
            logs, tree = eng.get_missing_resources(None, None)
            self.assertListEqual(logs, [])
            self.assertDictEqual(tree, expected)

    def test_resources_project_get(self):
        master = {
            'resources': {
                'projects': {
                    'p1': {
                        'name': 'p1',
                        'description': 'An awesome project',
                        'source-repositories': [
                            'r1',
                            {'r2': {
                                'zuul/config-project': True,
                                'default-branch': 'main'
                            }}
                        ],
                    },
                }
            }
        }

        with patch('managesf.model.yamlbkd.engine.YAMLBackend.'
                   'get_data') as gd, \
                patch('managesf.model.yamlbkd.engine.YAMLBackend.refresh'), \
                patch('os.path.isdir'), \
                patch('os.mkdir'):
            gd.return_value = master
            eng = engine.SFResourceBackendEngine('fake', 'resources')
            data = eng.get(None, None)
            expected = {
                'config-repo': None,
                'public-url': 'http://sftests.com/manage',
                'resources': {
                    'projects': {
                        'p1': {
                            'source-repositories': [
                                {'r1': {}},
                                {'r2': {'zuul/config-project': True,
                                        'default-branch': 'main'}}
                            ],
                            'description': 'An awesome project',
                            'name': 'p1'}
                        }
                    }
                }
            self.assertDictEqual(data, expected)
