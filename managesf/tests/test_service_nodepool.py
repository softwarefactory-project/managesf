#!/usr/bin/env python
#
# Copyright (C) 2016  Red Hat <licensing@enovance.com>
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


import os
import time
from StringIO import StringIO
from unittest import TestCase
from mock import patch, ANY

from managesf.services import nodepool
from managesf.tests import dummy_conf


NODE_GET_STDOUT = "| 102639 | rcip-dev | None | sfstack-centos-7 | default | None | sfstack-centos-7-rcip-dev-102639 | sfstack-centos-7-rcip-dev-102639 | a | X.Y.133.23  | ready | 00:02:06:33 |\n"  # noqa
NODE_GET_STDOUT += "| 101764 | rcip-dev | None | sfstack-mitaka-centos-7 | default | None | sfstack-mitaka-centos-7-rcip-dev-101764 | sfstack-mitaka-centos-7-rcip-dev-101764 | b | X.Y.133.96  | ready | 01:23:31:58 |\n"  # noqa
NODE_GET_STDOUT += "| 99242  | rcip-dev | None | skydive-centos-7 | default | None    | skydive-centos-7-rcip-dev-99242 | skydive-centos-7-rcip-dev-99242 | c | X.Y.133.123 | ready | 06:19:50:29 |"  # noqa


IMAGE_GET_STDOUT = "| 127  | rcip-dev | opencontainer-centos-7     | template-opencontainer-centos-7-1464273347     | 1464273347 | 155327c2-8266-4f09-b886-0cf354758507 | b5d74632-b3f0-4399-b597-7f5d0cb324bd | ready  | 209:03:29:43 |\n"  # noqa
IMAGE_GET_STDOUT += "| 526  | rcip-dev | rdo-liberty-centos-7       | template-rdo-liberty-centos-7-1464315248       | 1464315248 | da231bfb-c03b-4587-a65d-32119b1b2598 | 6fef1ed3-ff39-4253-8d12-119866f0fc71 | ready  | 208:15:40:06 |\n"  # noqa
IMAGE_GET_STDOUT += "| 639  | rcip-prod | rdo-liberty-centos-7       | template-rdo-liberty-centos-7-1465265646       | 1465265646 | b8735f89-0ef7-4454-a0ce-f3b7765d5bb0 | ca69cb63-15d7-452f-834c-e9674b6f3e87 | ready  | 197:15:38:49 |\n"  # noqa
IMAGE_GET_STDOUT += "| 2383 | rcip-prod | sfstack-centos-7           | template-sfstack-centos-7-1482113654           | 1482113654 | ff9a8340-1503-49d4-b0b4-dfa853d9270d | 090e4e5b-a04f-4546-a9c9-f1e6f74ed141 | ready  | 02:15:46:01  |"  # noqa

DIB_IMAGE_GET_STDOUT = "| 526 | rdo-liberty-centos-7 | /tmp/im1 | 24 | ready | 208:15:40:06 |\n" # noqa
DIB_IMAGE_GET_STDOUT += "| 3 | rdo-liberty-centos-7 | /tmp/im3 | 342 | building | 0:00:05:00 |\n" # noqa
DIB_IMAGE_GET_STDOUT += "| 16 | sfstack-centos-7 | /tmp/im4 | 542 | ready | 10:13:05:21 |" # noqa

class Fakechannel:
    def __init__(self, code, exec_time=2):
        self.code = code
        self.start_time = time.time()
        self.exec_time = exec_time

    def recv_exit_status(self):
        return self.code

    # simulate execution time
    def exit_status_ready(self):
        if time.time() - self.start_time > self.exec_time:
            return True
        return False


class Stdout(StringIO):
    def __init__(self, contents, exit_code=0):
        StringIO.__init__(self, contents)
        self.channel = Fakechannel(exit_code)


class BaseSFNodepoolService(TestCase):
    @classmethod
    def setupClass(cls):
        cls.conf = dummy_conf()
        cls.nodepool = nodepool.SoftwareFactoryNodepool(cls.conf)
        nodepool.image.model.conf = cls.conf

    def setUp(self):
        nodepool.image.model.init_model()

    def tearDown(self):
        os.unlink(self.conf.sqlalchemy['url'][len('sqlite:///'):])


class TestSFNodepoolManager(BaseSFNodepoolService):

    @patch('managesf.services.nodepool.paramiko')
    def test_get_client(self, paramiko):
        with self.nodepool.get_client() as client:
            client.do_something('dummy command')
            k = self.conf.nodepool['key']
            paramiko.RSAKey.from_private_key_file.assert_called_with(k)
            paramiko.SSHClient().connect.assert_called_with(
                hostname=self.conf.nodepool['host'],
                username=self.conf.nodepool['user'],
                pkey=ANY)

    @patch('managesf.services.nodepool.paramiko')
    def test_node_get(self, paramiko):
        self.assertRaisesRegexp(Exception, "invalid node id 'WRYYY'",
                                self.nodepool.node.get, "WRYYY")
        stdout = NODE_GET_STDOUT
        stderr = ''
        paramiko.SSHClient().exec_command.return_value = (StringIO(''),
                                                          Stdout(stdout),
                                                          StringIO(stderr))
        nodes = self.nodepool.node.get()
        self.assertEqual(len(NODE_GET_STDOUT.split('\n')), len(nodes), nodes)
        paramiko.SSHClient().exec_command.return_value = (StringIO(''),
                                                          Stdout(stdout),
                                                          StringIO(stderr))
        nodes = self.nodepool.node.get(node_id=101764)
        self.assertEqual(1, len(nodes), nodes)
        node = nodes[0]
        self.assertEqual("sfstack-mitaka-centos-7", node['label'], node)
        self.assertEqual("X.Y.133.96", node['ip'], node)
        self.assertEqual(171118, node['age'], node)
        paramiko.SSHClient().exec_command.return_value = (StringIO(''),
                                                          Stdout(stdout),
                                                          StringIO(stderr))
        nodes = self.nodepool.node.get(node_id=123453)
        self.assertEqual(0, len(nodes), nodes)
        stderr = 'Computer says no'
        paramiko.SSHClient().exec_command.return_value = (StringIO(''),
                                                          Stdout(stdout, 3),
                                                          StringIO(stderr))
        self.assertRaisesRegexp(Exception, stderr,
                                self.nodepool.node.get)
        self.assertRaisesRegexp(Exception, "3",
                                self.nodepool.node.get)

    @patch('managesf.services.nodepool.paramiko')
    def test_node_hold(self, paramiko):
        self.assertRaisesRegexp(Exception, "invalid node id 'WRYYY'",
                                self.nodepool.node.hold, "WRYYY")
        stdout = ''
        stderr = ''
        paramiko.SSHClient().exec_command.return_value = (StringIO(''),
                                                          Stdout(stdout),
                                                          StringIO(stderr))
        self.nodepool.node.hold(4)
        paramiko.SSHClient().exec_command.assert_called_with("nodepool hold 4")
        stderr = 'Computer says no'
        paramiko.SSHClient().exec_command.return_value = (StringIO(''),
                                                          Stdout(stdout, 5),
                                                          StringIO(stderr))
        self.assertRaisesRegexp(Exception, stderr,
                                self.nodepool.node.hold, 66)
        self.assertRaisesRegexp(Exception, "5",
                                self.nodepool.node.hold, 66)

    @patch('managesf.services.nodepool.paramiko')
    def test_node_delete(self, paramiko):
        self.assertRaisesRegexp(Exception, "invalid node id 'WRYYY'",
                                self.nodepool.node.hold, "WRYYY")
        stdout = ''
        stderr = ''
        paramiko.SSHClient().exec_command.return_value = (StringIO(''),
                                                          Stdout(stdout),
                                                          StringIO(stderr))
        self.nodepool.node.delete(4)
        c = "nodepool delete 4"
        paramiko.SSHClient().exec_command.assert_called_with(c)
        stderr = 'Computer says no'
        paramiko.SSHClient().exec_command.return_value = (StringIO(''),
                                                          Stdout(stdout, 17),
                                                          StringIO(stderr))
        self.assertRaisesRegexp(Exception, stderr,
                                self.nodepool.node.delete, 55)
        self.assertRaisesRegexp(Exception, "17",
                                self.nodepool.node.delete, 66)

    @patch('managesf.services.nodepool.paramiko')
    def test_node_add_authorized_key(self, paramiko):
        k = "ssh-rsa blahblahblah iggy@fool"
        self.assertRaisesRegexp(Exception, "invalid node id 'WRYYY'",
                                self.nodepool.node.add_authorized_key,
                                "WRYYY", k)
        self.assertRaisesRegexp(Exception, "invalid user .+",
                                self.nodepool.node.add_authorized_key,
                                2, k, user="-v; rm -rf /; ssh user")
        stdout = ''
        stderr = ''
        paramiko.SSHClient().exec_command.return_value = (StringIO(''),
                                                          Stdout(stdout),
                                                          StringIO(stderr))
        with patch.object(self.nodepool.node, 'get') as g:
            g.return_value = [{'ip': 'a.b.c.d'}, ]
            self.nodepool.node.add_authorized_key(4, k)
            c = ('echo "%(key)s" | ssh -o StrictHostKeyChecking=no '
                 '-i /var/lib/jenkins/.ssh/id_rsa %(user)s@%(ip)s'
                 ' "cat >> ~/.ssh/authorized_keys"')
            cmd = c % {'key': k, 'user': 'jenkins', 'ip': 'a.b.c.d'}
            paramiko.SSHClient().exec_command.assert_called_with(cmd)
            stderr = 'Computer says no'
            stdvalues = (StringIO(''),
                         Stdout(stdout, 34),
                         StringIO(stderr))
            paramiko.SSHClient().exec_command.return_value = stdvalues
            self.assertRaisesRegexp(Exception, stderr,
                                    self.nodepool.node.add_authorized_key,
                                    2, k)
            self.assertRaisesRegexp(Exception, "34",
                                    self.nodepool.node.add_authorized_key,
                                    2, k)
            g.return_value = []
            self.assertRaisesRegexp(Exception, "Node 2 not found",
                                    self.nodepool.node.add_authorized_key,
                                    2, k)

    @patch('managesf.services.nodepool.paramiko')
    def test_image_get(self, paramiko):
        stdout = IMAGE_GET_STDOUT
        stderr = ''
        paramiko.SSHClient().exec_command.return_value = (StringIO(''),
                                                          Stdout(stdout),
                                                          StringIO(stderr))
        images = self.nodepool.image.get()
        self.assertEqual(len(IMAGE_GET_STDOUT.split('\n')), len(images),
                         images)
        paramiko.SSHClient().exec_command.return_value = (StringIO(''),
                                                          Stdout(stdout),
                                                          StringIO(stderr))
        images = self.nodepool.image.get(image_name="rdo-liberty-centos-7")
        self.assertEqual(2, len(images), images)
        paramiko.SSHClient().exec_command.return_value = (StringIO(''),
                                                          Stdout(stdout),
                                                          StringIO(stderr))
        images = self.nodepool.image.get(provider_name="rcip-dev")
        self.assertEqual(2, len(images), images)
        paramiko.SSHClient().exec_command.return_value = (StringIO(''),
                                                          Stdout(stdout),
                                                          StringIO(stderr))
        images = self.nodepool.image.get(image_name="rdo-liberty-centos-7",
                                         provider_name="rcip-dev")
        self.assertEqual(1, len(images), images)
        image = images[0]
        self.assertEqual("ready", image['state'], image)
        self.assertEqual("526", image['id'], image)
        self.assertEqual(18027606, image['age'], image)
        paramiko.SSHClient().exec_command.return_value = (StringIO(''),
                                                          Stdout(stdout),
                                                          StringIO(stderr))
        images = self.nodepool.image.get(image_name="rdo-liberty-centos-8",
                                         provider_name="rcip-dev")
        self.assertEqual(0, len(images), images)
        stderr = 'Computer says no'
        paramiko.SSHClient().exec_command.return_value = (StringIO(''),
                                                          Stdout(stdout, 99),
                                                          StringIO(stderr))
        self.assertRaisesRegexp(Exception, stderr,
                                self.nodepool.image.get)
        self.assertRaisesRegexp(Exception, "99",
                                self.nodepool.image.get)

    @patch('managesf.services.nodepool.paramiko')
    def test_dib_image_get(self, paramiko):
        stdout = DIB_IMAGE_GET_STDOUT
        stderr = ''
        paramiko.SSHClient().exec_command.return_value = (StringIO(''),
                                                          Stdout(stdout),
                                                          StringIO(stderr))
        images = self.nodepool.dib_image.get()
        self.assertEqual(len(DIB_IMAGE_GET_STDOUT.split('\n')), len(images),
                         images)
        paramiko.SSHClient().exec_command.return_value = (StringIO(''),
                                                          Stdout(stdout),
                                                          StringIO(stderr))
        images = self.nodepool.dib_image.get(image_name="rdo-liberty-centos-7")
        self.assertEqual(2, len(images), images)
        image = images[0]
        self.assertEqual("ready", image['state'], image)
        self.assertEqual("526", image['id'], image)
        self.assertEqual(18027606, image['age'], image)
        paramiko.SSHClient().exec_command.return_value = (StringIO(''),
                                                          Stdout(stdout),
                                                          StringIO(stderr))
        images = self.nodepool.dib_image.get(image_name="rdo-liberty-centos-8")
        self.assertEqual(0, len(images), images)
        stderr = 'Computer says no'
        paramiko.SSHClient().exec_command.return_value = (StringIO(''),
                                                          Stdout(stdout, 99),
                                                          StringIO(stderr))
        self.assertRaisesRegexp(Exception, stderr,
                                self.nodepool.dib_image.get)
        self.assertRaisesRegexp(Exception, "99",
                                self.nodepool.dib_image.get)

    @patch('managesf.services.nodepool.paramiko')
    def test_image_update(self, paramiko):
        self.assertRaisesRegexp(Exception, "invalid provider",
                                self.nodepool.image.start_update,
                                provider_name="-h; rm -rf /; echo ",
                                image_name="PWNED")
        self.assertRaisesRegexp(Exception, "invalid provider",
                                self.nodepool.image.start_update,
                                image_name="-h; rm -rf /; echo ",
                                provider_name="PWNED")

        # Simple workflow
        stdout = Stdout(u'rebuilding image')
        stdout.channel.exec_time = 0
        stderr = u''
        process = (StringIO(''),
                   stdout,
                   StringIO(stderr))
        paramiko.SSHClient().exec_command.return_value = process
        u = self.nodepool.image.start_update('provider', 'image')
        m = ('nodepool image-update provider image')
        paramiko.SSHClient().exec_command.assert_called_with(m, get_pty=True)
        self.assertTrue(isinstance(u, int), type(u))
        self.assertTrue(u in nodepool.image.UPDATES_CACHE)
        v = self.nodepool.image.get_update_info(u)
        self.assertEqual(u, v['id'])
        self.assertEqual(0, int(v['exit_code']))
        self.assertEqual('SUCCESS', v['status'])
        self.assertEqual('rebuilding image', v['output'])
        self.assertEqual(stderr, v['error'])
        # cache should have been updated
        self.assertTrue(u not in nodepool.image.UPDATES_CACHE)

        # Long operation
        stdout = Stdout(u'rebuilding image another time')
        stdout.channel.exec_time = 10000
        process = (StringIO(''),
                   stdout,
                   StringIO(stderr))
        paramiko.SSHClient().exec_command.return_value = process
        u = self.nodepool.image.start_update('provider', 'image')
        v = self.nodepool.image.get_update_info(u)
        self.assertEqual(u, v['id'])
        self.assertEqual('IN_PROGRESS', v['status'])
        # still cached, until completion
        self.assertTrue(u in nodepool.image.UPDATES_CACHE)
        # finish the build
        stdout.channel.exec_time = 0
        v = self.nodepool.image.get_update_info(u)
        self.assertEqual(u, v['id'])
        self.assertEqual(0, int(v['exit_code']))
        self.assertEqual('SUCCESS', v['status'])
        self.assertEqual('rebuilding image another time', v['output'])
        # cache should have been updated
        self.assertTrue(u not in nodepool.image.UPDATES_CACHE)

        # Error during image update
        stdout = Stdout(u'Uh oh!', exit_code=128)
        stdout.channel.exec_time = 0
        stderr = u'A very helpful error message'
        process = (StringIO(''),
                   stdout,
                   StringIO(stderr))
        paramiko.SSHClient().exec_command.return_value = process
        u = self.nodepool.image.start_update('provider', 'image')
        v = self.nodepool.image.get_update_info(u)
        self.assertEqual(u, v['id'])
        self.assertEqual('FAILURE', v['status'])
        self.assertEqual(stderr, v['error'])
        self.assertEqual(128, int(v['exit_code']))

    @patch('managesf.services.nodepool.paramiko')
    def test_dib_image_update(self, paramiko):
        self.assertRaisesRegexp(Exception, "invalid provider",
                                self.nodepool.dib_image.start_update,
                                provider_name="-h; rm -rf /; echo ",
                                image_name="PWNED")
        self.assertRaisesRegexp(Exception, "invalid provider",
                                self.nodepool.dib_image.start_update,
                                image_name="-h; rm -rf /; echo ",
                                provider_name="PWNED")

        # Simple workflow
        u_stdout = Stdout(u'uploading image')
        u_stdout.channel.exec_time = 0
        stderr = u''
        upload_process = (StringIO(''),
                          u_stdout,
                          StringIO(stderr))
        paramiko.SSHClient().exec_command.return_value = upload_process
        u = self.nodepool.dib_image.start_update('provider', 'image')
        m = ('nodepool image-build image')
        paramiko.SSHClient().exec_command.assert_any_call(m, get_pty=True)
        self.assertTrue(isinstance(u, int), type(u))
        self.assertTrue(u in nodepool.image.UPDATES_CACHE)
        v = self.nodepool.dib_image.get_update_info(u)
        self.assertEqual(u, v['id'])
        self.assertEqual(0, int(v['exit_code']))
        self.assertEqual('SUCCESS', v['status'])
        self.assertEqual('uploading image', v['output'])
        self.assertEqual(stderr, v['error'])
        # cache should have been updated
        self.assertTrue(u not in nodepool.image.UPDATES_CACHE)

        # Error during image update
        stdout = Stdout(u'Uh oh!', exit_code=128)
        stdout.channel.exec_time = 0
        stderr = u'A very helpful error message'
        process = (StringIO(''),
                   stdout,
                   StringIO(stderr))
        paramiko.SSHClient().exec_command.return_value = process
        u = self.nodepool.dib_image.start_update('provider', 'image')
        v = self.nodepool.dib_image.get_update_info(u)
        self.assertEqual(u, v['id'])
        self.assertEqual('FAILURE', v['status'])
        self.assertEqual(stderr, v['error'])
        self.assertEqual(128, int(v['exit_code']))
