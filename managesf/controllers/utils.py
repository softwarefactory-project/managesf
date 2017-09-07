#
# Copyright (C) 2014 eNovance SAS <licensing@enovance.com>
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

from subprocess import Popen, PIPE
from pwd import getpwnam
from grp import getgrnam
import os
import logging
import time

logger = logging.getLogger(__name__)


def chown(path, user, group):
    uid = getpwnam(group).pw_uid
    gid = getgrnam(user).gr_gid
    os.chown(path, uid, gid)


def timeit(method):
    def timed(*args, **kw):
        ts = time.time()
        logger.debug('calling %r' % method.__name__)
        result = method(*args, **kw)
        te = time.time()
        logger.debug('%r ran in %2.2f sec' % (method.__name__, te-ts))
        return result
    return timed


class RemoteUser(object):
    def __init__(self, user, host, sshkey_path=None):
        self.opt = ['-o', 'LogLevel=ERROR', '-o', 'StrictHostKeyChecking=no',
                    '-o', 'UserKnownHostsFile=/dev/null']
        if sshkey_path:
            self.opt = self.opt + ['-i', sshkey_path]
        self.host = '%s@%s' % (user, host)

    def _exe(self, cmd):
        logger.debug(cmd)
        p = Popen(cmd, stdout=PIPE, stderr=PIPE)
        stdout, stderr = p.communicate()
        logger.debug("Stdout:\n%s\n\nStderr:\n%s\n" % (stdout, stderr))
        p.wait()
        return p

    def _ssh(self, cmd):
        cmd = ['ssh'] + self.opt + [self.host] + cmd.split()
        return self._exe(cmd)

    def _scpFromRemote(self, src, dest):
        src = '%s:%s' % (self.host, src)
        cmd = ['scp'] + self.opt + [src, dest]
        return self._exe(cmd)

    def _scpToRemote(self, src, dest):
        dest = '%s:%s' % (self.host, dest)
        cmd = ['scp'] + self.opt + [src, dest]
        return self._exe(cmd)
