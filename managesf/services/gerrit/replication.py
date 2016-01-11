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


import logging
import subprocess

from gerritlib import gerrit as G

from managesf.services import base
# from managesf.services import exceptions as exc


logger = logging.getLogger(__name__)


class SFGerritReplicationManager(base.ReplicationManager):
    def _replication_ssh_run_cmd(self, subcmd, shell=False):
        host = '%s@%s' % (self.plugin.conf['user'],
                          self.plugin.conf['host'])
        sshcmd = ['ssh', '-o', 'LogLevel=ERROR',
                  '-o', 'StrictHostKeyChecking=no',
                  '-o', 'UserKnownHostsFile=/dev/null', '-i',
                  self.plugin._full_conf.gerrit['sshkey_priv_path'], host]
        cmd = sshcmd + subcmd

        if shell:
            cmd = " ".join(cmd)
        p1 = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, shell=shell)
        out, err = p1.communicate()
        return out, err, p1.returncode

    def _replication_read_config(self):
        lines = []
        cmd = ['git', 'config', '-f',
               self.plugin._full_conf.gerrit['replication_config_path'], '-l']
        out, err, code = self._replication_ssh_run_cmd(cmd)
        if code:
            msg = "[%s] Reading config file err %s"
            logger.info(msg % (self.plugin.service_name,
                               err))
            logger.info("[%s] --[\n%s\n]--" % out)
            raise Exception(msg % (self.plugin.service_name,
                                   err))
        elif out:
            msg = "[%s] Contents of replication config file: \n%s "
            logger.info(msg % (self.plugin.service_name, out))
            out = out.strip()
            lines = out.split("\n")
        config = {}
        for line in lines:
            setting, value = line.split("=")
            section = setting.split(".")[1]
            setting = setting.split(".")[2]
            if setting == 'projects':
                msg = "[%s] Invalid Replication config file."
                if (len(value.split()) != 1):
                    logger.info(msg % self.plugin.service_name)
                    raise Exception(msg % self.plugin.service_name)
                elif section in config and 'projects' in config[section]:
                    logger.info(msg % self.plugin.service_name)
                    raise Exception(msg % self.plugin.service_name)
            if section not in config.keys():
                config[section] = {}
            config[section].setdefault(setting, []).append(value)
        msg = "[%s] Contents of the config file - %s"
        logger.info(msg % (self.plugin.service_name,
                           str(config)))
        return config

    def _replication_validate(self, projects, config,
                              section=None, setting=None):
        settings = ['push', 'projects', 'url', 'receivepack', 'uploadpack',
                    'timeout', 'replicationDelay', 'threads']
        if setting and (setting not in settings):
            msg = "[%s] Setting %s is not supported. Supported settings: %s"
            logger.info(msg % (self.plugin.service_name,
                               setting,
                               " , ".join(settings)))
            raise Exception(msg % (self.plugin.service_name,
                                   setting,
                                   " , ".join(settings)))
        if len(projects) == 0:
            msg = "[%s] User doesn't own any project"
            logger.info(msg % self.plugin.service_name)
            raise Exception(msg % self.plugin.service_name)
        if section and (section in config):
            for project in config[section].get('projects', []):
                if project not in projects:
                    msg = "[%s] User not allowed on section %s"
                    logger.info(msg % (self.plugin.service_name,
                                       section))
                    raise Exception(msg % (self.plugin.service_name,
                                           section))

    def get_config(self, user, section=None, setting=None):
        projects = self.plugin.project.get(user=user)
        config = self._replication_read_config()
        self._replication_validate(projects, config, section, setting)
        userConfig = {}

        # First, filter out any project the user has no access to
        for _section in config:
            for project in config[_section].get('projects', []):
                if project in projects:
                    userConfig[_section] = config[_section]

        # Limit response to section if set
        if section:
            userConfig = userConfig.get(section, {})

        # Limit response to setting if set
        if setting:
            userConfig = userConfig.get(setting, {})
        msg = "[%s] replication config for user: %s"
        logger.info(msg % (self.plugin.service_name, str(userConfig)))
        if userConfig:
            return userConfig

    def _replication_fill_knownhosts(self, url):
        try:
            host = url.split(':')[0]
            host = host.split('@')[1]
        except Exception, e:
            logger.info("[%s] Unable to parse %s: %s. Will not scan !" %
                        (self.plugin.service_name, url, str(e)))
            return
        logger.info("[%s] ssh-keyscan on %s" % (self.plugin.service_name,
                                                host))
        c = (" \"ssh-keyscan -v -T5 %s >>"
             " /home/gerrit/.ssh/known_hosts_gerrit\"")
        cmd = [c % host]
        out, err, code = self._replication_ssh_run_cmd(cmd, shell=True)
        logger.info("[%s] ssh-keyscan returned %s" % (self.plugin.service_name,
                                                      code))
        if code:
            msg = "[%s] ssh-keyscan failed on %s"
            logger.info(msg % (self.plugin.service_name,
                               host))
            msg = "[%s] ssh-keyscan stdout: %s"
            logger.debug(msg % (self.plugin.service_name,
                                out))
        else:
            msg = "[%s] ssh-keyscan succeeded on %s"
            logger.info(msg % (self.plugin.service_name,
                               host))

    def apply_config(self, user, section, setting=None, value=None):
        projects = self.plugin.project.get(user=user)
        config = self._replication_read_config()
        self._replication_validate(projects, config, section, setting)
        gitcmd = ['git',
                  'config',
                  '-f',
                  self.plugin._full_conf.gerrit['replication_config_path']]
        _section = 'remote.' + section
        if value:
            if setting:
                if setting == 'url' and ('$' in value):
                    # To allow $ in url
                    value = "\$".join(value.rsplit("$", 1))
                if setting == 'url':
                    # Get the remote fingerprint
                    self._replication_fill_knownhosts(value)
                cmd = ['--add', '%s.%s' % (_section, setting), value]
            else:
                cmd = ['--rename-section', _section, 'remote.%s' % value]
        elif setting:
            cmd = ['--unset-all', '%s.%s' % (_section, setting)]
        else:
            cmd = ['--remove-section', _section]
        str_cmd = " ".join(cmd)
        msg = "[%s] Requested command is ... \n%s "
        logger.info(msg % (self.plugin.service_name, str_cmd))
        cmd = gitcmd + cmd
        out, err, code = self._replication_ssh_run_cmd(cmd)
        if code:
            msg = "[%s] apply_config err %s "
            logger.info(msg % (self.plugin.service_name, err))
            return err
        else:
            logger.info("[%s] Reload the replication plugin to pick up"
                        " the new configuration" % self.plugin.service_name)
            gerrit_client = G.Gerrit(
                self.plugin._full_conf.gerrit['host'],
                self.plugin._full_conf.admin['name'],
                keyfile=self.plugin._full_conf.gerrit['sshkey_priv_path'])
            cmd = 'gerrit plugin reload replication'
            out, err = gerrit_client._ssh(cmd)

    def trigger(self, user, json):
        logger.info("[%s] Replication_trigger %s" % (self.plugin.service_name,
                                                     str(json)))
        wait = True if 'wait' not in json else json['wait'] in ['True',
                                                                'true',
                                                                1]
        url = None if 'url' not in json else json['url']
        project = None if 'project' not in json else json['project']
        cmd = " replication start"
        projects = self.plugin.project.get(user=user)
        config = self._replication_read_config()
        find_section = None
        for section in config:
            if url and 'url' in config[section]:
                if url in config[section]['url']:
                    find_section = section
                    cmd = cmd + " --url %s" % url
                    break
            elif project and 'projects' in config[section]:
                if project in config[section]['projects']:
                    find_section = section
                    cmd = cmd + " %s" % project
                    break
        if find_section:
            self._replication_validate(projects, config, find_section)
        elif wait:
            cmd = cmd + " --wait"
        elif self.plugin.role.is_admin(user):
            cmd = cmd + " --all"
        else:
            logger.info("[%s] Trigger replication for"
                        " owned by user" % self.plugin.service_name)
            if len(projects) == 0:
                msg = ("[%s] User doesn't own any projects, so "
                       "unauthorized to trigger replication")
                logger.info(msg % self.plugin.service_name)
                raise Exception(msg % self.plugin.service_name)
            cmd = cmd + "  " + "  ".join(projects)
        logger.info("[%s] Replication cmd - %s " % (self.plugin.service_name,
                                                    cmd))
        gerrit_client = G.Gerrit(
            self.plugin._full_conf.gerrit['host'],
            self.plugin._full_conf.admin['name'],
            keyfile=self.plugin._full_conf.gerrit['sshkey_priv_path'])
        logger.info("[%s] Triggering Replication" % self.plugin.service_name)
        out, err = gerrit_client._ssh(cmd)
        if err:
            msg = "[%s] Replication Trigger error - %s"
            logger.info(msg % (self.plugin.service_name, err))
