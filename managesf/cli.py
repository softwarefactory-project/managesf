#!/usr/bin/env python
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

import argparse
import base64
import getpass
import glob
import json
import logging
import os
import re
import requests
import sqlite3
import sys
import time
import urlparse
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2


try:
    import http.client as http_client
except ImportError:
    # Python 2
    import httplib as http_client

from pysflib import sfauth


requests_log = logging.getLogger("requests.packages.urllib3")
requests_log.setLevel(logging.DEBUG)
requests_log.propagate = True


logger = logging.getLogger('sfmanager')
ch = logging.StreamHandler()
fh_debug = logging.FileHandler('sfmanager.log')
fh_debug.setLevel(logging.DEBUG)
info_formatter = '%(levelname)-8s - %(message)s'
debug_formatter = '%(asctime)s - %(name)-16s - ' + info_formatter
info_formatter = logging.Formatter(info_formatter)
debug_formatter = logging.Formatter(debug_formatter)
fh_debug.setFormatter(debug_formatter)


logger.addHandler(ch)
logger.addHandler(fh_debug)
requests_log.addHandler(fh_debug)


def _build_path(old_path):
    path = old_path
    if not os.path.isabs(path):
        homebase = os.path.expanduser('~')
        path = os.path.join(homebase, path)
    return path


def _is_cookie_valid(cookie):
    if not cookie:
        return False
    try:
        valid_until = float(cookie.split('%3B')[1].split('%3D')[1])
    except Exception:
        return False
    if valid_until < time.time():
        return False
    return True


def get_chromium_cookie(path='', host='softwarefactory'):
    jar_path = _build_path(path)
    logger.debug('looking for chrome cookies at %s' % jar_path)
    # chrome hardcoded values
    salt = b'saltysalt'
    iv = b' ' * 16
    length = 16
    chrome_password = 'peanuts'.encode('utf8')
    iterations = 1
    key = PBKDF2(chrome_password, salt, length, iterations)
    try:
        c = sqlite3.connect(jar_path)
        cur = c.cursor()
        cur.execute('select value, encrypted_value, host_key from cookies '
                    'where host_key like ? and name = "auth_pubtkt" '
                    'order by expires_utc desc',
                    ('%' + host + '%',))
        cypher = AES.new(key, AES.MODE_CBC, IV=iv)
        # Strip padding by taking off number indicated by padding
        # eg if last is '\x0e' then ord('\x0e') == 14, so take off 14.

        def clean(x):
            return x[:-ord(x[-1])].decode('utf8')

        for clear, encrypted, host_key in cur.fetchall():
            if clear:
                cookie = clear
            else:
                # buffer starts with 'v10'
                encrypted = encrypted[3:]
                try:
                    cookie = clean(cypher.decrypt(encrypted))
                except UnicodeDecodeError:
                    logger.debug("could not decode cookie %s" % encrypted)
                    cookie = None
            if _is_cookie_valid(cookie):
                return cookie
    except sqlite3.OperationalError as e:
        logger.debug("Could not read cookies: %s" % e)
    return None


def get_firefox_cookie(path='', host='softwarefactory'):
    """Fetch the auth cookie stored by Firefox at %path% for the
    %host% instance of Software Factory."""
    jar_path = _build_path(path)
    logger.debug('looking for firefox cookies at %s' % jar_path)
    try:
        c = sqlite3.connect(jar_path)
        cur = c.cursor()
        cur.execute('select value from moz_cookies where host '
                    'like ? and name = "auth_pubtkt" '
                    'order by expiry desc', ('%' + host + '%',))
        for cookie_info in cur.fetchall():
            if cookie_info:
                if _is_cookie_valid(cookie_info[0]):
                    return cookie_info[0]
    except sqlite3.OperationalError as e:
        logger.debug("Could not read cookies: %s" % e)
    return None


def die(msg):
    logger.error(msg)
    sys.exit(1)


def split_and_strip(s):
    l = s.split(',')
    return [x.strip() for x in l]


def default_arguments(parser):
    parser.add_argument('--url',
                        help='Software Factory public gateway URL',
                        required=True)
    parser.add_argument('--auth', metavar='username[:password]',
                        help='Authentication information', required=False)
    parser.add_argument('--github-token', metavar='GithubPersonalAccessToken',
                        help='Authenticate with a Github Access Token')
    parser.add_argument('--auth-server-url', metavar='central-auth-server',
                        help='URL of the central auth server')
    parser.add_argument('--cookie', metavar='Authentication cookie',
                        help='cookie of the user if known')
    parser.add_argument('--insecure', default=False, action='store_true',
                        help='disable SSL certificate verification, '
                        'verification is enabled by default')
    parser.add_argument('--debug', default=False, action='store_true',
                        help='enable debug messages in console, '
                        'disabled by default')


def membership_command(parser):
    def membership_args(x):
        x.add_argument('--project', metavar='project-name', required=True,
                       help='The project name')
        x.add_argument('--user', metavar='user@example.com', required=True,
                       help="The user's email registered in Software Factory")

    root = parser.add_parser('membership',
                             help='Users membership to project(s)')
    sub_cmd = root.add_subparsers(dest='subcommand')
    add = sub_cmd.add_parser('add', help="Add a user to a project's group(s)")
    membership_args(add)
    add.add_argument('--groups', nargs='+',
                     metavar='[core-group|dev-group|ptl-group]',
                     help="The project's group(s)",
                     choices=['core-group', 'dev-group', 'ptl-group'])

    remove = sub_cmd.add_parser('remove',
                                help="Remove a user from project's group")
    membership_args(remove)
    remove.add_argument('--group', metavar='[core-group|dev-group|ptl-group]',
                        help="The project's group(s)",
                        choices=['core-group', 'dev-group', 'ptl-group'])

    sub_cmd.add_parser('list',
                       help='Print a list of active users in Software Factory')


def system_command(parser):
    root = parser.add_parser('system', help='system level commands')
    sub_cmd = root.add_subparsers(dest='subcommand')
    sub_cmd.add_parser('backup_start',
                       help='Start the backup process in Software Factory')
    sub_cmd.add_parser('backup_get',
                       help='Download the latest backup from Software Factory')
    restore = sub_cmd.add_parser('restore',
                                 help='Restore Software Factory data')
    restore.add_argument('--filename', metavar='absolute-path',
                         required=True,
                         help='The file downloaded from backup_get')


def replication_command(parser):
    def section_args(x, include_value=False):
        x.add_argument('--section', nargs='?', required=True,
                       help='section to which this setting belongs to')
        x.add_argument('name', metavar='name', nargs='?',
                       help='Setting name. Supported settings - project, url')
        if include_value:
            x.add_argument('value', nargs='?', help='Value of the setting')

    root = parser.add_parser('replication', help='System replication commands')
    sub_cmd = root.add_subparsers(dest='subcommand')

    help_msg = 'Trigger the replication events of a project'
    trigger = sub_cmd.add_parser('trigger', help=help_msg)
    trigger.add_argument('--wait', default=False, action='store_true',
                         help='Place the trigger in a queue')
    trigger.add_argument('--project', '-p', metavar='project-name')
    trigger.add_argument('--url', metavar='repo-url',
                         help='The url of the project')

    config = sub_cmd.add_parser('configure',
                                help='Configure the replication system')
    config_sub = config.add_subparsers(dest='rep_command')
    config_sub.add_parser('list',
                          help='List of replication variables settings')

    get_all = config_sub.add_parser('get-all',
                                    help='Get all variables for that setting')
    section_args(get_all)

    help_msg = 'Replace variable values for all settings'
    replace_all = config_sub.add_parser('replace-all', help=help_msg)
    section_args(replace_all, True)

    rename = config_sub.add_parser('rename', help='Rename variable name')
    section_args(rename, True)

    remove = config_sub.add_parser('remove', help='Remove the variable')
    section_args(remove)

    add = config_sub.add_parser('add', help='Set new variable')
    section_args(add, True)


def gerrit_api_htpasswd(sp):
    sp.add_parser('generate_password')
    sp.add_parser('delete_password')


def gerrit_ssh_config(sp):
    add_config = sp.add_parser('add')
    add_config.add_argument('--alias', nargs='?', required=True)
    add_config.add_argument('--hostname', nargs='?', required=True)
    add_config.add_argument('--keyfile', nargs='?', required=True)

    delete_config = sp.add_parser('delete')
    delete_config.add_argument('--alias', nargs='?', required=True)


def user_management_command(sp):
    cump = sp.add_parser('create', help='Create user. Admin rights required')
    cump.add_argument('--username', '-u', nargs='?', metavar='username',
                      required=True, help='A unique username/login')
    cump.add_argument('--password', '-p', nargs='?', metavar='password',
                      required=True,
                      help='The user password, can be provided interactively'
                           ' if this option is empty')
    cump.add_argument('--email', '-e', nargs='?', metavar='email',
                      required=True, help='The user email')
    cump.add_argument('--fullname', '-f', nargs='+', metavar='John Doe',
                      help="The user's full name, defaults to username",
                      required=True)
    cump.add_argument('--ssh-key', '-s', nargs='?', metavar='/path/to/pub_key',
                      required=False, help="The user's ssh public key file")
    uump = sp.add_parser('update', help='Update user details. Admin can update'
                         ' details of all users. User can update its own'
                         ' details.')
    uump.add_argument('--username', '-u', nargs='?', metavar='username',
                      required=True,
                      help='the user to update, defaults to current user')
    uump.add_argument('--password', '-p', nargs='?', metavar='password',
                      required=False, default=False,
                      help='The user password, can be provided interactively'
                           ' if this option is empty')
    uump.add_argument('--email', '-e', nargs='?', metavar='email',
                      required=False, help='The user email')
    uump.add_argument('--fullname', '-f', metavar='John Doe', nargs='+',
                      required=False, help="The user's full name")
    uump.add_argument('--ssh-key', '-s', nargs='?', metavar='/path/to/pub_key',
                      required=False, help="The user's ssh public key file")
    dump = sp.add_parser('delete', help='Delete user. Admin rights required')
    dump.add_argument('--username', '-u', nargs='?', metavar='username',
                      required=True, help='the user to delete')


def project_command(sp):
    cp = sp.add_parser('create')
    cp.add_argument('--name', '-n', nargs='?', metavar='project-name',
                    required=True)
    cp.add_argument('--description', '-d', nargs='?',
                    metavar='project-description')
    cp.add_argument('--upstream', '-u', nargs='?', metavar='GIT link')
    cp.add_argument('--upstream-ssh-key', metavar='upstream-ssh-key',
                    help='SSH key for authentication against the upstream ' +
                    'repository (without a passphrase)')
    cp.add_argument('--core-group', '-c', metavar='core-group-members',
                    help='member ids separated by comma', nargs='?')
    cp.add_argument('--ptl-group', '-p', metavar='ptl-group-members',
                    help='member ids serarated by comma', nargs='?')
    cp.add_argument('--dev-group', '-e', metavar='dev-group-members',
                    help='member ids serarated by comma'
                    ' (only relevant for private project)',
                    nargs='?')
    cp.add_argument('--private', action='store_true',
                    help='set if the project is private')

    dp = sp.add_parser('delete')
    dp.add_argument('--name', '-n', nargs='?', metavar='project-name',
                    required=True)


def tests_command(parser):
    tp = parser.add_parser('tests')
    subc = tp.add_subparsers(dest='subcommand')
    init = subc.add_parser('init',
                           help='Setup the initial tests configuration for'
                           ' a given project')
    init.add_argument('--no-scripts', action='store_true',
                      help='Does not create the tests scripts in the project')
    init.add_argument('--project', '--p', metavar='project-name',
                      required=True)


def command_options(parser):
    sp = parser.add_subparsers(dest="command")
    project_commands = sp.add_parser('project',
                                     help='project-related commands')
    spc = project_commands.add_subparsers(dest="subcommand")
    user_commands = sp.add_parser('user',
                                  help='project users-related commands')
    suc = user_commands.add_subparsers(dest="subcommand")
    gerrit_api_commands = sp.add_parser('gerrit_api_htpasswd',
                                        help='Gerrit API access commands')
    gic = gerrit_api_commands.add_subparsers(dest="subcommand")
    gerrit_ssh_commands = sp.add_parser('gerrit_ssh_config',
                                        help='Gerrit SSH config commands')
    gsc = gerrit_ssh_commands.add_subparsers(dest="subcommand")

    gerrit_api_htpasswd(gic)
    gerrit_ssh_config(gsc)
    project_command(spc)
    user_management_command(suc)

    # New options
    membership_command(sp)
    system_command(sp)
    replication_command(sp)
    tests_command(sp)


def get_cookie(args):
    if args.cookie is not None:
        return args.cookie
    url_stripper = re.compile('http[s]?://(.+)')
    use_ssl = False
    try:
        url = args.auth_server_url.rstrip('/')
        m = url_stripper.match(url)
        if m:
            if url.lower().startswith('https'):
                use_ssl = True
            url = m.groups()[0]
        if args.auth is not None:
            (username, password) = args.auth.split(':')
            cookie = sfauth.get_cookie(url, username=username,
                                       password=password,
                                       use_ssl=use_ssl,
                                       verify=(not args.insecure))
        elif args.github_token is not None:
            token = args.github_token
            cookie = sfauth.get_cookie(url, github_access_token=token,
                                       use_ssl=use_ssl,
                                       verify=(not args.insecure))
        else:
            die('Please provide credentials')
        if cookie:
            return cookie
        else:
            die('Authentication failed')
    except Exception as e:
        die(e.message)


def response(resp, as_text=False):
    if resp.ok:
        if as_text:
            print json.loads(resp.text)
        else:
            print resp.text
        return True
    if resp.status_code // 100 == 4:
        msg = 'NOT FOUND : %s' % resp.text
        die(msg)
    if resp.status_code // 100 == 5:
        msg = 'SERVER ERROR : %s' % resp.text
        die(msg)
    else:
        die(resp.text)


def build_url(*args):
    return '/'.join(s.strip('/') for s in args) + '/'


def membership_action(args, base_url, headers):
    if args.command != 'membership':
        return False

    if args.subcommand not in ['add', 'remove', 'list']:
        return False
    auth_cookie = {'auth_pubtkt': get_cookie(args)}

    if args.subcommand == 'list':
        logger.info('List users assigned to projects')
        url = build_url(base_url, 'project/membership')
        resp = requests.get(url, headers=headers, cookies=auth_cookie)
        return response(resp)

    url = build_url(base_url, 'project/membership', args.project, args.user)
    if args.subcommand == 'add':
        logger.info('Add member %s to project %s', args.user, args.project)
        if args.groups:
            data = json.dumps({'groups': args.groups})
        resp = requests.put(url, headers=headers, data=data,
                            cookies=auth_cookie)
        return response(resp)

    if args.subcommand == 'remove':
        logger.info('Remove member %s from project %s', args.user,
                    args.project)
        if args.group:
            url = build_url(url, args.group)
        resp = requests.delete(url, headers=headers, cookies=auth_cookie)
        return response(resp)

    return False


def project_user_action(args, base_url, headers):
    if args.command in ['add_user', 'delete_user', 'list_active_users']:
        subcommand = args.command
        logger.info("Deprecated syntax, "
                    "please use project %s ..." % subcommand)
    elif args.command == 'project':
        subcommand = args.subcommand
    else:
        return False

    if subcommand in ['add_user', 'delete_user']:
        url = "{}/project/membership/{}/{}/".format(base_url, args.name,
                                                    args.user)
    elif subcommand == 'list_active_users':
        url = base_url + '/project/membership/'
    if subcommand == 'add_user':
        groups = split_and_strip(args.groups)
        data = json.dumps({'groups': groups})
        resp = requests.put(url, headers=headers, data=data,
                            cookies=dict(auth_pubtkt=get_cookie(args)))

    elif subcommand == 'delete_user':
        # if a group name is provided, delete user from that group,
        # otherwise delete user from all groups
        if args.group:
            url = url + args.group
        resp = requests.delete(url, headers=headers,
                               cookies=dict(auth_pubtkt=get_cookie(args)))

    elif subcommand == 'list_active_users':
        resp = requests.get(url, headers=headers,
                            cookies=dict(auth_pubtkt=get_cookie(args)))

    else:
        return False

    return response(resp)


def project_action(args, base_url, headers):
    if args.command in ['delete', 'create']:
        subcommand = args.command
        logger.info("Deprecated syntax, "
                    "please use project %s ..." % subcommand)
    elif args.command == 'project':
        subcommand = args.subcommand
    else:
        return False

    url = base_url + "/project/%s" % args.name
    if subcommand == 'create':
        if getattr(args, 'core_group'):
            args.core_group = split_and_strip(args.core_group)
        if getattr(args, 'ptl_group'):
            args.ptl_group = split_and_strip(args.ptl_group)
        if getattr(args, 'dev_group'):
            args.dev_group = split_and_strip(args.dev_group)
        if getattr(args, 'upstream_ssh_key'):
            with open(args.upstream_ssh_key) as ssh_key_file:
                args.upstream_ssh_key = ssh_key_file.read()
        substitute = {'description': 'description',
                      'core_group': 'core-group-members',
                      'ptl_group': 'ptl-group-members',
                      'dev_group': 'dev-group-members',
                      'upstream': 'upstream',
                      'upstream_ssh_key': 'upstream-ssh-key',
                      'private': 'private'}
        info = {}
        for key, word in substitute.iteritems():
            if getattr(args, key):
                info[word] = getattr(args, key)

        params = {'headers': headers,
                  'cookies': dict(auth_pubtkt=get_cookie(args))}

        if len(info.keys()):
            params['data'] = json.dumps(info)

        resp = requests.put(url, **params)

    elif subcommand == 'delete':
        resp = requests.delete(url, headers=headers,
                               cookies=dict(auth_pubtkt=get_cookie(args)))
    else:
        return False

    return response(resp)


def tests_action(args, base_url, headers):

    if args.command != 'tests':
        return False

    if getattr(args, 'subcommand') != 'init':
        return False
    url = build_url(base_url, 'tests', args.project)
    data = {}
    if args.no_scripts:
        data['project-scripts'] = False
    else:
        data['project-scripts'] = True

    resp = requests.put(url, data=json.dumps(data), headers=headers,
                        cookies=dict(auth_pubtkt=get_cookie(args)))
    return response(resp)


def backup_action(args, base_url, headers):
    if args.command not in ['system', 'backup_get', 'backup_start',
                            'restore']:
        return False

    if args.command in ['backup_get', 'backup_start', 'restore']:
        logger.info('Depreacated syntax: Please use the system command')
        subcommand = args.command
    else:
        subcommand = args.subcommand

    url = build_url(base_url, 'backup')
    params = {'headers': headers,
              'cookies': dict(auth_pubtkt=get_cookie(args))}
    if subcommand == 'backup_get':
        resp = requests.get(url, **params)
        if resp.status_code != 200:
            die("backup_get failed with status_code " + str(resp.status_code))
        chunk_size = 1024
        with open('sf_backup.tar.gz', 'wb') as fd:
            for chunk in resp.iter_content(chunk_size):
                fd.write(chunk)
        return True

    elif subcommand == 'backup_start':
        resp = requests.post(url, **params)
        return response(resp)

    elif subcommand == 'restore':
        url = build_url(base_url, 'restore')
        filename = args.filename
        if not os.path.isfile(filename):
            die("file %s does not exist" % filename)
        files = {'file': open(filename, 'rb')}
        resp = requests.post(url, headers=headers, files=files,
                             cookies=dict(auth_pubtkt=get_cookie(args)))
        return response(resp)

    return False


def gerrit_api_htpasswd_action(args, base_url, headers):
    url = base_url + '/htpasswd'
    if not getattr(args, 'subcommand', None):
        return False
    if args.subcommand not in ['generate_password', 'delete_password']:
        return False

    if args.subcommand == 'generate_password':
        resp = requests.put(url, headers=headers,
                            cookies=dict(auth_pubtkt=get_cookie(args)))

    elif args.subcommand == 'delete_password':
        resp = requests.delete(url, headers=headers,
                               cookies=dict(auth_pubtkt=get_cookie(args)))

    return response(resp, as_text=True)


def gerrit_ssh_config_action(args, base_url, headers):
    url = base_url + '/sshconfig'
    if args.command not in ['gerrit', 'gerrit_ssh_config']:
        return False
    if not getattr(args, 'subcommand', None):
        return False
    if args.subcommand not in ['add', 'delete']:
        return False

    url += '/' + args.alias

    if args.subcommand == 'add':
        data = {
            "hostname": args.hostname,
            "userknownHostsfile": "/dev/null",
            "preferredauthentications": "publickey",
            "stricthostkeychecking": "no",
        }

        with open(args.keyfile) as ssh_key_file:
            data["identityfile_content"] = ssh_key_file.read()
        resp = requests.put(url, headers=headers, data=json.dumps(data),
                            cookies=dict(auth_pubtkt=get_cookie(args)))

    elif args.subcommand == 'delete':
        resp = requests.delete(url, headers=headers,
                               cookies=dict(auth_pubtkt=get_cookie(args)))

    return response(resp)


def replication_action(args, base_url, headers):
    if args.command not in ['replication_config', 'trigger_replication',
                            'replication']:
        return False

    if args.command in ['replication_config', 'trigger_replication']:
        logger.info('Deprecated syntax, please use at the replication command')
        subcommand = args.command
    else:
        subcommand = args.subcommand

    if subcommand in ['replication_config', 'configure']:
        headers['Content-Type'] = 'application/json'
        settings = ['projects', 'url', 'push', 'receivepack', 'uploadpack',
                    'timeout', 'replicationDelay', 'threads']
        url = build_url(base_url, 'replication')
        params = {'headers': headers,
                  'cookies': dict(auth_pubtkt=get_cookie(args))}

        # Validate the name argument
        if args.rep_command not in ('list', 'rename', 'remove'):
            if getattr(args, 'name') and (args.name not in settings):
                logger.error("Invalid setting %s" % args.name)
                die("Valid settings are " + " , ".join(settings))

        if args.rep_command == 'list':
            resp = requests.get(url, **params)
            return response(resp)

        if args.rep_command == 'get-all':
            url = build_url(url, args.section)
            resp = requests.get(url, **params)
            return response(resp)

        if args.rep_command == 'rename':
            url = build_url(url, args.section)
            params['data'] = json.dumps({'value': args.name})
            resp = requests.put(url, **params)
            return response(resp)

        if args.rep_command == 'remove':
            url = build_url(url, args.section)
            resp = requests.delete(url, **params)
            return response(resp)

        if args.rep_command == 'add':
            url = build_url(url, args.section, args.name)
            params['data'] = json.dumps({'value': args.value})
            resp = requests.put(url, **params)
            return response(resp)

        data = {}
        if args.rep_command != "list":
            if getattr(args, 'section'):
                url = url + '/%s' % args.section
            else:
                die("No section provided")
        if args.rep_command in ('add', 'replace-all', 'rename'):
            if getattr(args, 'value'):
                data = {'value': args.value}
            else:
                die("No value provided")

        if args.rep_command in {'unset-all', 'replace-all', 'remove'}:
            meth = requests.delete
        elif args.rep_command in {'add', 'rename'}:
            meth = requests.put
        elif args.rep_command in {'get-all', 'list'}:
            meth = requests.get
        resp = meth(url, headers=headers, data=json.dumps(data),
                    cookies=dict(auth_pubtkt=get_cookie(args)))
        if args.rep_command == 'replace-all':
            resp = requests.put(url, headers=headers, data=json.dumps(data),
                                cookies=dict(auth_pubtkt=get_cookie(args)))
            # These commands need json as output,
            # if server has no valid json it will send {}
            # for other commands print status
            if args.rep_command in {'get-all', 'list'}:
                logger.info(resp.json())
                return True
        return response(resp)

    elif subcommand in ['trigger_replication', 'trigger']:
        headers['Content-Type'] = 'application/json'
        url = build_url(base_url, 'replication')
        info = {}
        if args.wait:
            info['wait'] = 'true'
        else:
            info['wait'] = 'false'
        if getattr(args, 'url'):
            info['url'] = args.url
        if getattr(args, 'project'):
            info['project'] = args.project
        resp = requests.post(url, headers=headers, data=json.dumps(info),
                             cookies=dict(auth_pubtkt=get_cookie(args)))
        return response(resp)

    return False


def user_management_action(args, base_url, headers):
    if args.command != 'user':
        return False
    if args.subcommand not in ['create', 'update', 'delete']:
        return False
    url = build_url(base_url, 'user', args.username)
    if args.subcommand in ['create', 'update']:
        headers['Content-Type'] = 'application/json'
        password = None
        if args.password is None:
            # -p option has been passed by with no value
            password = getpass.getpass("Enter password: ")
        elif args.password:
            password = args.password
        info = {}
        if getattr(args, 'email'):
            info['email'] = args.email
        if getattr(args, 'ssh_key'):
            with open(args.ssh_key, 'r') as f:
                info['sshkey'] = f.read()
        if getattr(args, 'fullname'):
            info['fullname'] = ' '.join(args.fullname)
        if password:
            info['password'] = password
        resp = requests.post(url, headers=headers, data=json.dumps(info),
                             cookies=dict(auth_pubtkt=get_cookie(args)))
    if args.subcommand == 'delete':
        resp = requests.delete(url, headers=headers,
                               cookies=dict(auth_pubtkt=get_cookie(args)))
    return response(resp)


def main():
    parser = argparse.ArgumentParser(description="Tool to manage software"
                                     " factory projects")
    default_arguments(parser)
    command_options(parser)
    args = parser.parse_args()
    base_url = "%s/manage" % args.url.rstrip('/')

    if not args.debug:
        ch.setLevel(logging.ERROR)
        ch.setFormatter(info_formatter)
    else:
        http_client.HTTPConnection.debuglevel = 1
        ch.setLevel(logging.DEBUG)
        ch.setFormatter(debug_formatter)

    if args.auth_server_url is None:
        args.auth_server_url = args.url

    # check that the cookie is still valid
    if args.cookie is not None:
        if not _is_cookie_valid(args.cookie):
            die("Invalid cookie")

    if (args.auth is None and
       args.cookie is None and
       args.github_token is None):
        host = urlparse.urlsplit(args.url).hostname
        logger.info("No authentication provided, looking for an existing "
                    "cookie for host %s... " % host),
        # try Chrome
        CHROME_COOKIES_PATH = _build_path('.config/chromium/Default/Cookies')
        cookie = get_chromium_cookie(CHROME_COOKIES_PATH,
                                     host)
        if _is_cookie_valid(cookie):
            args.cookie = cookie
        if args.cookie is None:
            # try Firefox
            FIREFOX_COOKIES_PATH = _build_path(
                '.mozilla/firefox/*.default/cookies.sqlite')
            paths = glob.glob(FIREFOX_COOKIES_PATH)
            # FF can have several profiles, let's cycle through
            # them until we find a cookie
            for p in paths:
                cookie = get_firefox_cookie(p, host)
                if _is_cookie_valid(cookie):
                    args.cookie = cookie
                    break
        if args.cookie is None:
            logger.error("No cookie found.")
            die("Please provide valid credentials.")
        userid = args.cookie.split('%3B')[0].split('%3D')[1]
        logger.info("Authenticating as %s" % userid)

    headers = {}
    if args.auth is not None and ":" not in args.auth:
        password = getpass.getpass("%s's password: " % args.auth)
        args.auth = "%s:%s" % (args.auth, password)
        headers = {'Authorization': 'Basic ' + base64.b64encode(args.auth)}

    if args.insecure:
        import urllib3
        urllib3.disable_warnings()
    if not(project_user_action(args, base_url, headers) or
           project_action(args, base_url, headers) or
           backup_action(args, base_url, headers) or
           gerrit_api_htpasswd_action(args, base_url, headers) or
           replication_action(args, base_url, headers) or
           user_management_action(args, base_url, headers) or
           gerrit_ssh_config_action(args, base_url, headers) or
           membership_action(args, base_url, headers) or
           tests_action(args, base_url, headers)):
        die("ManageSF failed to execute your command")

if __name__ == '__main__':
    main()
