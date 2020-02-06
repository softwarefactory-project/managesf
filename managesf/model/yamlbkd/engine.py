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

import os
import re
import yaml
import deepdiff
import logging

try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO
from pecan import conf

from managesf.model.yamlbkd.yamlbackend import YAMLBackend
from managesf.model.yamlbkd.yamlbackend import MemoryYAMLBackend
from managesf.model.yamlbkd.yamlbackend import YAMLDBException
from managesf.model.yamlbkd.resource import ModelInvalidException
from managesf.model.yamlbkd.resource import ResourceInvalidException
from managesf.model.yamlbkd.resource import KEY_RE_CONSTRAINT

from managesf.model.yamlbkd.resources.gitrepository import GitRepository
from managesf.model.yamlbkd.resources.group import Group
from managesf.model.yamlbkd.resources.gitacls import ACL
from managesf.model.yamlbkd.resources.project import Project
from managesf.model.yamlbkd.resources.tenant import Tenant
from managesf.model.yamlbkd.resources.connection import Connection


logger = logging.getLogger(__name__)

MAPPING = {'repos': GitRepository,
           'groups': Group,
           'projects': Project,
           'acls': ACL,
           'tenants': Tenant,
           'connections': Connection}


class ResourceDepsException(Exception):
    pass


class ResourceUnicityException(Exception):
    pass


class RTYPENotDefinedException(Exception):
    pass


class SFResourceBackendEngine(object):
    def __init__(self, workdir, subdir):
        self.workdir = workdir
        self.subdir = subdir
        logger.info('Resource engine is using %s as workdir' % (
                    self.workdir))

    def _get_update_change(self, rtype, prev, new, rids):
        """ Based on the resources id known to have evolved
        (was updated) we use the DeepDiff library identify
        the resource keys where values have changed between
        the prev[rid] and new[rid] struct. DeepDiff permits
        to easily known if a tuple/list contains changes as
        well as simple type like str.

        This function acts at the resource[rtype][rid]
        level only.
        """
        r_key_changes = {}
        for rid in rids:
            n = MAPPING[rtype](rid, new[rid])
            p = MAPPING[rtype](rid, prev[rid])
            n.set_defaults()
            p.set_defaults()
            new_data = n.get_resource()
            prev_data = p.get_resource()
            changes = deepdiff.DeepDiff(prev_data, new_data)
            if not changes:
                continue
            r_key_changes[rid] = {'data': new_data, 'changed': set()}
            for ctype, _changes in changes.items():
                if ctype in ('values_changed', 'iterable_item_removed',
                             'iterable_item_added', 'type_changes',
                             'dictionary_item_added',
                             'dictionary_item_removed'):
                    for c in _changes:
                        key = re.search(
                            r"root\['(" + KEY_RE_CONSTRAINT + r")'\].*$", c)
                        key = key.groups()[0]
                        r_key_changes[rid]['changed'].add(key)
                else:
                    logger.info('Unexpected change type (%s) '
                                'detected for rid: %s' % (ctype, rid))
        return r_key_changes

    def _get_data_diff(self, prev, new):
        """ Top level resources diff method that take two
        resources trees and compute resources added/removed
        and updated.

        This method returns a dict containing ids and data
        of resources by resource type and modification type
        create, delete, update.
        """
        previous_data_resources_ids = {}
        for rtype, resources in prev['resources'].items():
            previous_data_resources_ids[rtype] = set(resources.keys())
        new_data_resources_ids = {}
        for rtype, resources in new['resources'].items():
            new_data_resources_ids[rtype] = set(resources.keys())
        changed_resources_ids = {}
        new_resources_ids = {}
        removed_resources_ids = {}
        rtype_list = (set(previous_data_resources_ids.keys()) |
                      set(new_data_resources_ids.keys()))
        for rtype in rtype_list:
            changed_resources_ids[rtype] = (
                previous_data_resources_ids[rtype] &
                new_data_resources_ids[rtype])
            new_resources_ids[rtype] = (
                new_data_resources_ids[rtype] -
                previous_data_resources_ids[rtype])
            removed_resources_ids[rtype] = (
                previous_data_resources_ids[rtype] -
                new_data_resources_ids[rtype])
        sanitized_changes = {}
        for rtype in rtype_list:
            sanitized_changes.setdefault(
                rtype,
                {'update': {}, 'create': {}, 'delete': {}})
            sanitized_changes[rtype]['create'].update(dict([
                (rid, d) for rid, d in new['resources'][rtype].items()
                if rid in new_resources_ids[rtype]]))
            sanitized_changes[rtype]['delete'].update(dict([
                (rid, d) for rid, d in prev['resources'][rtype].items()
                if rid in removed_resources_ids[rtype]]))
            sanitized_changes[rtype]['update'] = self._get_update_change(
                rtype, prev['resources'][rtype], new['resources'][rtype],
                changed_resources_ids[rtype])
        return sanitized_changes

    def _check_rtype_defined(self, data):
        for rtype in data['resources']:
            if rtype not in MAPPING:
                raise RTYPENotDefinedException(
                    "Resources type: %s not exists" % rtype)

    def _check_unicity_constraints(self, new_data):
        """ This method read the new tree and validate if each
        each resources PRIMARY_KEY are unique over the same
        set of type of resources
        """
        for rtype, resources in new_data['resources'].items():
            accu = {}
            pk = MAPPING[rtype].PRIMARY_KEY
            if not pk:
                continue
            for rid, data in resources.items():
                if data[pk] in accu:
                    raise ResourceUnicityException(
                        "Resource [type: %s, ID: %s] primary key (%s) "
                        "%s is already used by another resource" % (
                            rtype, rid, pk, data[pk]))
                else:
                    accu[data[pk]] = None

    def _check_deps_constraints(self, new_data):
        """ This method read the new tree and validate if each
        id returned by each resources get_deps method is found
        in the new tree.
        """
        for rtype, resources in new_data['resources'].items():
            for rid, data in resources.items():
                r = MAPPING[rtype](rid, data)
                if r.is_deps_soft():
                    # This resource do not require deps existence check
                    continue
                r.set_defaults()
                deps = r.get_deps()
                for deps_type, deps_ids in deps.items():
                    for deps_id in deps_ids:
                        try:
                            assert deps_type in new_data['resources']
                            assert deps_id in tuple(
                                new_data['resources'][deps_type])
                        except AssertionError:
                            raise ResourceDepsException(
                                "Resource [type: %s, ID: %s] depends on an "
                                "unknown resource [type: %s, ID: %s]" % (
                                    rtype, rid, deps_type, deps_id))

    def _validate_changes(self, sanitized_changes, validation_logs, new):
        """ This method validates if changes on the tree is authorized
        based on each resources constraints.
        """
        for rtype, changes in sanitized_changes.items():
            for ctype, scoped_changes in changes.items():
                if ctype == 'create':
                    for rid, data in scoped_changes.items():
                        # Full new resource validation
                        r = MAPPING[rtype](rid, data)
                        r.validate()
                        r.set_defaults()
                        xv = MAPPING[rtype].CALLBACKS['extra_validations']
                        logs = xv(conf, new, r.get_resource())
                        if logs:
                            validation_logs.extend(logs)
                            raise ResourceInvalidException(
                                "Resource [type: %s, ID: %s] extra "
                                "validations failed" % (rtype, rid))
                        validation_logs.append(
                            "Resource [type: %s, ID: %s] is going to "
                            "be created." % (rtype, rid))
                if ctype == 'update':
                    for rid, data in scoped_changes.items():
                        # Full new resource validation
                        r = MAPPING[rtype](rid, data['data'])
                        r.validate()
                        xv = MAPPING[rtype].CALLBACKS['extra_validations']
                        logs = xv(conf, new, data['data'])
                        if logs:
                            validation_logs.extend(logs)
                            raise ResourceInvalidException(
                                "Resource [type: %s, ID: %s] extra "
                                "validations failed" % (rtype, rid))
                        # Check key changes are possible
                        if not all([r.is_mutable(k) for
                                    k in data['changed']]):
                            raise YAMLDBException(
                                "Resource [type: %s, ID: %s] contains changed "
                                "resource keys that are immutable. "
                                "Please check the model." % (
                                    rtype, rid))
                        validation_logs.append(
                            "Resource [type: %s, ID: %s] is going to "
                            "be updated." % (rtype, rid))
                if ctype == 'delete':
                    for rid, data in scoped_changes.items():
                        validation_logs.append(
                            "Resource [type: %s, ID: %s] is going to "
                            "be deleted." % (rtype, rid))

    def _get_resources_priority(self):
        """ This method determines in which order resources changes
        must be applied on the services. It is based on the PRIORITY
        values of each resource types.
        """
        priorities = [(rtype, obj.PRIORITY) for
                      rtype, obj in MAPPING.items()]
        return sorted(priorities, key=lambda p: p[1], reverse=True)

    def _apply_changes(self, sanitized_changes, apply_logs, new):
        """ This method apply detected changes to services via
        the resources callbacks and add to a logs set successful
        and failed ops. Callbacks are called in the right order
        related to the PRIORITY.
        """
        partial_errors = False
        priorities = self._get_resources_priority()
        for rtype, priority in priorities:
            if rtype not in sanitized_changes:
                continue
            for ctype, datas in sanitized_changes[rtype].items():
                for rid, data in datas.items():
                    apply_logs.append(
                        "Resource [type: %s, ID: %s] will be %s." % (
                            rtype, rid, ctype + 'd'))
                    logs = []
                    try:
                        if ctype == 'update':
                            # Resource set_defaults is done in
                            # get_update_change for resources that
                            # need to be updated
                            logs = MAPPING[rtype].CALLBACKS[ctype](
                                conf, new, data['data'])
                        else:
                            r = MAPPING[rtype](rid, data)
                            r.set_defaults()
                            _data = r.get_resource()
                            logs = MAPPING[rtype].CALLBACKS[ctype](
                                conf, new, _data)
                    except Exception as e:
                        logger.exception("apply_changes failed %s" % e)
                        logs.append(
                            "Resource [type: %s, ID: %s] %s op error (%s)." % (
                                rtype, rid, ctype, str(e)))
                    if logs:
                        # We have logs here meaning callback call
                        # has encountered some troubles
                        apply_logs.extend(logs)
                        partial_errors = True
                        apply_logs.append(
                            "Resource [type: %s, ID: %s] %s op failed." % (
                                rtype, rid, ctype))
                    else:
                        apply_logs.append(
                            "Resource [type: %s, ID: %s] has been %s." % (
                                rtype, rid, ctype + 'd'))
        return partial_errors

    def _resolv_resources_need_refresh(self, sanitized_changes, tree):
        """ This method detects which resources need to be updated
        because resources it depends on have been updated. For instance
        if an ACLs has be updated then the project that depends on it
        need to be updated.
        """
        def scan(logs):
            u_resources = {}
            for rtype in sanitized_changes:
                u_resources[rtype] = sanitized_changes[rtype]['update'].keys()

            if not any([len(ids) for ids in u_resources.values()]):
                return logs

            for rtype, resources in tree['resources'].items():
                for rid, data in resources.items():
                    r = MAPPING[rtype](rid, data)
                    if not r.should_be_updated():
                        # This resource does not need to be refreshed
                        # as it depends on a resource type that an update on it
                        # has no impact on this resource.
                        # eg. An ACL type depends on group type but a group
                        # update does not need to trigger an ACL update.
                        continue
                    deps = r.get_deps()
                    for deps_type, deps_ids in deps.items():
                        if (deps_type in u_resources and
                                deps_ids & set(u_resources[deps_type])):
                            sanitized_changes.setdefault(rtype, {'update': {}})
                            if rid not in sanitized_changes[rtype]['update']:
                                logs.append(
                                    "Resource [type: %s, ID: %s] need a "
                                    "refresh as at least one of its "
                                    "dependencies has been updated" % (
                                        rtype, rid))
                                sanitized_changes[rtype]['update'][rid] = {
                                    'data': data}
        logs = []
        # Do it 3 times to resolv deps of max 3 depths
        for _ in range(3):
            scan(logs)
        return logs

    def _append_missing_rtype(self, data):
        # If a tree leaf is missing for rtype then add
        # it by default. More convenient to avoid more
        # check later in the code.
        data.setdefault('resources', {})
        for rtype in MAPPING:
            data['resources'].setdefault(rtype, {})

    def _load_resource_data(self, repo_uri, ref, mark):
        """ Read the tree from YAML files stored in
        a GIT repository at a specific ref.
        """
        cpath = os.path.join(self.workdir, mark)
        if not os.path.isdir(cpath):
            os.mkdir(cpath)

        bkd = YAMLBackend(repo_uri, ref,
                          self.subdir, cpath,
                          "%s_cache" % cpath)

        data = bkd.get_data()
        self._append_missing_rtype(data)
        return data

    def _load_resource_data_from_memory(self, data):
        data = MemoryYAMLBackend(data).get_data()
        self._append_missing_rtype(data)
        return data

    def _load_resources_data(self, repo_prev_uri, prev_ref,
                             repo_new_uri, new_ref):
        """ Load data from two GIT repo refs
        """
        prev_data = self._load_resource_data(
            repo_prev_uri, prev_ref, 'prev')
        new_data = self._load_resource_data(
            repo_new_uri, new_ref, 'new')
        return prev_data, new_data

    def _get_missing_resources_diff(self, current, reality, ret_tree):
        """ This method compute the resources read from the
        reality that miss the current (suppose to be the
        config/resources/ tree master) tree. The computing
        is based on the resources PRIMARY_KEY.

        Resources read from the reality will be attached
        to an auto computed rid. These rid will surely differ
        from what users will use when declaring a resource.

        Looking at each resources PRIMARY_KEY value let us
        detect of resource that exist in the current tree
        under a different rid.

        Furthermore dependency ids of resources from reality
        will be updated in the proposed tree (ret_tree) to
        match the current ones.

        Finally the method fill ret_tree with only missing
        resources.
        """
        current_cache_ids = {}
        already_exist_ids = {}
        # Create a cache by resource type with dict
        # {'PRIMARY_KEY_VALUE': rid} - This to speedup lookup.
        for rtype, resources in current['resources'].items():
            current_cache_ids.setdefault(rtype, {})
            for rid, data in resources.items():
                pk = MAPPING[rtype].PRIMARY_KEY
                r = MAPPING[rtype](rid, data)
                current_cache_ids[rtype][r.resource[pk]] = rid

        # Fill the ret_tree with non existing resources
        # compared to current and keep track of already
        # existing one ids.
        for rtype, resources in reality['resources'].items():
            for rid, data in resources.items():
                pk = MAPPING[rtype].PRIMARY_KEY
                r = MAPPING[rtype](rid, data)
                m_rid = current_cache_ids[rtype].get(
                    r.resource[pk], None)
                if not m_rid:
                    # The resource does not exists in the
                    # current tree - so keep it
                    ret_tree['resources'].setdefault(rtype, {})
                    ret_tree['resources'][rtype][rid] = data
                else:
                    # The resource already exists in the
                    # current tree - mark it as existing
                    already_exist_ids.setdefault(rtype, {})
                    already_exist_ids[rtype][rid] = m_rid

        # Finally update dependencies ids if needed
        for rtype, resources in ret_tree['resources'].items():
            for rid, data in resources.items():
                r = MAPPING[rtype](rid, data)
                dkey = r.get_deps(keyname=True)
                if not dkey:
                    continue
                rdeps = r.get_deps()
                resolved_rdeps = []
                drtype = list(rdeps)[0]
                dids = rdeps[drtype]
                if dids:
                    for did in dids:
                        if (drtype in already_exist_ids and
                           did in already_exist_ids[drtype]):
                            resolved_rdeps.append(
                                already_exist_ids[drtype][did])
                        else:
                            resolved_rdeps.append(did)
                    if r.MODEL[dkey][0] is list:
                        r.resource[dkey] = resolved_rdeps
                    elif r.MODEL[dkey][0] is str:
                        r.resource[dkey] = resolved_rdeps[0]

        # Remove the name key as the rid is the name
        for rtype, resources in ret_tree['resources'].items():
            for rid, data in resources.items():
                del ret_tree['resources'][rtype][rid]['name']

    def validate(self, repo_prev_uri, prev_ref,
                 repo_new_uri, new_ref):
        """ Top level validate function
        """
        logger.info("Resources engine: validate resources requested "
                    "(old ref: %s, new ref: %s)" % (prev_ref, new_ref))
        if not os.path.isdir(self.workdir):
            os.mkdir(self.workdir)
        validation_logs = []
        try:
            prev, new = self._load_resources_data(
                repo_prev_uri, prev_ref, repo_new_uri, new_ref)
            self._check_rtype_defined(new)
            self._check_deps_constraints(new)
            self._check_unicity_constraints(new)
            changes = self._get_data_diff(prev, new)
            self._validate_changes(changes, validation_logs, new)
            validation_logs.extend(
                self._resolv_resources_need_refresh(changes, new))
        except (YAMLDBException,
                RTYPENotDefinedException,
                ModelInvalidException,
                ResourceInvalidException,
                ResourceUnicityException,
                ResourceDepsException) as e:
            validation_logs.append(str(e))
            for line in validation_logs:
                logger.info(line)
            return False, validation_logs
        for line in validation_logs:
            logger.info(line)
        return True, validation_logs

    def validate_from_structured_data(self, repo_prev_uri, prev_ref, data):
        """ Top level validate_from_structured_data function
        """
        logger.info("Resources engine: validate_from_structured_data resources"
                    " requested (old ref: %s, structured_data)" % prev_ref)
        if not os.path.isdir(self.workdir):
            os.mkdir(self.workdir)
        validation_logs = []
        try:
            prev = self._load_resource_data(
                repo_prev_uri, prev_ref, 'prev')
            new = self._load_resource_data_from_memory(data)
            self._check_rtype_defined(new)
            self._check_deps_constraints(new)
            self._check_unicity_constraints(new)
            changes = self._get_data_diff(prev, new)
            self._validate_changes(changes, validation_logs, new)
            validation_logs.extend(
                self._resolv_resources_need_refresh(changes, new))
        except (YAMLDBException,
                RTYPENotDefinedException,
                ModelInvalidException,
                ResourceInvalidException,
                ResourceUnicityException,
                ResourceDepsException) as e:
            validation_logs.append(str(e))
            for line in validation_logs:
                logger.info(line)
            return False, validation_logs
        for line in validation_logs:
            logger.info(line)
        return True, validation_logs

    def apply(self, repo_prev_uri, prev_ref,
              repo_new_uri, new_ref):
        """ Top level apply function
        """
        logger.info("Resources engine: apply resources requested"
                    "(old ref: %s, new ref: %s)" % (prev_ref, new_ref))
        if not os.path.isdir(self.workdir):
            os.mkdir(self.workdir)
        apply_logs = []
        try:
            prev, new = self._load_resources_data(
                repo_prev_uri, prev_ref, repo_new_uri, new_ref)
            changes = self._get_data_diff(prev, new)
            logs = self._resolv_resources_need_refresh(changes, new)
            apply_logs.extend(logs)
            partial = self._apply_changes(changes, apply_logs, new)
        except YAMLDBException as e:
            apply_logs.append(str(e))
            for line in apply_logs:
                logger.info(line)
            return False, apply_logs
        for line in apply_logs:
            logger.info(line)
        return not partial, apply_logs

    def get(self, cur_uri, cur_ref, public_url=None):
        """ Top level get function. This read the HEAD of the
        repo and return the resources data tree unmodified.
        """
        logger.info("Resources engine: get resource tree requested")
        if not os.path.isdir(self.workdir):
            os.mkdir(self.workdir)
        current = YAMLBackend(cur_uri, cur_ref,
                              self.subdir, self.workdir,
                              "%s_cache" % self.workdir.rstrip('/'))
        data = current.get_data()
        data_trans = {"resources": {}}
        for rtype, resources in data.get('resources', {}).items():
            for rid, rdata in resources.items():
                r = MAPPING[rtype](rid, rdata)
                r.set_defaults(soft=True)
                dtrans = r.transform_for_get()
                data_trans["resources"].setdefault(rtype, {})[rid] = dtrans
        data_trans["config-repo"] = cur_uri
        data_trans["public-url"] = (
            public_url or conf.resources.get("public_url"))
        # If we have connections defined in the configuration than mean
        # we are on a tenant deployement. So can set the connections resources
        # key from the config
        if hasattr(
                conf, 'resources') and conf.resources.get('connections', {}):
            data_trans['resources'][
                'connections'] = conf.resources.get('connections', {})
        return data_trans

    def direct_apply(self, prev, new):
        """ Top level direct_apply function. This function should be
        called only under specific conditions.

        The yamls will be checked for consistencies then resources
        deduced from the diff of both will be applied. It is needed to
        understand that using this will de-synchronize the config
        respository from the reality.
        """
        logger.info("Resources engine: direct apply resources requested")
        direct_apply_logs = []
        try:
            try:
                prev = yaml.safe_load(StringIO(prev))
            except Exception:
                raise YAMLDBException("YAML format corrupted for prev")
            try:
                new = yaml.safe_load(StringIO(new))
            except Exception:
                raise YAMLDBException("YAML format corrupted for new")
            YAMLBackend._validate_base_struct(prev)
            YAMLBackend._validate_base_struct(new)
            for rtype in MAPPING:
                prev['resources'].setdefault(rtype, {})
                new['resources'].setdefault(rtype, {})
            self._check_rtype_defined(prev)
            self._check_rtype_defined(new)
            self._check_deps_constraints(new)
            self._check_unicity_constraints(new)
            changes = self._get_data_diff(prev, new)
            self._validate_changes(changes, direct_apply_logs, new)
            direct_apply_logs.extend(
                self._resolv_resources_need_refresh(changes, new))
            partial = self._apply_changes(changes, direct_apply_logs, new)
        except (YAMLDBException,
                RTYPENotDefinedException,
                ModelInvalidException,
                ResourceInvalidException,
                ResourceUnicityException,
                ResourceDepsException) as e:
            direct_apply_logs.append(str(e))
            for line in direct_apply_logs:
                logger.info(line)
            return False, direct_apply_logs
        for line in direct_apply_logs:
            logger.info(line)
        if partial:
            return False, direct_apply_logs
        return True, direct_apply_logs

    def get_missing_resources(self, cur_uri, cur_ref):
        """ Top level get_missing_resources. This method read
        the real resources from services and return resources
        struct containing only missing resources (not found
        in the YAML backend (config repo master HEAD) but on
        services)
        """
        logger.info("Resources engine: get missing resources diff requested")
        current = self.get(cur_uri, cur_ref)
        reality = {'resources': {}}
        for rtype in MAPPING:
            current['resources'].setdefault(rtype, {})
            reality['resources'].setdefault(rtype, {})
        ret_tree = {'resources': {}}
        logs = []
        for rtype in MAPPING:
            ret = MAPPING[rtype].CALLBACKS['get_all'](conf, {})
            logs.extend(ret[0])
            reality['resources'].update(ret[1])
        # Get diff between reality and config
        self._get_missing_resources_diff(current, reality, ret_tree)
        for line in logs:
            logger.info(line)
        return logs, ret_tree
