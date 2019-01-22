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


import re


class ModelInvalidException(Exception):
    pass


class ResourceInvalidException(Exception):
    pass


AUTHORIZED_CALLBACKS = ('update', 'create', 'delete',
                        'extra_validations', 'get_all')

KEY_RE_CONSTRAINT = "[a-zA-Z0-9-_]+"


class BaseResource(object):
    """ All resources to define for this backend
    must inherit from this class. This class
    cannot be initialized by itself.

    The resource data model description must
    contains a dictionnary where each key is a
    resource attribute and value a tuple that describes
    the attribute constraints.

    'key': (
        str, # Type
        regexp, # Value regex validator
        True, # Mandatory key
        None, # Default value
        True, # Is the value mutable
        "String", # Description
    ),

    """

    MODEL_TYPE = 'default'
    DESCRIPTION = 'No description available'
    MODEL = {}
    PRIORITY = None
    # The primary key tells if a field should be unique
    # over all resources of a given type. Leave it at None if not the case
    PRIMARY_KEY = None
    CALLBACKS = {
        'update': lambda conf, new, kwargs: NotImplementedError,
        'create': lambda conf, new, kwargs: NotImplementedError,
        'delete': lambda conf, new, kwargs: NotImplementedError,
        'extra_validations': lambda conf, new, kwargs: NotImplementedError,
        'get_all': lambda conf, new: NotImplementedError,
    }

    def __init__(self, id, resource):
        self.id = id
        self._model_definition_validate()
        self.resource = resource
        # "name" is a special key that will inherit of the Resource
        # ID value. The ID value must then match the "name" regex
        # contraint
        self.resource['name'] = self.id
        self.mandatory_keys = set(
            [k for k, v in self.__class__.MODEL.items() if v[2]])
        self.keys = set(self.__class__.MODEL)

    def _model_definition_validate(self):
        """ This validate the inherited model. This is
        to validate resource model defined by inherited
        classes. We make sure the model is followed by the
        developper.
        """
        try:
            assert isinstance(self.__class__.MODEL_TYPE, str)
            assert (isinstance(self.__class__.PRIMARY_KEY, str) or
                    self.__class__.PRIMARY_KEY is None)
            assert isinstance(self.__class__.PRIORITY, int)
            for key in self.__class__.MODEL:
                assert re.match("^" + KEY_RE_CONSTRAINT + "$", key)
            assert 'name' in self.__class__.MODEL
        except Exception:
            raise ModelInvalidException(
                "Model %s is invalid and not usable" % (
                    self.__class__.MODEL_TYPE))

        if self.__class__.PRIMARY_KEY and self.__class__.PRIMARY_KEY != 'name':
            if self.__class__.PRIMARY_KEY not in self.__class__.MODEL:
                raise ModelInvalidException(
                    "Model %s primary key %s does not exists" % (
                        self.__class__.MODEL_TYPE,
                        self.__class__.PRIMARY_KEY))

            if not self.__class__.MODEL[self.__class__.PRIMARY_KEY][2]:
                raise ModelInvalidException(
                    "Model %s primary key %s should be mandatory" % (
                        self.__class__.MODEL_TYPE,
                        self.__class__.PRIMARY_KEY))

        for constraints in self.__class__.MODEL.values():
            if len(constraints) != 6:
                raise ModelInvalidException(
                    "Model %s is invalid and not usable "
                    "(missing field)" % (
                        self.__class__.MODEL_TYPE))

        try:
            # Be sure default values are of the declared type
            # make some others validation on default value
            for key, constraints in self.__class__.MODEL.items():
                # Only act on non-mandatory keys as default
                # is provided. Skip 'name' checking.
                if not constraints[2] and key != 'name':
                    # Validate default value type
                    assert isinstance(constraints[3],
                                      constraints[0])
                    # Validate default value match the regexp
                    # if str type
                    if constraints[0] is str:
                        assert re.match(constraints[1],
                                        constraints[3])
                    # Validate default value match the regexp
                    # if dict type
                    if constraints[0] is dict:
                        assert isinstance(constraints[1], tuple)
                        key_re = re.compile(constraints[1][0])
                        val_re = re.compile(constraints[1][1])
                        for k, v in constraints[3].items():
                            assert key_re.match(k)
                            if isinstance(v, (str, bytes)):
                                assert val_re.match(v)
                            else:
                                if (not isinstance(v, bool) and
                                        not isinstance(v, int)):
                                    raise AssertionError()
                    # Validate list default values match the regexp
                    # if list type
                    if constraints[0] is list:
                        # Constraints[1] is string (a regexp) in case of list
                        # of str only
                        if isinstance(constraints[1], (str, bytes)):
                            assert all([re.match(constraints[1], c) for
                                        c in constraints[3]]) is True
                        # If constraints[1] is a tuple then constraints[1][0]
                        # must be a dict and constraints[1][1] is regexp for
                        # the dict key. But value can still be a simple string
                        # then the value is validated against constraints[1][1]
                        elif isinstance(constraints[1], tuple):
                            assert constraints[1][0] is dict
                            assert isinstance(constraints[1][1], str)
                            for c in constraints[3]:
                                if isinstance(c, dict):
                                    # Make sure default value only have dict
                                    # with a single key
                                    assert len(c.keys()) == 1
                                    # Make sure default value only have dict
                                    # with a key matching the regexp
                                    assert re.match(
                                        constraints[1][1], list(c)[0])
                                if isinstance(c, (str, bytes)):
                                    assert re.match(constraints[1][1], c)
                        else:
                            # Unsuported case constraints[1] can be only a
                            # (str, bytes) or tuple
                            assert False
        except Exception:
            raise ModelInvalidException(
                "Model %s is invalid and not usable "
                "(Wrong default value according to the type "
                "or regex)" % (
                    self.__class__.MODEL_TYPE))

        # Validate the callbacks of the inherited model
        try:
            # Be sure we have only the authorized callbacks
            assert len(set(AUTHORIZED_CALLBACKS).symmetric_difference(
                set(self.__class__.CALLBACKS))) == 0
            # Be sure the callbacks are callable or NotImplemented
            for key, callback in self.__class__.CALLBACKS.items():
                if (not callable(callback)
                        and callback is not NotImplementedError):
                    raise Exception
        except Exception:
            raise ModelInvalidException(
                "Model %s callbacks are invalid, model is not usable" % (
                    self.__class__.MODEL_TYPE))

    def val_validate(self, v, val_re):
        return val_re.match(v) if isinstance(v, (str, bytes)) else True

    def validate(self):
        """ Validate the data MODEL of the resource
        """
        # Validate all mandatory keys are present
        if not self.mandatory_keys.issubset(set(self.resource)):
            raise ResourceInvalidException(
                "Resource [type: %s, ID: %s] miss a "
                "mandatory key. Please check the model." % (
                    self.__class__.MODEL_TYPE,
                    self.id))

        # Validate the resource does not contains extra keys
        if not set(self.resource).issubset(self.keys):
            raise ResourceInvalidException(
                "Resource [type: %s, ID: %s] contains "
                "extra keys. Please check the model." % (
                    self.__class__.MODEL_TYPE,
                    self.id))

        # Validate the resource value type
        for key, value in self.resource.items():
            if not isinstance(value, self.__class__.MODEL[key][0]):
                raise ResourceInvalidException(
                    "Resource [type: %s, ID: %s] has an invalid "
                    "key (%s) data type (expected: %s)" % (
                        self.__class__.MODEL_TYPE,
                        self.id,
                        key,
                        self.__class__.MODEL[key][0]))
            # For str type validate the content as according the regex
            if self.__class__.MODEL[key][0] is str:
                if not re.match(self.__class__.MODEL[key][1], value):
                    raise ResourceInvalidException(
                        "Resource [type: %s, ID: %s] has an invalid "
                        "key (%s) data content (expected match : %s)" % (
                            self.__class__.MODEL_TYPE,
                            self.id,
                            key,
                            self.__class__.MODEL[key][1]))
            # For list type validate the content as according the regex, we
            # expect a string if MODEL[key][1] is a string. But the list will
            # contain dictionaries or string if MODEL[key][1] is a tuple
            if self.__class__.MODEL[key][0] is list:
                if isinstance(self.__class__.MODEL[key][1], (str, bytes)):
                    # List values can be only string
                    if not all([isinstance(v, (str, bytes)) for v in value]):
                        raise ResourceInvalidException(
                            "Resource [type: %s, ID: %s] has an "
                            "invalid key (%s) data content (expected "
                            "a string)" % (
                                self.__class__.MODEL_TYPE,
                                self.id,
                                key))
                    if not all([re.match(self.__class__.MODEL[key][1], v)
                                for v in value]):
                        raise ResourceInvalidException(
                            "Resource [type: %s, ID: %s] has an "
                            "invalid key (%s) data content (expected "
                            "match : %s)" % (
                                self.__class__.MODEL_TYPE,
                                self.id,
                                key,
                                self.__class__.MODEL[key][1]))
                else:
                    # We assume self.__class__.MODEL[key][1] is tuple. List
                    # values can be dict or list
                    for v in value:
                        if isinstance(v, (str, bytes)):
                            if not re.match(
                                    self.__class__.MODEL[key][1][1], v):
                                raise ResourceInvalidException(
                                    "Resource [type: %s, ID: %s] has an "
                                    "invalid key (%s) data content (expected "
                                    "match : %s)" % (
                                        self.__class__.MODEL_TYPE,
                                        self.id,
                                        key,
                                        self.__class__.MODEL[key][1][1]))
                        elif isinstance(v, dict):
                            if not len(v.keys()) == 1:
                                raise ResourceInvalidException(
                                    "Resource [type: %s, ID: %s] has an "
                                    "invalid key (%s) data content. List "
                                    "contains a dictionary with multiple "
                                    "keys" % (
                                        self.__class__.MODEL_TYPE,
                                        self.id,
                                        key))
                            if not re.match(
                                    self.__class__.MODEL[key][1][1],
                                    list(v.keys())[0]):
                                raise ResourceInvalidException(
                                    "Resource [type: %s, ID: %s] has an "
                                    "invalid key (%s) data content (expected "
                                    "match : %s)" % (
                                        self.__class__.MODEL_TYPE,
                                        self.id,
                                        key,
                                        self.__class__.MODEL[key][1]))
                        else:
                            raise ResourceInvalidException(
                                "Resource [type: %s, ID: %s] key %s contains "
                                "unsuported data type. Please check the "
                                " model." % (self.__class__.MODEL_TYPE,
                                             self.id, key))
            # For dict type validate the content as according the regex
            if self.__class__.MODEL[key][0] is dict:
                try:
                    for k, v in value.items():
                        assert isinstance(k, str)
                        try:
                            assert isinstance(v, str)
                        except Exception:
                            if (not isinstance(v, bool) and
                                    not isinstance(v, int)):
                                raise AssertionError()
                except Exception:
                    raise ResourceInvalidException(
                        "Resource [type: %s, ID: %s] has an invalid "
                        "key (%s) dict keys or values not valid" % (
                            self.__class__.MODEL_TYPE,
                            self.id,
                            key))
                key_re = re.compile(self.__class__.MODEL[key][1][0])
                val_re = re.compile(self.__class__.MODEL[key][1][1])
                if not all([all([key_re.match(k),
                                self.val_validate(v, val_re)]) for
                            k, v in value.items()]):
                    raise ResourceInvalidException(
                        "Resource [type: %s, ID: %s] has an invalid "
                        "key (%s) dict key, value (expected match : %s)" % (
                            self.__class__.MODEL_TYPE,
                            self.id,
                            key,
                            self.__class__.MODEL[key][1]))

    def is_mutable(self, key):
        return self.__class__.MODEL[key][4]

    def get_deps(self, keyname=False):
        """ Return a dictionnary of {rtype: set([ids, ])} that list
        resource instance dependencies. eg. a given
        resource field requires another resource to be validated, or
        applied. Note that dependencies between resources of the
        same type cannot exists.

        If keyname is set to True then this method should return
        the key name of the resource that contains dependency ids.
        """
        if keyname:
            return ''
        return {}

    def is_deps_soft(self):
        """ If this returns True contraints dependencies check become
        soft. That means resources ids returned by get_deps won't be
        checked for existence.
        """
        return False

    def set_defaults(self, soft=False):
        """ Enrich the data MODEL. This method add
        missing fields to the resource. Missing fields are
        initialized with their default value.
        If soft is True then only default value that is data (not [] or '')
        will be added as default value.
        """
        for key, constraints in self.__class__.MODEL.items():
            if key not in self.resource:
                if soft and not constraints[3]:
                    continue
                self.resource[key] = constraints[3]

    def get_resource(self):
        return self.resource

    def should_be_updated(self):
        """ Is the resource should be updated by inheritance
        if one of the resources it depends on (only one
        rtype possible) has been updated.
        """
        return True

    def transform_for_get(self):
        """ This method can be overwritten to format of the resource
        when a get on the resource tree is asked.
        """
        return self.resource
