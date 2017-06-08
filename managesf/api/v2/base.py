#
# Copyright (C) 2017 eNovance SAS <licensing@enovance.com>
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


def paginate(func):
    """Decorator facility to automatically paginate GET outputs"""
    def _f(**kwargs):
        try:
            skipped = int(kwargs.get('skip', 0))
        except ValueError:
            raise ValueError('Invalid starting index')
        try:
            limit = int(kwargs.get('limit', 25))
        except ValueError:
            raise ValueError('Invalid limit')
        if skipped < 0:
            raise ValueError('Invalid starting index')
        if limit < 0:
            raise ValueError('Invalid limit')
        try:
            results, total = func(**kwargs)
        except ValueError:
            results = func(**kwargs)
            total = len(results)
        if not total:
            total = len(results)
        # results is expected to be ordered in one way or an other
        if len(results) > limit:
            results = results[skipped: skipped + limit]
        return {'total': total,
                'skipped': skipped,
                'limit': limit,
                'results': results}
    return _f
