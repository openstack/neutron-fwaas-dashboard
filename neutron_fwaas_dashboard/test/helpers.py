#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from openstack_dashboard.test import helpers

from neutron_fwaas_dashboard.test.test_data import utils


class TestDataLoaderMixin(object):
    def _setup_test_data(self):
        super(TestDataLoaderMixin, self)._setup_test_data()
        utils.load_data(self)


class TestCase(TestDataLoaderMixin, helpers.TestCase):
    pass


class BaseAdminViewTests(TestDataLoaderMixin, helpers.TestCase):
    pass


class APITestCase(TestDataLoaderMixin, helpers.APITestCase):
    pass
