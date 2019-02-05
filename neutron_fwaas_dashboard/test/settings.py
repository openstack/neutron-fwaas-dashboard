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

# Default to Horizons test settings to avoid any missing keys
from horizon.test.settings import *  # noqa
from openstack_dashboard.test.settings import *  # noqa

import openstack_dashboard.enabled
from openstack_dashboard.utils import settings

import neutron_fwaas_dashboard.enabled

# pop these keys to avoid log warnings about deprecation
# update_dashboards will populate them anyway
HORIZON_CONFIG.pop('dashboards', None)
HORIZON_CONFIG.pop('default_dashboard', None)

# Update the dashboards with neutron_fwaas_dashboard
settings.update_dashboards(
    [
        openstack_dashboard.enabled,
        neutron_fwaas_dashboard.enabled,
    ],
    HORIZON_CONFIG,
    INSTALLED_APPS
)

# Ensure any duplicate apps are removed after the update_dashboards call
INSTALLED_APPS = list(set(INSTALLED_APPS))

# --------------------
# Test-only settings
# --------------------
# TEST_GLOBAL_MOCKS_ON_PANELS: defines what and how methods should be
# mocked globally for unit tests and Selenium tests.
# 'method' is required. 'return_value' and 'side_effect'
# are optional and passed to mock.patch().
TEST_GLOBAL_MOCKS_ON_PANELS['firewalls_v2'] = {
    'method': ('neutron_fwaas_dashboard.dashboards.project.firewalls_v2.panel.'
               'Firewall_V2.can_access'),
    'return_value': True,
}
