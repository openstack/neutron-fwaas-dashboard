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

# FEATURE just declares this enabled file needs to be loaded.
# This is required for ADD_INSTALLED_APPS to be processed.
# The value itself has no meaning in the current horizon.
FEATURE = 'neutron-fwaas-dashboard'

ADD_INSTALLED_APPS = ['neutron_fwaas_dashboard']
AUTO_DISCOVER_STATIC_FILES = True
ADD_SCSS_FILES = ['neutron_fwaas_dashboard/scss/firewalls.scss']
