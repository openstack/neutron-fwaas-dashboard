..
      Copyright 2017 OpenStack Foundation
      All Rights Reserved.

      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.

============
Installation
============

Manual Installation
-------------------

Before installing neutron-fwaas-dashboard,
you first need to install horizon in your environment.

Fetch the source code from git and run pip install.
Make sure to install neutron-fwaas-dashboard into the same python environment
where horizon is installed.

.. code-block:: console

   $ git clone https://git.openstack.org//openstack/neutron-fwaas-dashboard
   $ cd neutron-fwaas-dashboard
   $ sudo pip install .

Enable the horizon plugin.

.. code-block:: console

   $ cp neutron_fwaas_dashboard/enabled/_70*_*.py \
         /opt/stack/horizon/openstack_dashboard/local/enabled/

.. note::

   The directory ``local/enabled`` may be different depending on your
   environment or distribution used. For example, for Ubuntu, this is
   ``/usr/share/openstack-dashboard/openstack_dashboard/local/enabled``.

.. note::

   The number of the plugin enabled file determines the order of panels.
   If you would like to configure the place of the Neutron FWaaS dashboard,
   change the number of the file.

.. note::

   For more detail of the horizon plugin settings,
   see `Pluggable Settings
   <https://docs.openstack.org/horizon/latest/configuration/pluggable_panels.html>`__
   in the horizon documentation.

Configure the policy file for Neutron FWaaS dashboard
in OpenStack Dashboard ``local_settings.py``.
``<fwaas-dashboard-config-dir>`` is a directory which contains
configurations for Neutron FWaaS dashboard and the locaiton varies
across distributions or deployments.

.. code-block:: python

   POLICY_FILES['neutron-fwaas'] = '<fwaas-dashboard-config-dir>/etc/neutron-fwaas-policy.json'

.. note::

   If you do not configure ``POLICY_FILES`` in your ``local_settings.py``,
   you also need to define the default ``POLICY_FILES`` in
   ``local_settings.py``. If you use the example ``local_settings.py`` file
   from horizon, what you need is to uncomment ``POLICY_FILES`` (which contains
   the default values).

Compile the message catalogs of Neutron FWaaS dashboard.

.. code-block:: console

   $ cd neutron-fwaas-dashboard
   $ ./manage.py compilemessages

Run the Django update commands (if you use).

.. code-block:: console

   $ DJANGO_SETTINGS_MODULE=openstack_dashboard.settings python manage.py collectstatic --noinput
   $ DJANGO_SETTINGS_MODULE=openstack_dashboard.settings python manage.py compress --force

Restart Apache:

.. code-block:: console

   $ sudo service apache2 restart
