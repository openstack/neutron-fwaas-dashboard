===========================================
DevStack plugin for neutron-fwaas-dashboard
===========================================

This is setup as a DevStack plugin.
For more information on DevStack plugins,
see the `DevStack Plugins documentation
<https://docs.openstack.org/developer/devstack/plugins.html>`__.

Common to FWaaS v1 and v2 dashboard
-----------------------------------

If neutron-fwaas-dashboard DevStack plugin is enabled,
Neutron FWaaS dashboard is automatically enabled and
the appropriate version of FWaaS panel is displayed based on
the FWaaS version enabled in your neutron server.
You do not need to specify FWaaS API version in the DevStack plugin
configuration.

How to enable FWaaS v2 dsashboard
---------------------------------

Add the following to the localrc section of your local.conf.

.. code-block:: none

   [[local|localrc]]
   enable_plugin neutron-fwaas https://git.openstack.org/openstack/neutron-fwaas master
   enable_service q-fwaas-v2
   enable_plugin neutron-fwaas-dashboard https://git.openstack.org/openstack/neutron-fwaas-dashboard master

How to enable FWaaS v1 dsashboard
---------------------------------

Add the following to the localrc section of your local.conf.

.. code-block:: none

   [[local|localrc]]
   enable_plugin neutron-fwaas https://git.openstack.org/openstack/neutron-fwaas master
   enable_service q-fwaas-v1
   enable_plugin neutron-fwaas-dashboard https://git.openstack.org/openstack/neutron-fwaas-dashboard master
