===========================================
DevStack plugin for neutron-fwaas-dashboard
===========================================

This is setup as a DevStack plugin.
For more information on DevStack plugins,
see the `DevStack Plugins documentation
<https://docs.openstack.org/developer/devstack/plugins.html>`__.

If neutron-fwaas-dashboard DevStack plugin is enabled,
Neutron FWaaS dashboard is automatically enabled and
the appropriate version of FWaaS panel is displayed based on
the FWaaS version enabled in your neutron server.
You do not need to specify FWaaS API version in the DevStack plugin
configuration.

To enable FWaaS dashboard, add the following to the localrc section
of your local.conf.

.. code-block:: none

   [[local|localrc]]
   enable_plugin neutron-fwaas https://opendev.org/openstack/neutron-fwaas master
   enable_service q-fwaas-v2
   enable_plugin neutron-fwaas-dashboard https://opendev.org/openstack/neutron-fwaas-dashboard master
