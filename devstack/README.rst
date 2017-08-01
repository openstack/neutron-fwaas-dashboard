===========================================
DevStack plugin for neutron-fwaas-dashboard
===========================================

This is setup as a DevStack plugin.
For more information on DevStack plugins,
see the `DevStack Plugins documentation
<https://docs.openstack.org/devstack/latest/plugins.html>`__.

How to enable FWaaS v1 dsashboard
---------------------------------

Add the following to the localrc section of your local.conf.
You need to configure FWaaS v1 DevStack plugin as well.

If ``q-fwaas-v1`` (or ``q-fwaas``) is enabled,
FWaaS v1 dashboard ``neutron-fwaas-v1-dashboard`` is automatically enabled.

.. code-block:: none

   [[local|localrc]]
   enable_plugin neutron-fwaas https://git.openstack.org/openstack/neutron-fwaas master
   enable_service q-fwaas-v1
   enable_plugin neutron-fwaas-dashboard https://git.openstack.org/openstack/neutron-fwaas-dashboard master

If you run horizon in a separate server from neutron server and
neutron-fwaas is not configured,
``neutron-fwaas-v1-dashboard`` is enabled by default.

How to enable FWaaS v2 dsashboard
---------------------------------

Coming soon.
