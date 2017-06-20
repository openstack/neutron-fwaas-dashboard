#    Copyright 2017, Juniper Networks.
#
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

from neutronclient.v2_0.client import Client as neutronclient

from neutron_fwaas_dashboard.api import fwaas_v2 as api_fwaas_v2
from neutron_fwaas_dashboard.test import helpers as test


class FwaasV2ApiTests(test.APITestCase):
    @test.create_stubs({neutronclient: ('create_fwaas_firewall_rule',)})
    def test_rule_create(self):
        rule1 = self.fw_rules_v2.first()
        rule1_dict = self.api_fw_rules_v2.first()
        form_data = {'name': rule1.name,
                     'description': rule1.description,
                     'protocol': rule1.protocol,
                     'action': rule1.action,
                     'source_ip_address': rule1.source_ip_address,
                     'source_port': rule1.source_port,
                     'destination_ip_address': rule1.destination_ip_address,
                     'destination_port': rule1.destination_port,
                     'shared': rule1.shared,
                     'enabled': rule1.enabled
                     }
        form_dict = {'firewall_rule': form_data}
        ret_dict = {'firewall_rule': rule1_dict}
        neutronclient.create_fwaas_firewall_rule(form_dict).AndReturn(ret_dict)
        self.mox.ReplayAll()

        ret_val = api_fwaas_v2.rule_create(self.request, **form_data)
        self._assert_rule_return_value(ret_val, rule1)

    def _assert_rule_return_value(self, ret_val, exp_rule):
        self.assertIsInstance(ret_val, api_fwaas_v2.Rule)
        self.assertEqual(exp_rule.name, ret_val.name)
        self.assertTrue(ret_val.id)

    @test.create_stubs({neutronclient: ('list_fwaas_firewall_rules',)})
    def test_rule_list(self):
        exp_rules = self.fw_rules_v2.list()
        api_rules = {'firewall_rules': self.api_fw_rules_v2.list()}

        neutronclient.list_fwaas_firewall_rules().AndReturn(api_rules)
        self.mox.ReplayAll()

        ret_val = api_fwaas_v2.rule_list(self.request)
        for (v, d) in zip(ret_val, exp_rules):
            self._assert_rule_return_value(v, d)

    @test.create_stubs({neutronclient: ('list_fwaas_firewall_rules',)})
    def test_rule_list_for_tenant(self):
        tenant_id = self.request.user.project_id
        exp_rules = self.fw_rules_v2.list()
        api_rules = {'firewall_rules': self.api_fw_rules_v2.list()}

        neutronclient.list_fwaas_firewall_rules(
            tenant_id=tenant_id,
            shared=False).AndReturn({'firewall_rules': []})
        neutronclient.list_fwaas_firewall_rules(shared=True) \
            .AndReturn(api_rules)
        self.mox.ReplayAll()

        ret_val = api_fwaas_v2.rule_list_for_tenant(self.request, tenant_id)
        for (v, d) in zip(ret_val, exp_rules):
            self._assert_rule_return_value(v, d)

    @test.create_stubs({neutronclient: ('show_fwaas_firewall_rule',)})
    def test_rule_get(self):
        exp_rule = self.fw_rules_v2.first()
        ret_dict = {'firewall_rule': self.api_fw_rules_v2.first()}

        neutronclient.show_fwaas_firewall_rule(exp_rule.id).AndReturn(ret_dict)
        self.mox.ReplayAll()

        ret_val = api_fwaas_v2.rule_get(self.request, exp_rule.id)
        self._assert_rule_return_value(ret_val, exp_rule)

    @test.create_stubs({neutronclient: ('update_fwaas_firewall_rule',)})
    def test_rule_update(self):
        rule = self.fw_rules_v2.first()
        rule_dict = self.api_fw_rules_v2.first()

        rule.name = 'new name'
        rule.description = 'new desc'
        rule.protocol = 'icmp'
        rule.action = 'deny'
        rule.shared = True
        rule.enabled = False

        rule_dict['name'] = 'new name'
        rule_dict['description'] = 'new desc'
        rule_dict['protocol'] = 'icmp'
        rule_dict['action'] = 'deny'
        rule_dict['shared'] = True
        rule_dict['enabled'] = False

        form_data = {'name': rule.name,
                     'description': rule.description,
                     'protocol': rule.protocol,
                     'action': rule.action,
                     'shared': rule.shared,
                     'enabled': rule.enabled
                     }
        form_dict = {'firewall_rule': form_data}
        ret_dict = {'firewall_rule': rule_dict}

        neutronclient.update_fwaas_firewall_rule(
            rule.id, form_dict).AndReturn(ret_dict)
        self.mox.ReplayAll()

        ret_val = api_fwaas_v2.rule_update(self.request,
                                           rule.id, **form_data)
        self._assert_rule_return_value(ret_val, rule)

    @test.create_stubs({neutronclient: ('create_fwaas_firewall_policy', )})
    def test_policy_create(self):
        policy1 = self.fw_policies_v2.first()
        policy1_dict = self.api_fw_policies_v2.first()

        form_data = {'name': policy1.name,
                     'description': policy1.description,
                     'firewall_rules': policy1.firewall_rules,
                     'shared': policy1.shared,
                     'audited': policy1.audited
                     }
        form_dict = {'firewall_policy': form_data}
        ret_dict = {'firewall_policy': policy1_dict}

        neutronclient.create_fwaas_firewall_policy(form_dict).\
            AndReturn(ret_dict)
        self.mox.ReplayAll()

        ret_val = api_fwaas_v2.policy_create(self.request, **form_data)
        self.assertIsInstance(ret_val, api_fwaas_v2.Policy)
        self.assertEqual(policy1.name, ret_val.name)
        self.assertTrue(ret_val.id)

    def _assert_policy_return_value(self, ret_val, exp_policy):
        self.assertIsInstance(ret_val, api_fwaas_v2.Policy)
        self.assertEqual(exp_policy.name, ret_val.name)
        self.assertTrue(ret_val.id)
        self.assertEqual(len(exp_policy.firewall_rules), len(ret_val.rules))
        self.assertEqual(len(exp_policy.firewall_rules),
                         len(ret_val.firewall_rules))
        for (r, exp_r) in zip(ret_val.rules, exp_policy.rules):
            self.assertEqual(exp_r.id, r.id)

    @test.create_stubs({neutronclient: ('list_fwaas_firewall_policies',
                                        'list_fwaas_firewall_rules')})
    def test_policy_list(self):
        exp_policies = self.fw_policies_v2.list()
        policies_dict = {'firewall_policies': self.api_fw_policies_v2.list()}
        rules_dict = {'firewall_rules': self.api_fw_rules_v2.list()}

        neutronclient.list_fwaas_firewall_policies().AndReturn(policies_dict)
        neutronclient.list_fwaas_firewall_rules().AndReturn(rules_dict)
        self.mox.ReplayAll()

        ret_val = api_fwaas_v2.policy_list(self.request)
        for (v, d) in zip(ret_val, exp_policies):
            self._assert_policy_return_value(v, d)

    @test.create_stubs({neutronclient: ('list_fwaas_firewall_policies',
                                        'list_fwaas_firewall_rules')})
    def test_policy_list_for_tenant(self):
        tenant_id = self.request.user.project_id
        exp_policies = self.fw_policies_v2.list()
        policies_dict = {'firewall_policies': self.api_fw_policies_v2.list()}
        rules_dict = {'firewall_rules': self.api_fw_rules_v2.list()}

        neutronclient.list_fwaas_firewall_policies(
            tenant_id=tenant_id,
            shared=False).AndReturn({'firewall_policies': []})
        neutronclient.list_fwaas_firewall_policies(
            shared=True).AndReturn(policies_dict)
        neutronclient.list_fwaas_firewall_rules().AndReturn(rules_dict)
        self.mox.ReplayAll()

        ret_val = api_fwaas_v2.policy_list_for_tenant(self.request, tenant_id)
        for (v, d) in zip(ret_val, exp_policies):
            self._assert_policy_return_value(v, d)

    @test.create_stubs({neutronclient: ('show_fwaas_firewall_policy',
                                        'list_fwaas_firewall_rules')})
    def test_policy_get(self):
        exp_policy = self.fw_policies_v2.first()
        policy_dict = self.api_fw_policies_v2.first()
        # The first two rules are associated with the first policy.
        api_rules = self.api_fw_rules_v2.list()[:2]

        ret_dict = {'firewall_policy': policy_dict}
        neutronclient.show_fwaas_firewall_policy(
            exp_policy.id).AndReturn(ret_dict)
        filters = {'firewall_policy_id': exp_policy.id}
        ret_dict = {'firewall_rules': api_rules}
        neutronclient.list_fwaas_firewall_rules(**filters).AndReturn(ret_dict)
        self.mox.ReplayAll()

        ret_val = api_fwaas_v2.policy_get(self.request, exp_policy.id)
        self._assert_policy_return_value(ret_val, exp_policy)

    @test.create_stubs({neutronclient: ('show_fwaas_firewall_policy',)})
    def test_policy_get_no_rule(self):
        # 2nd policy is not associated with any rules.
        exp_policy = self.fw_policies_v2.list()[1]
        policy_dict = self.api_fw_policies_v2.list()[1]

        ret_dict = {'firewall_policy': policy_dict}
        neutronclient.show_fwaas_firewall_policy(
            exp_policy.id).AndReturn(ret_dict)
        self.mox.ReplayAll()

        ret_val = api_fwaas_v2.policy_get(self.request, exp_policy.id)
        self.assertIsInstance(ret_val, api_fwaas_v2.Policy)
        self.assertEqual(exp_policy.name, ret_val.name)
        self.assertTrue(ret_val.id)
        self.assertFalse(len(ret_val.rules))

    @test.create_stubs({neutronclient: ('update_fwaas_firewall_policy',)})
    def test_policy_update(self):
        policy = self.fw_policies_v2.first()
        policy_dict = self.api_fw_policies_v2.first()

        policy.name = 'new name'
        policy.description = 'new desc'
        policy.shared = True
        policy.audited = False

        policy_dict['name'] = 'new name'
        policy_dict['description'] = 'new desc'
        policy_dict['shared'] = True
        policy_dict['audited'] = False

        form_data = {'name': policy.name,
                     'description': policy.description,
                     'shared': policy.shared,
                     'audited': policy.audited
                     }

        form_dict = {'firewall_policy': form_data}
        ret_dict = {'firewall_policy': policy_dict}

        neutronclient.update_fwaas_firewall_policy(
            policy.id, form_dict).AndReturn(ret_dict)
        self.mox.ReplayAll()

        ret_val = api_fwaas_v2.policy_update(self.request,
                                             policy.id, **form_data)
        self.assertIsInstance(ret_val, api_fwaas_v2.Policy)
        self.assertEqual(policy.name, ret_val.name)
        self.assertTrue(ret_val.id)

    @test.create_stubs({neutronclient: ('insert_rule_fwaas_firewall_policy',)})
    def test_policy_insert_rule(self):
        policy = self.fw_policies_v2.first()
        policy_dict = self.api_fw_policies_v2.first()

        new_rule_id = 'h0881d38-c3eb-4fee-9763-12de3338041d'
        policy.firewall_rules.append(new_rule_id)
        policy_dict['firewall_rules'].append(new_rule_id)

        body = {'firewall_rule_id': new_rule_id,
                'insert_before': policy.firewall_rules[1],
                'insert_after': policy.firewall_rules[0]}

        neutronclient.insert_rule_fwaas_firewall_policy(
            policy.id, body).AndReturn(policy_dict)
        self.mox.ReplayAll()

        ret_val = api_fwaas_v2.policy_insert_rule(self.request,
                                                  policy.id, **body)
        self.assertIn(new_rule_id, ret_val.firewall_rules)

    @test.create_stubs({neutronclient: ('remove_rule_fwaas_firewall_policy',)})
    def test_policy_remove_rule(self):
        policy = self.fw_policies_v2.first()
        policy_dict = self.api_fw_policies_v2.first()

        remove_rule_id = policy.firewall_rules[0]
        policy_dict['firewall_rules'].remove(remove_rule_id)

        body = {'firewall_rule_id': remove_rule_id}

        neutronclient.remove_rule_fwaas_firewall_policy(
            policy.id, body).AndReturn(policy_dict)
        self.mox.ReplayAll()

        ret_val = api_fwaas_v2.policy_remove_rule(self.request,
                                                  policy.id, **body)
        self.assertNotIn(remove_rule_id, ret_val.firewall_rules)

    @test.create_stubs({neutronclient: ('create_fwaas_firewall_group', )})
    def test_firewall_group_create(self):
        firewall_group = self.firewall_groups_v2.first()
        firewall_group_dict = self.api_firewall_groups_v2.first()

        form_data = {
            'name': firewall_group.name,
            'description': firewall_group.description,
            'ingress_firewall_policy_id':
            firewall_group.ingress_firewall_policy_id,
            'egress_firewall_policy_id':
            firewall_group.egress_firewall_policy_id,
            'admin_state_up': firewall_group.admin_state_up
        }

        form_dict = {'firewall_group': form_data}
        ret_dict = {'firewall_group': firewall_group_dict}
        neutronclient.create_fwaas_firewall_group(
            form_dict).AndReturn(ret_dict)
        self.mox.ReplayAll()

        ret_val = api_fwaas_v2.firewall_group_create(self.request, **form_data)
        self.assertIsInstance(ret_val, api_fwaas_v2.FirewallGroup)
        self.assertEqual(firewall_group.name, ret_val.name)
        self.assertEqual(firewall_group.id, ret_val.id)

    def _assert_firewall_return_value(self, ret_val, exp_firewall,
                                      expand_policy=True):
        self.assertIsInstance(ret_val, api_fwaas_v2.FirewallGroup)
        self.assertEqual(exp_firewall.name, ret_val.name)
        self.assertTrue(ret_val.id)
        self.assertEqual(exp_firewall.ingress_firewall_policy_id,
                         ret_val.ingress_firewall_policy_id)
        if expand_policy:
            if exp_firewall.ingress_firewall_policy_id:
                self.assertEqual(exp_firewall.ingress_firewall_policy_id,
                                 ret_val.ingress_policy.id)
                self.assertEqual(exp_firewall.ingress_policy.name,
                                 ret_val.ingress_policy.name)
            else:
                self.assertIsNone(ret_val.ingress_policy)
            if exp_firewall.egress_firewall_policy_id:
                self.assertEqual(exp_firewall.egress_firewall_policy_id,
                                 ret_val.egress_policy.id)
                self.assertEqual(exp_firewall.egress_policy.name,
                                 ret_val.egress_policy.name)
            else:
                self.assertIsNone(ret_val.egress_policy)

    # TODO(Sarath Mekala) : Add API tests for firewall_group_create with ports,
    #                  add port to firewall and remove port from fw.

    @test.create_stubs({neutronclient: ('list_fwaas_firewall_groups',
                                        'list_fwaas_firewall_policies')})
    def test_firewall_list(self):
        exp_firewalls = self.firewall_groups_v2.list()
        firewalls_dict = {
            'firewall_groups': self.api_firewall_groups_v2.list()}

        neutronclient.list_fwaas_firewall_groups().AndReturn(firewalls_dict)
        self.mox.ReplayAll()

        ret_val = api_fwaas_v2.firewall_list(self.request)
        for (v, d) in zip(ret_val, exp_firewalls):
            self._assert_firewall_return_value(v, d, expand_policy=False)

    @test.create_stubs({neutronclient: ('list_fwaas_firewall_groups',
                                        'list_fwaas_firewall_policies')})
    def test_firewall_list_for_tenant(self):
        tenant_id = self.request.user.project_id
        exp_firewalls = self.firewall_groups_v2.list()
        firewalls_dict = {
            'firewall_groups': self.api_firewall_groups_v2.list()}

        neutronclient.list_fwaas_firewall_groups(shared=False, tenant_id=tenant_id) \
            .AndReturn(firewalls_dict)
        neutronclient.list_fwaas_firewall_groups(shared=True) \
            .AndReturn(firewalls_dict)
        self.mox.ReplayAll()
        ret_val = api_fwaas_v2.firewall_list_for_tenant(
            self.request, tenant_id)
        for (v, d) in zip(ret_val, exp_firewalls):
            self._assert_firewall_return_value(v, d, expand_policy=False)

    @test.create_stubs({neutronclient: ('list_ports',
                                        'list_fwaas_firewall_groups')})
    def test_fwg_port_list_for_tenant(self):
        tenant_id = self.request.user.project_id
        router_port = {
            'id': 'id-1',
            'name': 'port-1',
            'device_owner': 'network:router_interface'
        }
        vm_port1 = {
            'id': 'id-vm_port-1',
            'name': 'port-2',
            'device_owner': 'compute:nova'
        }
        vm_port2 = {
            'id': 'id-vm_port-2',
            'name': 'port-2',
            'device_owner': 'compute:nova'
        }
        gateway_port = {
            'id': 'id-3',
            'name': 'port-3',
            'device_owner': 'network:router_gateway'
        }
        dhcp_port = {
            'id': 'id-4',
            'name': 'port-4',
            'device_owner': 'network:dhcp'
        }
        dummy_ports = {'ports': [
            router_port,
            vm_port1,
            vm_port2,
            gateway_port,
            dhcp_port,
        ]}

        neutronclient.list_ports(tenant_id=tenant_id).AndReturn(dummy_ports)
        neutronclient.list_fwaas_firewall_groups(
            tenant_id=tenant_id).AndReturn({'firewall_groups': []})
        self.mox.ReplayAll()
        ports = api_fwaas_v2.fwg_port_list_for_tenant(self.request, tenant_id)
        self.assertEqual(router_port['id'], ports[0]['id'])
        self.assertEqual(vm_port1['id'], ports[1]['id'])
        self.assertEqual(vm_port2['id'], ports[2]['id'])

    @test.create_stubs({neutronclient: ('list_ports',
                                        'list_fwaas_firewall_groups')})
    def test_fwg_port_list_for_tenant_with_used_port(self):
        tenant_id = self.request.user.project_id
        router_port = {
            'id': 'id-1',
            'name': 'port-1',
            'device_owner': 'network:router_interface'
        }
        vm_port1 = {
            'id': 'id-vm_port-1',
            'name': 'port-2',
            'device_owner': 'compute:nova'
        }
        gateway_port = {
            'id': 'id-3',
            'name': 'port-3',
            'device_owner': 'network:router_gateway'
        }
        dhcp_port = {
            'id': 'id-4',
            'name': 'port-4',
            'device_owner': 'network:dhcp'
        }
        dummy_ports = {'ports': [
            router_port,
            vm_port1,
            gateway_port,
            dhcp_port,
        ]}

        used_ports = {'firewall_groups': [{'ports': [router_port['id']]}]}

        neutronclient.list_ports(tenant_id=tenant_id).AndReturn(dummy_ports)
        neutronclient.list_fwaas_firewall_groups(
            tenant_id=tenant_id).AndReturn(used_ports)
        self.mox.ReplayAll()
        ports = api_fwaas_v2.fwg_port_list_for_tenant(self.request, tenant_id)
        self.assertEqual(vm_port1['id'], ports[0]['id'])

    @test.create_stubs({neutronclient: ('list_ports',
                                        'list_fwaas_firewall_groups')})
    def test_fwg_port_list_for_tenant_no_match(self):
        tenant_id = self.request.user.project_id
        dummy_ports = {'ports': [
            {'name': 'port-3', 'device_owner': 'network:router_gateway'},
            {'name': 'port-4', 'device_owner': 'network:dhcp'},
        ]}
        neutronclient.list_ports(tenant_id=tenant_id).AndReturn(dummy_ports)
        neutronclient.list_fwaas_firewall_groups(
            tenant_id=tenant_id).AndReturn({'firewall_groups': []})
        self.mox.ReplayAll()
        ports = api_fwaas_v2.fwg_port_list_for_tenant(self.request, tenant_id)
        self.assertEqual([], ports)

    @test.create_stubs({neutronclient: ('list_ports',
                                        'list_fwaas_firewall_groups')})
    def test_fwg_port_list_for_tenant_no_ports(self):
        tenant_id = self.request.user.project_id
        neutronclient.list_ports(tenant_id=tenant_id).AndReturn({'ports': []})
        neutronclient.list_fwaas_firewall_groups(
            tenant_id=tenant_id).AndReturn({'firewall_groups': []})
        self.mox.ReplayAll()
        ports = api_fwaas_v2.fwg_port_list_for_tenant(self.request, tenant_id)
        self.assertEqual([], ports)

    @test.create_stubs({neutronclient: ('show_fwaas_firewall_group',
                                        'show_fwaas_firewall_policy')})
    def test_firewall_get(self):
        exp_firewall = self.firewall_groups_v2.first()
        ret_dict = {'firewall_group': self.api_firewall_groups_v2.first()}

        ingress_policy_id = exp_firewall.ingress_firewall_policy_id
        ingress_policy = [p for p in self.api_fw_policies_v2.list()
                          if p['id'] == ingress_policy_id][0]

        egress_policy_id = exp_firewall.egress_firewall_policy_id
        egress_policy = [p for p in self.api_fw_policies_v2.list()
                         if p['id'] == egress_policy_id][0]

        neutronclient.show_fwaas_firewall_group(
            exp_firewall.id).AndReturn(ret_dict)
        neutronclient.show_fwaas_firewall_policy(ingress_policy_id)\
            .AndReturn({'firewall_policy': ingress_policy})
        neutronclient.show_fwaas_firewall_policy(egress_policy_id)\
            .AndReturn({'firewall_policy': egress_policy})
        self.mox.ReplayAll()

        ret_val = api_fwaas_v2.firewall_get(self.request, exp_firewall.id)
        self._assert_firewall_return_value(ret_val, exp_firewall)

    @test.create_stubs({neutronclient: ('update_fwaas_firewall_group',)})
    def test_firewall_update(self):
        firewall = self.firewall_groups_v2.first()
        firewall_dict = self.api_firewall_groups_v2.first()

        firewall.name = 'new name'
        firewall.description = 'new desc'
        firewall.admin_state_up = False

        firewall_dict['name'] = 'new name'
        firewall_dict['description'] = 'new desc'
        firewall_dict['admin_state_up'] = False

        form_data = {'name': firewall.name,
                     'description': firewall.description,
                     'admin_state_up': firewall.admin_state_up
                     }

        form_dict = {'firewall_group': form_data}
        ret_dict = {'firewall_group': firewall_dict}

        neutronclient.update_fwaas_firewall_group(
            firewall.id, form_dict).AndReturn(ret_dict)
        self.mox.ReplayAll()

        ret_val = api_fwaas_v2.firewall_update(self.request,
                                               firewall.id, **form_data)
        self.assertIsInstance(ret_val, api_fwaas_v2.FirewallGroup)
        self.assertEqual(firewall.name, ret_val.name)
        self.assertTrue(ret_val.id)
