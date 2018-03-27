#    Copyright 2013, Big Switch Networks, Inc.
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

import mock
from neutronclient.v2_0.client import Client as neutronclient
from openstack_dashboard.api import neutron as api_neutron
from openstack_dashboard.test import helpers

from neutron_fwaas_dashboard.api import fwaas as api_fwaas
from neutron_fwaas_dashboard.test import helpers as test


class FwaasApiTests(test.APITestCase):

    use_mox = False

    @helpers.create_mocks({neutronclient: ('create_firewall_rule',)})
    def test_rule_create(self):
        rule1 = self.fw_rules.first()
        rule1_dict = self.api_fw_rules.first()
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
        self.mock_create_firewall_rule.return_value = ret_dict

        ret_val = api_fwaas.rule_create(self.request, **form_data)

        self.assertIsInstance(ret_val, api_fwaas.Rule)
        self.assertEqual(rule1.name, ret_val.name)
        self.assertTrue(ret_val.id)
        self.mock_create_firewall_rule.assert_called_once_with(form_dict)

    def _assert_rule_return_value(self, ret_val, exp_rule):
        self.assertIsInstance(ret_val, api_fwaas.Rule)
        self.assertEqual(exp_rule.name, ret_val.name)
        self.assertTrue(ret_val.id)
        if exp_rule.policy:
            self.assertEqual(exp_rule.firewall_policy_id, ret_val.policy.id)
            self.assertEqual(exp_rule.policy.name, ret_val.policy.name)
        else:
            self.assertIsNone(ret_val.policy)

    @helpers.create_mocks({neutronclient: ('list_firewall_rules',
                                           'list_firewall_policies')})
    def test_rule_list(self):
        exp_rules = self.fw_rules.list()
        api_rules = {'firewall_rules': self.api_fw_rules.list()}
        api_policies = {'firewall_policies': self.api_fw_policies.list()}

        self.mock_list_firewall_rules.return_value = api_rules
        self.mock_list_firewall_policies.return_value = api_policies

        ret_val = api_fwaas.rule_list(self.request)
        for (v, d) in zip(ret_val, exp_rules):
            self._assert_rule_return_value(v, d)
        self.mock_list_firewall_rules.assert_called_once_with()
        self.mock_list_firewall_policies.assert_called_once_with()

    @helpers.create_mocks({neutronclient: ('list_firewall_rules',
                                           'list_firewall_policies')})
    def test_rule_list_for_tenant(self):
        tenant_id = self.request.user.project_id
        exp_rules = self.fw_rules.list()
        api_rules = {'firewall_rules': self.api_fw_rules.list()}
        api_policies = {'firewall_policies': self.api_fw_policies.list()}

        self.mock_list_firewall_rules.side_effect = [
            {'firewall_rules': []},
            api_rules,
        ]
        self.mock_list_firewall_policies.return_value = api_policies

        ret_val = api_fwaas.rule_list_for_tenant(self.request, tenant_id)

        for (v, d) in zip(ret_val, exp_rules):
            self._assert_rule_return_value(v, d)
        self.assertEqual(2, self.mock_list_firewall_rules.call_count)
        self.mock_list_firewall_rules.assert_has_calls([
            mock.call(tenant_id=tenant_id, shared=False),
            mock.call(shared=True),
        ])
        self.mock_list_firewall_policies.assert_called_once_with()

    @helpers.create_mocks({neutronclient: ('show_firewall_rule',
                                           'show_firewall_policy')})
    def test_rule_get(self):
        exp_rule = self.fw_rules.first()
        ret_dict = {'firewall_rule': self.api_fw_rules.first()}
        policy_dict = {'firewall_policy': self.api_fw_policies.first()}

        self.mock_show_firewall_rule.return_value = ret_dict
        self.mock_show_firewall_policy.return_value = policy_dict

        ret_val = api_fwaas.rule_get(self.request, exp_rule.id)

        self._assert_rule_return_value(ret_val, exp_rule)
        self.mock_show_firewall_rule.assert_called_once_with(exp_rule.id)
        self.mock_show_firewall_policy.assert_called_once_with(
            exp_rule.firewall_policy_id)

    @helpers.create_mocks({neutronclient: ('update_firewall_rule',)})
    def test_rule_update(self):
        rule = self.fw_rules.first()
        rule_dict = self.api_fw_rules.first()

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

        self.mock_update_firewall_rule.return_value = ret_dict

        ret_val = api_fwaas.rule_update(self.request,
                                        rule.id, **form_data)
        self.assertIsInstance(ret_val, api_fwaas.Rule)
        self.assertEqual(rule.name, ret_val.name)
        self.assertTrue(ret_val.id)
        self.mock_update_firewall_rule.assert_called_once_with(rule.id,
                                                               form_dict)

    @helpers.create_mocks({neutronclient: ('create_firewall_policy', )})
    def test_policy_create(self):
        policy1 = self.fw_policies.first()
        policy1_dict = self.api_fw_policies.first()

        form_data = {'name': policy1.name,
                     'description': policy1.description,
                     'firewall_rules': policy1.firewall_rules,
                     'shared': policy1.shared,
                     'audited': policy1.audited
                     }
        form_dict = {'firewall_policy': form_data}
        ret_dict = {'firewall_policy': policy1_dict}

        self.mock_create_firewall_policy.return_value = ret_dict

        ret_val = api_fwaas.policy_create(self.request, **form_data)
        self.assertIsInstance(ret_val, api_fwaas.Policy)
        self.assertEqual(policy1.name, ret_val.name)
        self.assertTrue(ret_val.id)
        self.mock_create_firewall_policy.assert_called_once_with(form_dict)

    def _assert_policy_return_value(self, ret_val, exp_policy):
        self.assertIsInstance(ret_val, api_fwaas.Policy)
        self.assertEqual(exp_policy.name, ret_val.name)
        self.assertTrue(ret_val.id)
        self.assertEqual(len(exp_policy.firewall_rules), len(ret_val.rules))
        self.assertEqual(len(exp_policy.firewall_rules),
                         len(ret_val.firewall_rules))
        for (r, exp_r) in zip(ret_val.rules, exp_policy.rules):
            self.assertEqual(exp_r.id, r.id)

    @helpers.create_mocks({neutronclient: ('list_firewall_policies',
                                           'list_firewall_rules')})
    def test_policy_list(self):
        exp_policies = self.fw_policies.list()
        policies_dict = {'firewall_policies': self.api_fw_policies.list()}
        rules_dict = {'firewall_rules': self.api_fw_rules.list()}

        self.mock_list_firewall_policies.return_value = policies_dict
        self.mock_list_firewall_rules.return_value = rules_dict

        ret_val = api_fwaas.policy_list(self.request)
        for (v, d) in zip(ret_val, exp_policies):
            self._assert_policy_return_value(v, d)
        self.mock_list_firewall_policies.assert_called_once_with()
        self.mock_list_firewall_rules.assert_called_once_with()

    @helpers.create_mocks({neutronclient: ('list_firewall_policies',
                                           'list_firewall_rules')})
    def test_policy_list_for_tenant(self):
        tenant_id = self.request.user.project_id
        exp_policies = self.fw_policies.list()
        policies_dict = {'firewall_policies': self.api_fw_policies.list()}
        rules_dict = {'firewall_rules': self.api_fw_rules.list()}

        self.mock_list_firewall_policies.side_effect = [
            {'firewall_policies': []},
            policies_dict,
        ]
        self.mock_list_firewall_rules.return_value = rules_dict

        ret_val = api_fwaas.policy_list_for_tenant(self.request, tenant_id)
        for (v, d) in zip(ret_val, exp_policies):
            self._assert_policy_return_value(v, d)
        self.assertEqual(2, self.mock_list_firewall_policies.call_count)
        self.mock_list_firewall_policies.assert_has_calls([
            mock.call(tenant_id=tenant_id, shared=False),
            mock.call(shared=True),
        ])
        self.mock_list_firewall_rules.assert_called_once_with()

    @helpers.create_mocks({neutronclient: ('show_firewall_policy',
                                           'list_firewall_rules')})
    def test_policy_get(self):
        exp_policy = self.fw_policies.first()
        policy_dict = self.api_fw_policies.first()
        # The first two rules are associated with the first policy.
        api_rules = self.api_fw_rules.list()[:2]

        ret_dict = {'firewall_policy': policy_dict}
        self.mock_show_firewall_policy.return_value = ret_dict
        filters = {'firewall_policy_id': exp_policy.id}
        ret_dict = {'firewall_rules': api_rules}
        self.mock_list_firewall_rules.return_value = ret_dict

        ret_val = api_fwaas.policy_get(self.request, exp_policy.id)
        self._assert_policy_return_value(ret_val, exp_policy)
        self.mock_show_firewall_policy.assert_called_once_with(exp_policy.id)
        self.mock_list_firewall_rules.assert_called_once_with(**filters)

    @helpers.create_mocks({neutronclient: ('show_firewall_policy',)})
    def test_policy_get_no_rule(self):
        # 2nd policy is not associated with any rules.
        exp_policy = self.fw_policies.list()[1]
        policy_dict = self.api_fw_policies.list()[1]

        ret_dict = {'firewall_policy': policy_dict}
        self.mock_show_firewall_policy.return_value = ret_dict

        ret_val = api_fwaas.policy_get(self.request, exp_policy.id)
        self.assertIsInstance(ret_val, api_fwaas.Policy)
        self.assertEqual(exp_policy.name, ret_val.name)
        self.assertTrue(ret_val.id)
        self.assertFalse(len(ret_val.rules))
        self.mock_show_firewall_policy.assert_called_once_with(exp_policy.id)

    @helpers.create_mocks({neutronclient: ('update_firewall_policy',)})
    def test_policy_update(self):
        policy = self.fw_policies.first()
        policy_dict = self.api_fw_policies.first()

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

        self.mock_update_firewall_policy.return_value = ret_dict

        ret_val = api_fwaas.policy_update(self.request,
                                          policy.id, **form_data)
        self.assertIsInstance(ret_val, api_fwaas.Policy)
        self.assertEqual(policy.name, ret_val.name)
        self.assertTrue(ret_val.id)
        self.mock_update_firewall_policy.assert_called_once_with(
            policy.id, form_dict)

    @helpers.create_mocks({neutronclient: ('firewall_policy_insert_rule',)})
    def test_policy_insert_rule(self):
        policy = self.fw_policies.first()
        policy_dict = self.api_fw_policies.first()

        new_rule_id = 'h0881d38-c3eb-4fee-9763-12de3338041d'
        policy.firewall_rules.append(new_rule_id)
        policy_dict['firewall_rules'].append(new_rule_id)

        body = {'firewall_rule_id': new_rule_id,
                'insert_before': policy.firewall_rules[1],
                'insert_after': policy.firewall_rules[0]}

        self.mock_firewall_policy_insert_rule.return_value = policy_dict

        ret_val = api_fwaas.policy_insert_rule(self.request,
                                               policy.id, **body)
        self.assertIn(new_rule_id, ret_val.firewall_rules)
        self.mock_firewall_policy_insert_rule.assert_called_once_with(
            policy.id, body)

    @helpers.create_mocks({neutronclient: ('firewall_policy_remove_rule',)})
    def test_policy_remove_rule(self):
        policy = self.fw_policies.first()
        policy_dict = self.api_fw_policies.first()

        remove_rule_id = policy.firewall_rules[0]
        policy_dict['firewall_rules'].remove(remove_rule_id)

        body = {'firewall_rule_id': remove_rule_id}

        self.mock_firewall_policy_remove_rule.return_value = policy_dict

        ret_val = api_fwaas.policy_remove_rule(self.request,
                                               policy.id, **body)
        self.assertNotIn(remove_rule_id, ret_val.firewall_rules)
        self.mock_firewall_policy_remove_rule.assert_called_once_with(
            policy.id, body)

    @helpers.create_mocks({neutronclient: ('create_firewall', )})
    def test_firewall_create(self):
        firewall = self.firewalls.first()
        firewall_dict = self.api_firewalls.first()

        form_data = {'name': firewall.name,
                     'description': firewall.description,
                     'firewall_policy_id': firewall.firewall_policy_id,
                     'admin_state_up': firewall.admin_state_up
                     }

        form_dict = {'firewall': form_data}
        ret_dict = {'firewall': firewall_dict}
        self.mock_create_firewall.return_value = ret_dict

        ret_val = api_fwaas.firewall_create(self.request, **form_data)
        self.assertIsInstance(ret_val, api_fwaas.Firewall)
        self.assertEqual(firewall.name, ret_val.name)
        self.assertTrue(ret_val.id)
        self.mock_create_firewall.assert_called_once_with(form_dict)

    def _assert_firewall_return_value(self, ret_val, exp_firewall):
        self.assertIsInstance(ret_val, api_fwaas.Firewall)
        self.assertEqual(exp_firewall.name, ret_val.name)
        self.assertTrue(ret_val.id)
        self.assertEqual(exp_firewall.firewall_policy_id, ret_val.policy.id)
        self.assertEqual(exp_firewall.policy.name, ret_val.policy.name)

    # TODO(absubram) : Add API tests for firewall_create with routers,
    #                  add router to firewall and remove router from fw.

    @helpers.create_mocks({neutronclient: ('list_firewalls',
                                           'list_firewall_policies'),
                           api_neutron: ('is_extension_supported',
                                         'router_list')})
    def test_firewall_list(self):
        exp_firewalls = self.firewalls.list()
        firewalls_dict = {'firewalls': self.api_firewalls.list()}
        policies_dict = {'firewall_policies': self.api_fw_policies.list()}

        self.mock_list_firewalls.return_value = firewalls_dict
        self.mock_list_firewall_policies.return_value = policies_dict
        self.mock_is_extension_supported.return_value = True
        self.mock_router_list.return_value = self.routers.list()

        ret_val = api_fwaas.firewall_list(self.request)
        for (v, d) in zip(ret_val, exp_firewalls):
            self._assert_firewall_return_value(v, d)
        self.mock_list_firewalls.assert_called_once_with()
        self.mock_list_firewall_policies.assert_called_once_with()
        self.mock_is_extension_supported.assert_called_once_with(
            helpers.IsHttpRequest(), 'fwaasrouterinsertion')
        self.mock_router_list.assert_called_once_with(
            helpers.IsHttpRequest())

    @helpers.create_mocks({neutronclient: ('list_firewalls',
                                           'list_firewall_policies'),
                           api_neutron: ('is_extension_supported',
                                         'router_list')})
    def test_firewall_list_for_tenant(self):
        tenant_id = self.request.user.project_id
        exp_firewalls = self.firewalls.list()
        firewalls_dict = {'firewalls': self.api_firewalls.list()}
        policies_dict = {'firewall_policies': self.api_fw_policies.list()}

        self.mock_list_firewalls.return_value = firewalls_dict
        self.mock_list_firewall_policies.return_value = policies_dict
        self.mock_is_extension_supported.return_value = True
        self.mock_router_list.return_value = self.routers.list()

        ret_val = api_fwaas.firewall_list_for_tenant(self.request, tenant_id)
        for (v, d) in zip(ret_val, exp_firewalls):
            self._assert_firewall_return_value(v, d)

        self.mock_list_firewalls.assert_called_once_with(tenant_id=tenant_id)
        self.mock_list_firewall_policies.assert_called_once_with()
        self.mock_is_extension_supported.assert_called_once_with(
            helpers.IsHttpRequest(), 'fwaasrouterinsertion')
        self.mock_router_list.assert_called_once_with(
            helpers.IsHttpRequest(), tenant_id=self.request.user.project_id)

    @helpers.create_mocks({neutronclient: ('show_firewall',
                                           'show_firewall_policy'),
                           api_neutron: ('is_extension_supported',
                                         'router_list')})
    def test_firewall_get(self):
        exp_firewall = self.firewalls.first()
        ret_dict = {'firewall': self.api_firewalls.first()}
        policy_dict = {'firewall_policy': self.api_fw_policies.first()}

        self.mock_show_firewall.return_value = ret_dict
        self.mock_show_firewall_policy.return_value = policy_dict
        self.mock_is_extension_supported.return_value = True
        self.mock_router_list.return_value = exp_firewall.routers

        ret_val = api_fwaas.firewall_get(self.request, exp_firewall.id)
        self._assert_firewall_return_value(ret_val, exp_firewall)
        self.assertEqual(exp_firewall.router_ids, ret_val.router_ids)
        self.assertEqual(exp_firewall.router_ids,
                         [r.id for r in ret_val.routers])
        self.assertEqual([r.name for r in exp_firewall.routers],
                         [r.name for r in ret_val.routers])
        self.mock_show_firewall.assert_called_once_with(exp_firewall.id)
        self.mock_show_firewall_policy.assert_called_once_with(
            exp_firewall.firewall_policy_id)
        self.mock_is_extension_supported.assert_called_once_with(
            helpers.IsHttpRequest(), 'fwaasrouterinsertion')
        self.mock_router_list.assert_called_once_with(
            helpers.IsHttpRequest(), id=exp_firewall.router_ids)

    @helpers.create_mocks({neutronclient: ('update_firewall',)})
    def test_firewall_update(self):
        firewall = self.firewalls.first()
        firewall_dict = self.api_firewalls.first()

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

        form_dict = {'firewall': form_data}
        ret_dict = {'firewall': firewall_dict}

        self.mock_update_firewall.return_value = ret_dict

        ret_val = api_fwaas.firewall_update(self.request,
                                            firewall.id, **form_data)
        self.assertIsInstance(ret_val, api_fwaas.Firewall)
        self.assertEqual(firewall.name, ret_val.name)
        self.assertTrue(ret_val.id)
        self.mock_update_firewall.assert_called_once_with(firewall.id,
                                                          form_dict)
