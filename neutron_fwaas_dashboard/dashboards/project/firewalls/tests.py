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

from django.urls import reverse

from openstack_dashboard import api
from openstack_dashboard.test import helpers

from neutron_fwaas_dashboard.api import fwaas as api_fwaas
from neutron_fwaas_dashboard.test import helpers as test


class FirewallTests(test.TestCase):

    use_mox = False

    DASHBOARD = 'project'
    INDEX_URL = reverse('horizon:%s:firewalls:index' % DASHBOARD)

    ADDRULE_PATH = 'horizon:%s:firewalls:addrule' % DASHBOARD
    ADDPOLICY_PATH = 'horizon:%s:firewalls:addpolicy' % DASHBOARD
    ADDFIREWALL_PATH = 'horizon:%s:firewalls:addfirewall' % DASHBOARD

    RULE_DETAIL_PATH = 'horizon:%s:firewalls:ruledetails' % DASHBOARD
    POLICY_DETAIL_PATH = 'horizon:%s:firewalls:policydetails' % DASHBOARD
    FIREWALL_DETAIL_PATH = 'horizon:%s:firewalls:firewalldetails' % DASHBOARD

    UPDATERULE_PATH = 'horizon:%s:firewalls:updaterule' % DASHBOARD
    UPDATEPOLICY_PATH = 'horizon:%s:firewalls:updatepolicy' % DASHBOARD
    UPDATEFIREWALL_PATH = 'horizon:%s:firewalls:updatefirewall' % DASHBOARD

    INSERTRULE_PATH = 'horizon:%s:firewalls:insertrule' % DASHBOARD
    REMOVERULE_PATH = 'horizon:%s:firewalls:removerule' % DASHBOARD

    ADDROUTER_PATH = 'horizon:%s:firewalls:addrouter' % DASHBOARD
    REMOVEROUTER_PATH = 'horizon:%s:firewalls:removerouter' % DASHBOARD

    def setup_mocks(self, fwaas_router_extension=True):
        policies = self.fw_policies.list()
        firewalls = self.firewalls.list()
        routers = self.routers.list()

        self.mock_is_extension_supported.return_value = fwaas_router_extension
        self.mock_rule_list_for_tenant.return_value = self.fw_rules.list()
        self.mock_policy_list_for_tenant.return_value = policies
        self.mock_firewall_list_for_tenant.return_value = firewalls
        self.mock_firewall_unassociated_routers_list.return_value = routers

    def check_mocks(self, fwaas_router_extension=True):
        tenant_id = self.tenant.id

        self.assert_mock_multiple_calls_with_same_arguments(
            self.mock_is_extension_supported, 5,
            mock.call(helpers.IsHttpRequest(), 'fwaasrouterinsertion'))
        self.mock_rule_list_for_tenant.assert_called_once_with(
            helpers.IsHttpRequest(), tenant_id)
        self.mock_policy_list_for_tenant.assert_called_once_with(
            helpers.IsHttpRequest(), tenant_id)
        self.mock_firewall_list_for_tenant.assert_called_once_with(
            helpers.IsHttpRequest(), tenant_id)
        self.assert_mock_multiple_calls_with_same_arguments(
            self.mock_firewall_unassociated_routers_list, 2,
            mock.call(helpers.IsHttpRequest(), tenant_id))

    def setup_mocks_with_exception(self):
        self.mock_is_extension_supported.return_value = True
        self.mock_rule_list_for_tenant.side_effect = self.exceptions.neutron
        self.mock_policy_list_for_tenant.side_effect = self.exceptions.neutron
        self.mock_firewall_list_for_tenant.side_effect = \
            self.exceptions.neutron

    def check_mocks_with_exception(self):
        tenant_id = self.tenant.id

        self.mock_is_extension_supported.assert_called_once_with(
            helpers.IsHttpRequest(), 'fwaasrouterinsertion')
        self.mock_rule_list_for_tenant.assert_called_once_with(
            helpers.IsHttpRequest(), tenant_id)
        self.mock_policy_list_for_tenant.assert_called_once_with(
            helpers.IsHttpRequest(), tenant_id)
        self.mock_firewall_list_for_tenant.assert_called_once_with(
            helpers.IsHttpRequest(), tenant_id)

    @helpers.create_mocks({api_fwaas: ('firewall_list_for_tenant',
                                       'policy_list_for_tenant',
                                       'rule_list_for_tenant',
                                       'firewall_unassociated_routers_list',),
                           api.neutron: ('is_extension_supported',), })
    def test_index_firewalls(self):
        self.setup_mocks()

        tenant_id = self.tenant.id

        res = self.client.get(self.INDEX_URL, tenant_id=tenant_id)

        self.assertTemplateUsed(res, '%s/firewalls/details_tabs.html'
                                % self.DASHBOARD)
        self.assertTemplateUsed(res, 'horizon/common/_detail_table.html')
        self.assertEqual(len(res.context['table'].data),
                         len(self.firewalls.list()))
        self.check_mocks()

    # TODO(absubram): Change test_index_firewalls for with and without
    #                 router extensions.

    @helpers.create_mocks({api_fwaas: ('firewall_list_for_tenant',
                                       'policy_list_for_tenant',
                                       'rule_list_for_tenant',
                                       'firewall_unassociated_routers_list',),
                           api.neutron: ('is_extension_supported',), })
    def test_index_policies(self):
        self.setup_mocks()

        tenant_id = self.tenant.id

        res = self.client.get(self.INDEX_URL + '?tab=fwtabs__policies',
                              tenant_id=tenant_id)

        self.assertTemplateUsed(res, '%s/firewalls/details_tabs.html'
                                % self.DASHBOARD)
        self.assertTemplateUsed(res, 'horizon/common/_detail_table.html')
        self.assertEqual(len(res.context['policiestable_table'].data),
                         len(self.fw_policies.list()))
        self.check_mocks()

    @helpers.create_mocks({api_fwaas: ('firewall_list_for_tenant',
                                       'policy_list_for_tenant',
                                       'rule_list_for_tenant',
                                       'firewall_unassociated_routers_list',),
                           api.neutron: ('is_extension_supported',), })
    def test_index_rules(self):
        self.setup_mocks()

        tenant_id = self.tenant.id

        res = self.client.get(self.INDEX_URL + '?tab=fwtabs__rules',
                              tenant_id=tenant_id)

        self.assertTemplateUsed(res, '%s/firewalls/details_tabs.html'
                                % self.DASHBOARD)
        self.assertTemplateUsed(res, 'horizon/common/_detail_table.html')
        self.assertEqual(len(res.context['rulestable_table'].data),
                         len(self.fw_rules.list()))
        self.check_mocks()

    @helpers.create_mocks({api_fwaas: ('firewall_list_for_tenant',
                                       'policy_list_for_tenant',
                                       'rule_list_for_tenant'),
                           api.neutron: ('is_extension_supported',), })
    def test_index_exception_firewalls(self):
        self.setup_mocks_with_exception()

        tenant_id = self.tenant.id

        res = self.client.get(self.INDEX_URL, tenant_id=tenant_id)

        self.assertTemplateUsed(res,
                                '%s/firewalls/details_tabs.html'
                                % self.DASHBOARD)
        self.assertTemplateUsed(res,
                                'horizon/common/_detail_table.html')
        self.assertEqual(len(res.context['table'].data), 0)
        self.check_mocks_with_exception()

    @helpers.create_mocks({api_fwaas: ('firewall_list_for_tenant',
                                       'policy_list_for_tenant',
                                       'rule_list_for_tenant'),
                           api.neutron: ('is_extension_supported',), })
    def test_index_exception_policies(self):
        self.setup_mocks_with_exception()

        tenant_id = self.tenant.id

        res = self.client.get(self.INDEX_URL + '?tab=fwtabs__policies',
                              tenant_id=tenant_id)

        self.assertTemplateUsed(res,
                                '%s/firewalls/details_tabs.html'
                                % self.DASHBOARD)
        self.assertTemplateUsed(res,
                                'horizon/common/_detail_table.html')
        self.assertEqual(len(res.context['policiestable_table'].data), 0)
        self.check_mocks_with_exception()

    @helpers.create_mocks({api_fwaas: ('firewall_list_for_tenant',
                                       'policy_list_for_tenant',
                                       'rule_list_for_tenant'),
                           api.neutron: ('is_extension_supported',), })
    def test_index_exception_rules(self):
        self.setup_mocks_with_exception()

        tenant_id = self.tenant.id

        res = self.client.get(self.INDEX_URL + '?tab=fwtabs__rules',
                              tenant_id=tenant_id)

        self.assertTemplateUsed(res,
                                '%s/firewalls/details_tabs.html'
                                % self.DASHBOARD)
        self.assertTemplateUsed(res,
                                'horizon/common/_detail_table.html')
        self.assertEqual(len(res.context['rulestable_table'].data), 0)
        self.check_mocks_with_exception()

    @helpers.create_mocks({api_fwaas: ('rule_create',), })
    def test_add_rule_post(self):
        rule1 = self.fw_rules.first()

        form_data = {'name': rule1.name,
                     'description': rule1.description,
                     'protocol': rule1.protocol,
                     'action': rule1.action,
                     'source_ip_address': rule1.source_ip_address,
                     'source_port': rule1.source_port,
                     'destination_ip_address': rule1.destination_ip_address,
                     'destination_port': rule1.destination_port,
                     'shared': rule1.shared,
                     'enabled': rule1.enabled,
                     'ip_version': rule1.ip_version
                     }

        self.mock_rule_create.return_value = rule1

        res = self.client.post(reverse(self.ADDRULE_PATH), form_data)

        self.assertNoFormErrors(res)
        self.assertRedirectsNoFollow(res, str(self.INDEX_URL))
        self.mock_rule_create.assert_called_once_with(
            helpers.IsHttpRequest(), **form_data)

    @helpers.create_mocks({api_fwaas: ('rule_create',), })
    def test_add_rule_post_src_None(self):
        rule1 = self.fw_rules.first()
        form_data = {'name': rule1.name,
                     'description': rule1.description,
                     'protocol': rule1.protocol,
                     'action': rule1.action,
                     'destination_ip_address': rule1.destination_ip_address,
                     'destination_port': rule1.destination_port,
                     'shared': rule1.shared,
                     'enabled': rule1.enabled,
                     'ip_version': rule1.ip_version
                     }

        self.mock_rule_create.return_value = rule1

        res = self.client.post(reverse(self.ADDRULE_PATH), form_data)

        self.assertNoFormErrors(res)
        self.assertRedirectsNoFollow(res, str(self.INDEX_URL))
        data = form_data.copy()
        data['source_ip_address'] = None
        data['source_port'] = None
        self.mock_rule_create.assert_called_once_with(
            helpers.IsHttpRequest(), **data)

    @helpers.create_mocks({api_fwaas: ('rule_create',), })
    def test_add_rule_post_dest_None(self):
        rule1 = self.fw_rules.first()
        form_data = {'name': rule1.name,
                     'description': rule1.description,
                     'protocol': rule1.protocol,
                     'action': rule1.action,
                     'source_ip_address': rule1.source_ip_address,
                     'source_port': rule1.source_port,
                     'shared': rule1.shared,
                     'enabled': rule1.enabled,
                     'ip_version': rule1.ip_version
                     }

        self.mock_rule_create.return_value = rule1

        res = self.client.post(reverse(self.ADDRULE_PATH), form_data)

        self.assertNoFormErrors(res)
        self.assertRedirectsNoFollow(res, str(self.INDEX_URL))
        data = form_data.copy()
        data['destination_ip_address'] = None
        data['destination_port'] = None
        self.mock_rule_create.assert_called_once_with(
            helpers.IsHttpRequest(), **data)

    def test_add_rule_post_with_error(self):
        rule1 = self.fw_rules.first()

        form_data = {'name': rule1.name,
                     'description': rule1.description,
                     'protocol': 'abc',
                     'action': 'pass',
                     'source_ip_address': rule1.source_ip_address,
                     'source_port': rule1.source_port,
                     'destination_ip_address': rule1.destination_ip_address,
                     'destination_port': rule1.destination_port,
                     'shared': rule1.shared,
                     'enabled': rule1.enabled,
                     'ip_version': 6
                     }

        res = self.client.post(reverse(self.ADDRULE_PATH), form_data)

        self.assertFormErrors(res, 3)

    @helpers.create_mocks({api_fwaas: ('policy_create',
                                       'rule_list_for_tenant'), })
    def test_add_policy_post(self):
        policy = self.fw_policies.first()
        rules = self.fw_rules.list()
        tenant_id = self.tenant.id
        form_data = {'name': policy.name,
                     'description': policy.description,
                     'firewall_rules': policy.firewall_rules,
                     'shared': policy.shared,
                     'audited': policy.audited
                     }
        post_data = {'name': policy.name,
                     'description': policy.description,
                     'rule': policy.firewall_rules,
                     'shared': policy.shared,
                     'audited': policy.audited
                     }

        # NOTE: SelectRulesAction.populate_rule_choices() lists rule not
        # associated with any policy. We need to ensure that rules specified
        # in policy.firewall_rules in post_data (above) are not associated
        # with any policy. Test data in neutron_data is data in a stable state,
        # so we need to modify here.
        for rule in rules:
            if rule.id in policy.firewall_rules:
                rule.firewall_policy_id = rule.policy = None
        self.mock_rule_list_for_tenant.return_value = rules
        self.mock_policy_create.return_value = policy

        res = self.client.post(reverse(self.ADDPOLICY_PATH), post_data)

        self.assertNoFormErrors(res)
        self.assertRedirectsNoFollow(res, str(self.INDEX_URL))
        self.mock_rule_list_for_tenant.assert_called_once_with(
            helpers.IsHttpRequest(), tenant_id)
        self.mock_policy_create.assert_called_once_with(
            helpers.IsHttpRequest(), **form_data)

    @helpers.create_mocks({api_fwaas: ('rule_list_for_tenant',), })
    def test_add_policy_post_with_error(self):
        policy = self.fw_policies.first()
        rules = self.fw_rules.list()
        tenant_id = self.tenant.id
        form_data = {'description': policy.description,
                     'firewall_rules': None,
                     'shared': policy.shared,
                     'audited': policy.audited
                     }
        self.mock_rule_list_for_tenant.return_value = rules

        res = self.client.post(reverse(self.ADDPOLICY_PATH), form_data)

        self.assertFormErrors(res, 1)
        self.mock_rule_list_for_tenant.assert_called_once_with(
            helpers.IsHttpRequest(), tenant_id)

    @helpers.create_mocks({api_fwaas: ('firewall_create',
                                       'policy_list_for_tenant',
                                       'firewall_list_for_tenant',),
                           api.neutron: ('is_extension_supported',
                                         'router_list'), })
    def _test_add_firewall_post(self, router_extension=False):
        firewall = self.firewalls.first()
        policies = self.fw_policies.list()
        tenant_id = self.tenant.id
        if router_extension:
            routers = self.routers.list()
            firewalls = self.firewalls.list()

        form_data = {'name': firewall.name,
                     'description': firewall.description,
                     'firewall_policy_id': firewall.firewall_policy_id,
                     'admin_state_up': firewall.admin_state_up
                     }
        data = form_data.copy()
        if router_extension:
            # Lookup for unassociated router(s)
            associated = []
            for fw in firewalls:
                associated += fw.router_ids
            unassociated = [r.id for r in routers if r.id not in associated]
            form_data['router'] = unassociated
            data['router_ids'] = unassociated
            self.mock_router_list.return_value = routers
            self.mock_firewall_list_for_tenant.return_value = firewalls

        self.mock_is_extension_supported.return_value = router_extension
        self.mock_policy_list_for_tenant.return_value = policies
        self.mock_firewall_create.return_value = firewall

        res = self.client.post(reverse(self.ADDFIREWALL_PATH), form_data)

        self.assertNoFormErrors(res)
        # self.assertRedirectsNoFollow(res, str(self.INDEX_URL))

        if router_extension:
            self.mock_router_list.assert_called_once_with(
                helpers.IsHttpRequest(), tenant_id=tenant_id)
            self.mock_firewall_list_for_tenant.assert_called_once_with(
                helpers.IsHttpRequest(), tenant_id=tenant_id)
        else:
            self.mock_router_list.assert_not_called()
            self.mock_firewall_list_for_tenant.assert_not_called()

        self.mock_is_extension_supported.assert_called_once_with(
            helpers.IsHttpRequest(), 'fwaasrouterinsertion')
        self.mock_policy_list_for_tenant.assert_called_once_with(
            helpers.IsHttpRequest(), tenant_id)
        self.mock_firewall_create.assert_called_once_with(
            helpers.IsHttpRequest(), **data)

    def test_add_firewall_post(self):
        self._test_add_firewall_post()

    def test_add_firewall_post_with_router_extension(self):
        self._test_add_firewall_post(router_extension=True)

    @helpers.create_mocks({api_fwaas: ('policy_list_for_tenant',),
                           api.neutron: ('is_extension_supported',), })
    def test_add_firewall_post_with_error(self):
        firewall = self.firewalls.first()
        policies = self.fw_policies.list()
        tenant_id = self.tenant.id
        form_data = {'name': firewall.name,
                     'description': firewall.description,
                     'firewall_policy_id': None,
                     'admin_state_up': firewall.admin_state_up
                     }
        self.mock_is_extension_supported.return_value = False
        self.mock_policy_list_for_tenant.return_value = policies

        res = self.client.post(reverse(self.ADDFIREWALL_PATH), form_data)

        self.assertFormErrors(res, 1)
        self.mock_is_extension_supported.assert_called_once_with(
            helpers.IsHttpRequest(), 'fwaasrouterinsertion')
        self.mock_policy_list_for_tenant.assert_called_once_with(
            helpers.IsHttpRequest(), tenant_id)

    @helpers.create_mocks({api_fwaas: ('rule_get',)})
    def test_update_rule_get(self):
        rule = self.fw_rules.first()

        self.mock_rule_get.return_value = rule

        res = self.client.get(reverse(self.UPDATERULE_PATH, args=(rule.id,)))

        self.assertTemplateUsed(res, 'project/firewalls/updaterule.html')
        self.mock_rule_get.assert_called_once_with(helpers.IsHttpRequest(),
                                                   rule.id)

    @helpers.create_mocks({api_fwaas: ('rule_get', 'rule_update')})
    def test_update_rule_post(self):
        rule = self.fw_rules.first()

        self.mock_rule_get.return_value = rule

        data = {'name': 'new name',
                'description': 'new desc',
                'protocol': 'icmp',
                'action': 'allow',
                'shared': False,
                'enabled': True,
                'ip_version': rule.ip_version,
                'source_ip_address': rule.source_ip_address,
                'destination_ip_address': None,
                'source_port': None,
                'destination_port': rule.destination_port,
                }

        self.mock_rule_update.return_value = rule

        form_data = data.copy()
        form_data['destination_ip_address'] = ''
        form_data['source_port'] = ''

        res = self.client.post(
            reverse(self.UPDATERULE_PATH, args=(rule.id,)), form_data)

        self.assertNoFormErrors(res)
        self.assertRedirectsNoFollow(res, str(self.INDEX_URL))

        self.mock_rule_get.assert_called_once_with(
            helpers.IsHttpRequest(), rule.id)
        self.mock_rule_update.assert_called_once_with(
            helpers.IsHttpRequest(), rule.id, **data)

    @helpers.create_mocks({api_fwaas: ('rule_get', 'rule_update')})
    def test_update_protocol_any_rule_post(self):
        # protocol any means protocol == None in neutron context.
        rule = self.fw_rules.get(protocol=None)

        self.mock_rule_get.return_value = rule
        self.mock_rule_update.return_value = rule

        data = {'name': 'new name',
                'description': 'new desc',
                'protocol': 'icmp',
                'action': 'allow',
                'shared': False,
                'enabled': True,
                'ip_version': rule.ip_version,
                'source_ip_address': rule.source_ip_address,
                'destination_ip_address': None,
                'source_port': None,
                'destination_port': rule.destination_port,
                }

        form_data = data.copy()
        form_data['destination_ip_address'] = ''
        form_data['source_port'] = ''

        res = self.client.post(
            reverse(self.UPDATERULE_PATH, args=(rule.id,)), form_data)

        self.assertNoFormErrors(res)
        self.assertRedirectsNoFollow(res, str(self.INDEX_URL))

        self.mock_rule_get.assert_called_once_with(
            helpers.IsHttpRequest(), rule.id)
        self.mock_rule_update.assert_called_once_with(
            helpers.IsHttpRequest(), rule.id, **data)

    @helpers.create_mocks({api_fwaas: ('rule_get', 'rule_update')})
    def test_update_rule_protocol_to_any_post(self):
        rule = self.fw_rules.first()

        self.mock_rule_get.return_value = rule
        self.mock_rule_update.return_value = rule

        data = {'name': 'new name',
                'description': 'new desc',
                'protocol': None,
                'action': 'allow',
                'shared': False,
                'enabled': True,
                'ip_version': rule.ip_version,
                'source_ip_address': rule.source_ip_address,
                'destination_ip_address': None,
                'source_port': None,
                'destination_port': rule.destination_port,
                }

        form_data = data.copy()
        form_data['destination_ip_address'] = ''
        form_data['source_port'] = ''
        form_data['protocol'] = 'any'

        res = self.client.post(
            reverse(self.UPDATERULE_PATH, args=(rule.id,)), form_data)

        self.assertNoFormErrors(res)
        self.assertRedirectsNoFollow(res, str(self.INDEX_URL))

        self.mock_rule_get.assert_called_once_with(
            helpers.IsHttpRequest(), rule.id)
        self.mock_rule_update.assert_called_once_with(
            helpers.IsHttpRequest(), rule.id, **data)

    @helpers.create_mocks({api_fwaas: ('policy_get',)})
    def test_update_policy_get(self):
        policy = self.fw_policies.first()

        self.mock_policy_get.return_value = policy

        res = self.client.get(
            reverse(self.UPDATEPOLICY_PATH, args=(policy.id,)))

        self.assertTemplateUsed(res, 'project/firewalls/updatepolicy.html')

        self.mock_policy_get.assert_called_once_with(
            helpers.IsHttpRequest(), policy.id)

    @helpers.create_mocks({api_fwaas: ('policy_get', 'policy_update')})
    def test_update_policy_post(self):
        policy = self.fw_policies.first()

        self.mock_policy_get.return_value = policy
        self.mock_policy_update.return_value = policy

        data = {'name': 'new name',
                'description': 'new desc',
                'shared': True,
                'audited': False
                }

        res = self.client.post(
            reverse(self.UPDATEPOLICY_PATH, args=(policy.id,)), data)

        self.assertNoFormErrors(res)
        self.assertRedirectsNoFollow(res, str(self.INDEX_URL))

        self.mock_policy_get.assert_called_once_with(
            helpers.IsHttpRequest(), policy.id)
        self.mock_policy_update.assert_called_once_with(
            helpers.IsHttpRequest(), policy.id, **data)

    @helpers.create_mocks({api_fwaas: ('firewall_get',
                                       'policy_list_for_tenant')})
    def test_update_firewall_get(self):
        firewall = self.firewalls.first()
        policies = self.fw_policies.list()
        tenant_id = self.tenant.id

        self.mock_policy_list_for_tenant.return_value = policies
        self.mock_firewall_get.return_value = firewall

        res = self.client.get(
            reverse(self.UPDATEFIREWALL_PATH, args=(firewall.id,)))

        self.assertTemplateUsed(res, 'project/firewalls/updatefirewall.html')

        self.mock_policy_list_for_tenant.assert_called_once_with(
            helpers.IsHttpRequest(), tenant_id)
        self.mock_firewall_get.assert_called_once_with(
            helpers.IsHttpRequest(), firewall.id)

    @helpers.create_mocks({api_fwaas: ('firewall_get',
                                       'policy_list_for_tenant',
                                       'firewall_update')})
    def test_update_firewall_post(self):
        firewall = self.firewalls.first()
        tenant_id = self.tenant.id
        policies = self.fw_policies.list()
        self.mock_firewall_get.return_value = firewall
        self.mock_policy_list_for_tenant.return_value = policies
        self.mock_firewall_update.return_value = firewall

        data = {'name': 'new name',
                'description': 'new desc',
                'firewall_policy_id': firewall.firewall_policy_id,
                'admin_state_up': False
                }

        res = self.client.post(
            reverse(self.UPDATEFIREWALL_PATH, args=(firewall.id,)), data)

        self.assertNoFormErrors(res)
        self.assertRedirectsNoFollow(res, str(self.INDEX_URL))

        self.mock_firewall_get.assert_called_once_with(
            helpers.IsHttpRequest(), firewall.id)
        self.mock_policy_list_for_tenant.assert_called_once_with(
            helpers.IsHttpRequest(), tenant_id)
        self.mock_firewall_update.assert_called_once_with(
            helpers.IsHttpRequest(), firewall.id, **data)

    @helpers.create_mocks({api_fwaas: ('policy_get',
                                       'policy_insert_rule',
                                       'rule_list_for_tenant',
                                       'rule_get')})
    def test_policy_insert_rule(self):
        policy = self.fw_policies.first()
        tenant_id = self.tenant.id
        rules = self.fw_rules.list()

        new_rule_id = rules[2].id

        data = {'firewall_rule_id': new_rule_id,
                'insert_before': rules[1].id,
                'insert_after': rules[0].id}

        policy.firewall_rules = [rules[0].id,
                                 new_rule_id,
                                 rules[1].id]

        self.mock_policy_get.return_value = policy
        self.mock_rule_list_for_tenant.return_value = rules
        self.mock_rule_get.return_value = rules[2]
        self.mock_policy_insert_rule.return_value = policy

        res = self.client.post(
            reverse(self.INSERTRULE_PATH, args=(policy.id,)), data)

        self.assertNoFormErrors(res)
        self.assertRedirectsNoFollow(res, str(self.INDEX_URL))

        self.mock_policy_get.assert_called_once_with(
            helpers.IsHttpRequest(), policy.id)
        self.mock_rule_list_for_tenant.assert_called_once_with(
            helpers.IsHttpRequest(), tenant_id)
        self.mock_rule_get.assert_called_once_with(
            helpers.IsHttpRequest(), new_rule_id)
        self.mock_policy_insert_rule.assert_called_once_with(
            helpers.IsHttpRequest(), policy.id, **data)

    @helpers.create_mocks({api_fwaas: ('policy_get',
                                       'policy_remove_rule',
                                       'rule_list_for_tenant',
                                       'rule_get')})
    def test_policy_remove_rule(self):
        policy = self.fw_policies.first()
        tenant_id = self.tenant.id
        rules = self.fw_rules.list()

        remove_rule_id = policy.firewall_rules[0]
        left_rule_id = policy.firewall_rules[1]

        data = {'firewall_rule_id': remove_rule_id}

        after_remove_policy_dict = {'id': 'abcdef-c3eb-4fee-9763-12de3338041e',
                                    'tenant_id': '1',
                                    'name': 'policy1',
                                    'description': 'policy description',
                                    'firewall_rules': [left_rule_id],
                                    'audited': True,
                                    'shared': True}
        after_remove_policy = api_fwaas.Policy(after_remove_policy_dict)

        self.mock_policy_get.return_value = policy
        self.mock_rule_list_for_tenant.return_value = rules
        self.mock_rule_get.return_value = rules[0]
        self.mock_policy_remove_rule.return_value = after_remove_policy

        res = self.client.post(
            reverse(self.REMOVERULE_PATH, args=(policy.id,)), data)

        self.assertNoFormErrors(res)
        self.assertRedirectsNoFollow(res, str(self.INDEX_URL))

        self.mock_policy_get.assert_called_once_with(
            helpers.IsHttpRequest(), policy.id)
        self.mock_rule_list_for_tenant.assert_called_once_with(
            helpers.IsHttpRequest(), tenant_id)
        self.mock_rule_get.assert_called_once_with(
            helpers.IsHttpRequest(), remove_rule_id)
        self.mock_policy_remove_rule.assert_called_once_with(
            helpers.IsHttpRequest(), policy.id, **data)

    @helpers.create_mocks({api_fwaas: ('firewall_get',
                                       'firewall_list_for_tenant',
                                       'firewall_update',
                                       'firewall_unassociated_routers_list')})
    def test_firewall_add_router(self):
        tenant_id = self.tenant.id
        firewall = self.firewalls.first()
        routers = self.routers.list()

        existing_router_ids = firewall.router_ids
        add_router_ids = [routers[1].id]

        form_data = {'router_ids': add_router_ids}
        post_data = {'router_ids': add_router_ids + existing_router_ids}

        firewall.router_ids = [add_router_ids, existing_router_ids]

        self.mock_firewall_get.return_value = firewall
        self.mock_firewall_unassociated_routers_list.return_value = routers
        self.mock_firewall_update.return_value = firewall

        res = self.client.post(
            reverse(self.ADDROUTER_PATH, args=(firewall.id,)), form_data)

        self.assertNoFormErrors(res)
        self.assertRedirectsNoFollow(res, str(self.INDEX_URL))

        self.mock_firewall_get.assert_called_once_with(
            helpers.IsHttpRequest(), firewall.id)
        self.mock_firewall_unassociated_routers_list.assert_called_once_with(
            helpers.IsHttpRequest(), tenant_id)
        self.mock_firewall_update.assert_called_once_with(
            helpers.IsHttpRequest(), firewall.id, **post_data)

    @helpers.create_mocks({api_fwaas: ('firewall_get',
                                       'firewall_update'),
                           api.neutron: ('router_list',), })
    def test_firewall_remove_router(self):
        firewall = self.firewalls.first()
        tenant_id = self.tenant.id
        routers = self.routers.list()
        existing_router_ids = firewall.router_ids

        form_data = {'router_ids': existing_router_ids}

        firewall.router_ids = []

        self.mock_firewall_get.return_value = firewall
        self.mock_router_list.return_value = routers
        self.mock_firewall_update.return_value = firewall

        res = self.client.post(
            reverse(self.REMOVEROUTER_PATH, args=(firewall.id,)), form_data)

        self.assertNoFormErrors(res)
        self.assertRedirectsNoFollow(res, str(self.INDEX_URL))

        self.mock_firewall_get.assert_called_once_with(
            helpers.IsHttpRequest(), firewall.id)
        api.neutron.router_list.assert_called_once_with(
            helpers.IsHttpRequest(), tenant_id=tenant_id)
        self.mock_firewall_update.assert_called_once_with(
            helpers.IsHttpRequest(), firewall.id, **form_data)

    @helpers.create_mocks({api_fwaas: ('rule_list_for_tenant',
                                       'rule_delete'),
                           api.neutron: ('is_extension_supported',)})
    def test_delete_rule(self):
        self.mock_is_extension_supported.return_value = True
        self.mock_rule_list_for_tenant.return_value = self.fw_rules.list()
        self.mock_rule_delete.return_value = None

        rule = self.fw_rules.list()[2]
        form_data = {"action": "rulestable__deleterule__%s" % rule.id}
        res = self.client.post(self.INDEX_URL, form_data)

        self.assertNoFormErrors(res)

        self.mock_is_extension_supported.assert_called_once_with(
            helpers.IsHttpRequest(), 'fwaasrouterinsertion')
        self.mock_rule_list_for_tenant.assert_called_once_with(
            helpers.IsHttpRequest(), self.tenant.id)
        self.mock_rule_delete.assert_called_once_with(
            helpers.IsHttpRequest(), rule.id)

    @helpers.create_mocks({api_fwaas: ('policy_list_for_tenant',
                                       'policy_delete'),
                           api.neutron: ('is_extension_supported',)})
    def test_delete_policy(self):
        self.mock_is_extension_supported.return_value = True
        self.mock_policy_list_for_tenant.return_value = self.fw_policies.list()
        self.mock_policy_delete.return_value = None

        policy = self.fw_policies.first()
        form_data = {"action": "policiestable__deletepolicy__%s" % policy.id}
        res = self.client.post(self.INDEX_URL, form_data)

        self.assertNoFormErrors(res)
        api.neutron.is_extension_supported.assert_called_once_with(
            helpers.IsHttpRequest(), 'fwaasrouterinsertion')
        self.mock_policy_list_for_tenant.assert_called_once_with(
            helpers.IsHttpRequest(), self.tenant.id)
        self.mock_policy_delete.assert_called_once_with(
            helpers.IsHttpRequest(), policy.id)

    @helpers.create_mocks({api_fwaas: ('firewall_list_for_tenant',
                                       'firewall_delete'),
                           api.neutron: ('is_extension_supported',)})
    def test_delete_firewall(self):
        fwl = self.firewalls.first()
        self.mock_firewall_list_for_tenant.return_value = [fwl]
        self.mock_firewall_delete.return_value = None
        self.mock_is_extension_supported.return_value = False

        form_data = {"action": "firewallstable__deletefirewall__%s" % fwl.id}
        res = self.client.post(self.INDEX_URL, form_data)

        self.assertNoFormErrors(res)
        self.mock_firewall_list_for_tenant.assert_called_once_with(
            helpers.IsHttpRequest(), self.tenant.id)
        self.mock_firewall_delete.assert_called_once_with(
            helpers.IsHttpRequest(), fwl.id)
        self.mock_is_extension_supported.assert_called_once_with(
            helpers.IsHttpRequest(), 'fwaasrouterinsertion')
