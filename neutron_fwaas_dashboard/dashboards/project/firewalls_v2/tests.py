# Copyright 2017, Juniper Networks, Inc
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

from unittest import mock

from django.urls import reverse

from openstack_dashboard.test import helpers

from neutron_fwaas_dashboard.api import fwaas_v2 as api_fwaas_v2
from neutron_fwaas_dashboard.test import helpers as test


class FirewallTests(test.TestCase):

    INDEX_URL = reverse('horizon:project:firewalls_v2:index')

    ADDRULE_PATH = 'horizon:project:firewalls_v2:addrule'
    ADDPOLICY_PATH = 'horizon:project:firewalls_v2:addpolicy'
    ADDFIREWALLGROUP_PATH = 'horizon:project:firewalls_v2:addfirewallgroup'

    RULE_DETAIL_PATH = 'horizon:project:firewalls_v2:ruledetails'
    POLICY_DETAIL_PATH = 'horizon:project:firewalls_v2:policydetails'
    FIREWALLGROUP_DETAIL_PATH = \
        'horizon:project:firewalls_v2:firewallgroupdetails'

    UPDATERULE_PATH = 'horizon:project:firewalls_v2:updaterule'
    UPDATEPOLICY_PATH = 'horizon:project:firewalls_v2:updatepolicy'
    UPDATEFIREWALLGROUP_PATH = 'horizon:project:firewalls_v2:updatefirewall'

    INSERTRULE_PATH = 'horizon:project:firewalls_v2:insertrule'
    REMOVERULE_PATH = 'horizon:project:firewalls_v2:removerule'

    ADDPORT_PATH = 'horizon:project:firewalls_v2:addport'
    REMOVEPORT_PATH = 'horizon:project:firewalls_v2:removeport'

    def setup_mocks(self):
        firewallgroups = self.firewall_groups_v2.list()
        self.mock_firewall_group_list_for_tenant.return_value = firewallgroups
        policies = self.fw_policies_v2.list()
        self.mock_policy_list_for_tenant.return_value = policies
        self.mock_rule_list_for_tenant.return_value = self.fw_rules_v2.list()

    def check_mocks(self):
        tenant_id = self.tenant.id

        self.mock_firewall_group_list_for_tenant.assert_called_once_with(
            helpers.IsHttpRequest(), tenant_id)
        # TODO(amotoki): get_firewallgroupstable_data() also calls
        # policy_list_for_tenant(). This needs to be clean up.
        self.assert_mock_multiple_calls_with_same_arguments(
            self.mock_policy_list_for_tenant, 2,
            mock.call(helpers.IsHttpRequest(), tenant_id))
        self.mock_rule_list_for_tenant.assert_called_once_with(
            helpers.IsHttpRequest(), tenant_id)

    def setup_mocks_with_exception(self):
        self.mock_rule_list_for_tenant.side_effect = self.exceptions.neutron
        self.mock_policy_list_for_tenant.side_effect = self.exceptions.neutron
        self.mock_firewall_group_list_for_tenant.side_effect = \
            self.exceptions.neutron

    def check_mocks_with_exception(self):
        tenant_id = self.tenant.id
        self.mock_rule_list_for_tenant.assert_called_once_with(
            helpers.IsHttpRequest(), tenant_id)
        self.mock_policy_list_for_tenant.assert_called_once_with(
            helpers.IsHttpRequest(), tenant_id)
        self.mock_firewall_group_list_for_tenant.assert_called_once_with(
            helpers.IsHttpRequest(), tenant_id)

    @helpers.create_mocks({api_fwaas_v2: ('firewall_group_list_for_tenant',
                                          'policy_list_for_tenant',
                                          'rule_list_for_tenant',)})
    def test_index_firewallgroups(self):
        self.setup_mocks()

        tenant_id = self.tenant.id

        res = self.client.get(self.INDEX_URL, tenant_id=tenant_id)

        self.assertTemplateUsed(res, 'project/firewalls_v2/details_tabs.html')
        self.assertTemplateUsed(res, 'horizon/common/_detail_table.html')
        self.assertEqual(len(res.context['table'].data),
                         len(self.firewall_groups_v2.list()))
        self.check_mocks()

    @helpers.create_mocks({api_fwaas_v2: ('firewall_group_list_for_tenant',
                                          'policy_list_for_tenant',
                                          'rule_list_for_tenant',)})
    def test_index_policies(self):
        self.setup_mocks()

        tenant_id = self.tenant.id

        res = self.client.get(self.INDEX_URL + '?tab=fwtabs__policies',
                              tenant_id=tenant_id)

        self.assertTemplateUsed(res, 'project/firewalls_v2/details_tabs.html')
        self.assertTemplateUsed(res, 'horizon/common/_detail_table.html')
        self.assertEqual(len(res.context['policiestable_table'].data),
                         len(self.fw_policies_v2.list()))
        self.check_mocks()

    @helpers.create_mocks({api_fwaas_v2: ('firewall_group_list_for_tenant',
                                          'policy_list_for_tenant',
                                          'rule_list_for_tenant',)})
    def test_index_rules(self):
        self.setup_mocks()

        tenant_id = self.tenant.id

        res = self.client.get(self.INDEX_URL + '?tab=fwtabs__rules',
                              tenant_id=tenant_id)

        self.assertTemplateUsed(res, 'project/firewalls_v2/details_tabs.html')
        self.assertTemplateUsed(res, 'horizon/common/_detail_table.html')
        self.assertEqual(len(res.context['rulestable_table'].data),
                         len(self.fw_rules_v2.list()))
        self.check_mocks()

    @helpers.create_mocks({api_fwaas_v2: ('firewall_group_list_for_tenant',
                                          'policy_list_for_tenant',
                                          'rule_list_for_tenant')})
    def test_index_exception_firewallgroups(self):
        self.setup_mocks_with_exception()

        tenant_id = self.tenant.id

        res = self.client.get(self.INDEX_URL, tenant_id=tenant_id)

        self.assertTemplateUsed(res, 'project/firewalls_v2/details_tabs.html')
        self.assertTemplateUsed(res, 'horizon/common/_detail_table.html')
        self.assertEqual(len(res.context['table'].data), 0)

        self.check_mocks_with_exception()

    @helpers.create_mocks({api_fwaas_v2: ('firewall_group_list_for_tenant',
                                          'policy_list_for_tenant',
                                          'rule_list_for_tenant')})
    def test_index_exception_policies(self):
        self.setup_mocks_with_exception()

        tenant_id = self.tenant.id

        res = self.client.get(self.INDEX_URL + '?tab=fwtabs__policies',
                              tenant_id=tenant_id)

        self.assertTemplateUsed(res, 'project/firewalls_v2/details_tabs.html')
        self.assertTemplateUsed(res,
                                'horizon/common/_detail_table.html')
        self.assertEqual(len(res.context['policiestable_table'].data), 0)

        self.check_mocks_with_exception()

    @helpers.create_mocks({api_fwaas_v2: ('firewall_group_list_for_tenant',
                                          'policy_list_for_tenant',
                                          'rule_list_for_tenant')})
    def test_index_exception_rules(self):
        self.setup_mocks_with_exception()

        tenant_id = self.tenant.id

        res = self.client.get(self.INDEX_URL + '?tab=fwtabs__rules',
                              tenant_id=tenant_id)

        self.assertTemplateUsed(res, 'project/firewalls_v2/details_tabs.html')
        self.assertTemplateUsed(res, 'horizon/common/_detail_table.html')
        self.assertEqual(len(res.context['rulestable_table'].data), 0)

        self.check_mocks_with_exception()

    @helpers.create_mocks({api_fwaas_v2: ('rule_create',), })
    def test_add_rule_post(self):
        rule1 = self.fw_rules_v2.first()

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

    @helpers.create_mocks({api_fwaas_v2: ('rule_create',), })
    def test_add_rule_post_src_None(self):
        rule1 = self.fw_rules_v2.first()
        form_data = {'name': rule1.name,
                     'description': rule1.description,
                     'protocol': rule1.protocol,
                     'action': rule1.action,
                     'source_ip_address': '',
                     'destination_ip_address': rule1.destination_ip_address,
                     'source_port': '',
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

    @helpers.create_mocks({api_fwaas_v2: ('rule_create',), })
    def test_add_rule_post_dest_None(self):
        rule1 = self.fw_rules_v2.first()
        form_data = {'name': rule1.name,
                     'description': rule1.description,
                     'protocol': rule1.protocol,
                     'action': rule1.action,
                     'source_ip_address': rule1.source_ip_address,
                     'destination_ip_address': '',
                     'source_port': rule1.source_port,
                     'destination_port': '',
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
        rule1 = self.fw_rules_v2.first()

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

    @helpers.create_mocks({api_fwaas_v2: ('policy_create',
                                          'rule_list_for_tenant'), })
    def test_add_policy_post(self):
        policy = self.fw_policies_v2.first()
        rules = self.fw_rules_v2.list()
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

    @helpers.create_mocks({api_fwaas_v2: ('rule_list_for_tenant',)})
    def test_add_policy_post_with_error(self):
        policy = self.fw_policies_v2.first()
        rules = self.fw_rules_v2.list()
        tenant_id = self.tenant.id
        form_data = {'description': policy.description,
                     'firewall_rules': '',
                     'shared': policy.shared,
                     'audited': policy.audited
                     }
        self.mock_rule_list_for_tenant.return_value = rules

        res = self.client.post(reverse(self.ADDPOLICY_PATH), form_data)

        self.assertFormErrors(res, 1)

        self.mock_rule_list_for_tenant.assert_called_once_with(
            helpers.IsHttpRequest(), tenant_id)

    @helpers.create_mocks({api_fwaas_v2: ('firewall_group_create',
                                          'policy_list_for_tenant',
                                          'fwg_port_list_for_tenant',)})
    def test_add_firewall_group_post(self):
        fwg = self.firewall_groups_v2.first()
        policies = self.fw_policies_v2.list()
        tenant_id = self.tenant.id

        form_data = {
            'name': fwg.name,
            'description': fwg.description,
            'ingress_firewall_policy_id': fwg.ingress_firewall_policy_id,
            'egress_firewall_policy_id': fwg.egress_firewall_policy_id,
            'admin_state_up': fwg.admin_state_up,
            'shared': False,
            'port': [],
        }

        self.mock_policy_list_for_tenant.return_value = policies
        self.mock_fwg_port_list_for_tenant.return_value = []
        self.mock_firewall_group_create.return_value = fwg

        res = self.client.post(reverse(self.ADDFIREWALLGROUP_PATH), form_data)
        self.assertNoFormErrors(res)
        self.assertRedirectsNoFollow(res, str(self.INDEX_URL))

        self.mock_policy_list_for_tenant.assert_called_once_with(
            helpers.IsHttpRequest(), tenant_id)
        self.mock_fwg_port_list_for_tenant.assert_called_once_with(
            helpers.IsHttpRequest(), tenant_id)
        data = form_data.copy()
        data['ports'] = data.pop('port')
        self.mock_firewall_group_create.assert_called_once_with(
            helpers.IsHttpRequest(), **data)

    # TODO(SarathMekala) : Fix this test.
    # @helpers.create_mocks({api_fwaas_v2: ('firewall_group_create',
    #                                       'policy_list_for_tenant',
    #                                       'fwg_port_list_for_tenant',)})
    # def test_add_firewall_post_with_error(self):
    #    firewall_groups = self.firewall_groups_v2.first()
    #    policies = self.fw_policies_v2.list()
    #    tenant_id = self.tenant.id
    #    form_data = {'name': firewall_groups.name,
    #                 'description': firewall_groups.description,
    #                 'admin_state_up': False
    #                 }
    #    self.mock_policy_list_for_tenant(
    #        helpers.IsHttpRequest(), tenant_id).AndReturn(policies)
    #
    #    self.mox.ReplayAll()
    #    res = self.client.post(reverse(self.ADDFIREWALLGROUP_PATH), form_data)
    #
    #    self.assertFormErrors(res, 1)

    @helpers.create_mocks({api_fwaas_v2: ('rule_get',)})
    def test_update_rule_get(self):
        rule = self.fw_rules_v2.first()

        self.mock_rule_get.return_value = rule

        res = self.client.get(reverse(self.UPDATERULE_PATH, args=(rule.id,)))

        self.assertTemplateUsed(res, 'project/firewalls_v2/updaterule.html')
        self.mock_rule_get.assert_called_once_with(helpers.IsHttpRequest(),
                                                   rule.id)

    @helpers.create_mocks({api_fwaas_v2: ('rule_get', 'rule_update')})
    def test_update_rule_post(self):
        rule = self.fw_rules_v2.first()

        self.mock_rule_get.return_value = rule
        self.mock_rule_update.return_value = rule

        data = {
            'name': 'new name',
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
        expected_put_data = {
            'name': 'new name',
            'description': 'new desc',
            'protocol': 'icmp',
            'action': 'allow',
            'shared': False,
            'destination_ip_address': None,
            'source_port': None,
        }

        form_data = data.copy()
        form_data['destination_ip_address'] = ''
        form_data['source_port'] = ''

        res = self.client.post(
            reverse(self.UPDATERULE_PATH, args=(rule.id,)), form_data)

        self.assertNoFormErrors(res)
        self.assertRedirectsNoFollow(res, str(self.INDEX_URL))

        self.mock_rule_get.assert_called_once_with(helpers.IsHttpRequest(),
                                                   rule.id)
        self.mock_rule_update.assert_called_once_with(
            helpers.IsHttpRequest(), rule.id, **expected_put_data)

    @helpers.create_mocks({api_fwaas_v2: ('rule_get', 'rule_update')})
    def test_update_protocol_any_rule_post(self):
        # protocol any means protocol == None in neutron context.
        rule = self.fw_rules_v2.get(protocol=None)

        self.mock_rule_get.return_value = rule
        self.mock_rule_update.return_value = rule

        data = {
            'name': 'new name',
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
        expected_put_data = {
            'name': 'new name',
            'description': 'new desc',
            'protocol': 'icmp',
            'action': 'allow',
            'shared': False,
            'destination_ip_address': None,
            'source_port': None,
        }

        form_data = data.copy()
        form_data['destination_ip_address'] = ''
        form_data['source_port'] = ''

        res = self.client.post(
            reverse(self.UPDATERULE_PATH, args=(rule.id,)), form_data)

        self.assertNoFormErrors(res)
        self.assertRedirectsNoFollow(res, str(self.INDEX_URL))

        self.mock_rule_get.assert_called_once_with(helpers.IsHttpRequest(),
                                                   rule.id)
        self.mock_rule_update.assert_called_once_with(
            helpers.IsHttpRequest(), rule.id, **expected_put_data)

    @helpers.create_mocks({api_fwaas_v2: ('rule_get', 'rule_update')})
    def test_update_rule_protocol_to_ANY_post(self):
        rule = self.fw_rules_v2.first()

        self.mock_rule_get.return_value = rule
        self.mock_rule_update.return_value = rule

        form_data = {
            'name': 'new name',
            'description': 'new desc',
            'protocol': 'any',
            'action': 'allow',
            'shared': False,
            'enabled': True,
            'ip_version': rule.ip_version,
            'source_ip_address': rule.source_ip_address,
            'destination_ip_address': '',
            'source_port': '',
            'destination_port': rule.destination_port,
        }

        expected_put_data = {
            'name': 'new name',
            'description': 'new desc',
            'protocol': None,
            'action': 'allow',
            'shared': False,
            'destination_ip_address': None,
            'source_port': None,
        }

        res = self.client.post(
            reverse(self.UPDATERULE_PATH, args=(rule.id,)), form_data)

        self.assertNoFormErrors(res)
        self.assertRedirectsNoFollow(res, str(self.INDEX_URL))

        self.mock_rule_get.assert_called_once_with(helpers.IsHttpRequest(),
                                                   rule.id)
        self.mock_rule_update.assert_called_once_with(
            helpers.IsHttpRequest(), rule.id, **expected_put_data)

    @helpers.create_mocks({api_fwaas_v2: ('policy_get',)})
    def test_update_policy_get(self):
        policy = self.fw_policies_v2.first()

        self.mock_policy_get.return_value = policy

        res = self.client.get(
            reverse(self.UPDATEPOLICY_PATH, args=(policy.id,)))

        self.assertTemplateUsed(res, 'project/firewalls_v2/updatepolicy.html')

        self.mock_policy_get.assert_called_once_with(helpers.IsHttpRequest(),
                                                     policy.id)

    @helpers.create_mocks({api_fwaas_v2: ('policy_get', 'policy_update')})
    def test_update_policy_post(self):
        policy = self.fw_policies_v2.first()

        self.mock_policy_get.return_value = policy
        self.mock_policy_update.return_value = policy

        data = {
            'name': 'new name',
            'description': 'new desc',
            'shared': True,
            'audited': False
        }
        expected_put_data = {
            'name': 'new name',
            'description': 'new desc',
            'audited': False,
        }

        res = self.client.post(
            reverse(self.UPDATEPOLICY_PATH, args=(policy.id,)), data)

        self.assertNoFormErrors(res)
        self.assertRedirectsNoFollow(res, str(self.INDEX_URL))

        self.mock_policy_get.assert_called_once_with(helpers.IsHttpRequest(),
                                                     policy.id)
        self.mock_policy_update.assert_called_once_with(
            helpers.IsHttpRequest(), policy.id, **expected_put_data)

    @helpers.create_mocks({api_fwaas_v2: ('firewall_group_get',
                                          'policy_list_for_tenant')})
    def test_update_firewall_group_get(self):
        firewall_group = self.firewall_groups_v2.first()
        policies = self.fw_policies_v2.list()
        tenant_id = self.tenant.id

        self.mock_policy_list_for_tenant.return_value = policies
        self.mock_firewall_group_get.return_value = firewall_group

        res = self.client.get(
            reverse(self.UPDATEFIREWALLGROUP_PATH, args=(firewall_group.id,)))

        self.assertTemplateUsed(res,
                                'project/firewalls_v2/updatefirewall.html')

        self.mock_policy_list_for_tenant.assert_called_once_with(
            helpers.IsHttpRequest(), tenant_id)
        self.mock_firewall_group_get.assert_called_once_with(
            helpers.IsHttpRequest(), firewall_group.id)

    @helpers.create_mocks({api_fwaas_v2: ('firewall_group_get',
                                          'policy_list_for_tenant',
                                          'firewall_group_update')})
    def test_update_firewall_post(self):
        fwg = self.firewall_groups_v2.first()
        tenant_id = self.tenant.id
        policies = self.fw_policies_v2.list()

        data = {
            'name': 'new name',
            'description': 'new desc',
            'ingress_firewall_policy_id': fwg.ingress_firewall_policy_id,
            'egress_firewall_policy_id': '',
            'admin_state_up': False,
            'shared': False,
        }

        expected_put_data = {
            'name': 'new name',
            'description': 'new desc',
            'egress_firewall_policy_id': None,
            'admin_state_up': False,
        }

        self.mock_firewall_group_get.return_value = fwg
        self.mock_policy_list_for_tenant.return_value = policies
        self.mock_firewall_group_update.return_value = fwg

        res = self.client.post(
            reverse(
                self.UPDATEFIREWALLGROUP_PATH,
                args=(
                    fwg.id,
                )),
            data)

        self.assertNoFormErrors(res)
        self.assertRedirectsNoFollow(res, str(self.INDEX_URL))

        self.mock_firewall_group_get.assert_called_once_with(
            helpers.IsHttpRequest(), fwg.id)
        self.mock_policy_list_for_tenant.assert_called_once_with(
            helpers.IsHttpRequest(), tenant_id)
        self.mock_firewall_group_update.assert_called_once_with(
            helpers.IsHttpRequest(), fwg.id, **expected_put_data)

    @helpers.create_mocks({api_fwaas_v2: ('policy_get', 'policy_insert_rule',
                                          'rule_list_for_tenant', 'rule_get')})
    def test_policy_insert_rule(self):
        policy = self.fw_policies_v2.first()
        tenant_id = self.tenant.id
        rules = self.fw_rules_v2.list()

        new_rule_id = rules[2].id

        data = {'firewall_rule_id': new_rule_id,
                'insert_before': rules[1].id,
                'insert_after': rules[0].id}

        self.mock_policy_get.return_value = policy

        policy.firewall_rules = [rules[0].id,
                                 new_rule_id,
                                 rules[1].id]

        self.mock_rule_list_for_tenant.return_value = rules
        self.mock_rule_get.return_value = rules[2]
        self.mock_policy_insert_rule.return_value = policy

        res = self.client.post(
            reverse(self.INSERTRULE_PATH, args=(policy.id,)), data)

        self.assertNoFormErrors(res)
        self.assertRedirectsNoFollow(res, str(self.INDEX_URL))

        self.mock_policy_get.assert_called_once_with(helpers.IsHttpRequest(),
                                                     policy.id)
        self.mock_rule_list_for_tenant.assert_called_once_with(
            helpers.IsHttpRequest(), tenant_id)
        self.mock_rule_get.assert_called_once_with(
            helpers.IsHttpRequest(), new_rule_id)
        self.mock_policy_insert_rule.assert_called_once_with(
            helpers.IsHttpRequest(), policy.id, **data)

    @helpers.create_mocks({api_fwaas_v2: ('policy_get', 'policy_remove_rule',
                                          'rule_list_for_tenant', 'rule_get')})
    def test_policy_remove_rule(self):
        policy = self.fw_policies_v2.first()
        tenant_id = self.tenant.id
        rules = self.fw_rules_v2.list()

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
        after_remove_policy = api_fwaas_v2.Policy(after_remove_policy_dict)

        self.mock_policy_get.return_value = policy
        self.mock_rule_list_for_tenant.return_value = rules
        self.mock_rule_get.return_value = rules[0]
        self.mock_policy_remove_rule.return_value = after_remove_policy

        res = self.client.post(
            reverse(self.REMOVERULE_PATH, args=(policy.id,)), data)

        self.assertNoFormErrors(res)
        self.assertRedirectsNoFollow(res, str(self.INDEX_URL))

        self.mock_policy_get.assert_called_once_with(helpers.IsHttpRequest(),
                                                     policy.id)
        self.mock_rule_list_for_tenant.assert_called_once_with(
            helpers.IsHttpRequest(), tenant_id)
        self.mock_rule_get.assert_called_once_with(
            helpers.IsHttpRequest(), remove_rule_id)
        self.mock_policy_remove_rule.assert_called_once_with(
            helpers.IsHttpRequest(), policy.id, **data)

    @helpers.create_mocks({api_fwaas_v2: ('rule_list_for_tenant',
                                          'rule_delete')})
    def test_delete_rule(self):
        rule = self.fw_rules_v2.list()[2]

        self.mock_rule_list_for_tenant.return_value = self.fw_rules_v2.list()
        self.mock_rule_delete.return_value = None

        form_data = {"action": "rulestable__deleterule__%s" % rule.id}
        res = self.client.post(self.INDEX_URL, form_data)

        self.assertNoFormErrors(res)

        self.mock_rule_list_for_tenant.assert_called_once_with(
            helpers.IsHttpRequest(), self.tenant.id)
        self.mock_rule_delete.assert_called_once_with(
            helpers.IsHttpRequest(), rule.id)

    @helpers.create_mocks({api_fwaas_v2: ('policy_list_for_tenant',
                                          'policy_delete')})
    def test_delete_policy(self):
        policy = self.fw_policies_v2.first()

        self.mock_policy_list_for_tenant.return_value = \
            self.fw_policies_v2.list()
        self.mock_policy_delete.return_value = None

        form_data = {"action": "policiestable__deletepolicy__%s" % policy.id}
        res = self.client.post(self.INDEX_URL, form_data)

        self.assertNoFormErrors(res)

        self.mock_policy_list_for_tenant.assert_called_once_with(
            helpers.IsHttpRequest(), self.tenant.id)
        self.mock_policy_delete.assert_called_once_with(
            helpers.IsHttpRequest(), policy.id)

    @helpers.create_mocks({api_fwaas_v2: ('firewall_group_list_for_tenant',
                                          'policy_list_for_tenant',
                                          'firewall_group_delete',)})
    def test_delete_firewall_group(self):
        fwl = self.firewall_groups_v2.first()

        self.mock_firewall_group_list_for_tenant.return_value = [fwl]
        self.mock_policy_list_for_tenant.return_value = \
            self.fw_policies_v2.list()
        self.mock_firewall_group_delete.return_value = None

        form_data = {
            "action": "FirewallGroupsTable__deletefirewallgroup__%s" %
            fwl.id}
        res = self.client.post(self.INDEX_URL, form_data)

        self.assertNoFormErrors(res)

        self.mock_firewall_group_list_for_tenant.assert_called_once_with(
            helpers.IsHttpRequest(), self.tenant.id)
        self.mock_policy_list_for_tenant.assert_called_once_with(
            helpers.IsHttpRequest(), self.tenant.id)
        self.mock_firewall_group_delete.assert_called_once_with(
            helpers.IsHttpRequest(), fwl.id)
