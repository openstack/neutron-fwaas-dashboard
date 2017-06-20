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

from django.core.urlresolvers import reverse
from django import http
from mox3.mox import IsA

from openstack_dashboard.api import neutron as api_neutron

from neutron_fwaas_dashboard.api import fwaas_v2 as api_fwaas_v2
from neutron_fwaas_dashboard.test import helpers as test


class FirewallTests(test.TestCase):
    class AttributeDict(dict):
        def __getattr__(self, attr):
            return self[attr]

        def __setattr__(self, attr, value):
            self[attr] = value

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

    def set_up_expect(self):
        tenant_id = self.tenant.id

        # retrieves firewallgroups
        firewallgroups = self.firewall_groups_v2.list()
        api_fwaas_v2.firewall_list_for_tenant(
            IsA(http.HttpRequest), tenant_id).AndReturn(firewallgroups)

        # retrieves policies
        # TODO(amotoki): get_firewallgroupstable_data() also calls
        # policy_list_for_tenant(). This needs to be clean up.
        policies = self.fw_policies_v2.list()
        api_fwaas_v2.policy_list_for_tenant(
            IsA(http.HttpRequest), tenant_id).AndReturn(policies)
        api_fwaas_v2.policy_list_for_tenant(
            IsA(http.HttpRequest), tenant_id).AndReturn(policies)

        # retrieve rules
        api_fwaas_v2.rule_list_for_tenant(
            IsA(http.HttpRequest),
            tenant_id).AndReturn(self.fw_rules_v2.list())

    def set_up_expect_with_exception(self):
        tenant_id = self.tenant.id
        api_fwaas_v2.rule_list_for_tenant(
            IsA(http.HttpRequest),
            tenant_id).AndRaise(self.exceptions.neutron)
        api_fwaas_v2.policy_list_for_tenant(
            IsA(http.HttpRequest),
            tenant_id).AndRaise(self.exceptions.neutron)
        api_fwaas_v2.firewall_list_for_tenant(
            IsA(http.HttpRequest),
            tenant_id).AndRaise(self.exceptions.neutron)

    @test.create_stubs({api_fwaas_v2: ('firewall_list_for_tenant',
                                       'policy_list_for_tenant',
                                       'rule_list_for_tenant',),
                        api_neutron: ('is_extension_supported',), })
    def test_index_firewallgroups(self):
        self.set_up_expect()

        self.mox.ReplayAll()

        tenant_id = self.tenant.id

        res = self.client.get(self.INDEX_URL, tenant_id=tenant_id)

        self.assertTemplateUsed(res, 'project/firewalls_v2/details_tabs.html')
        self.assertTemplateUsed(res, 'horizon/common/_detail_table.html')
        self.assertEqual(len(res.context['table'].data),
                         len(self.firewall_groups_v2.list()))

    @test.create_stubs({api_fwaas_v2: ('firewall_list_for_tenant',
                                       'policy_list_for_tenant',
                                       'rule_list_for_tenant',),
                        api_neutron: ('is_extension_supported',), })
    def test_index_policies(self):
        self.set_up_expect()

        self.mox.ReplayAll()

        tenant_id = self.tenant.id

        res = self.client.get(self.INDEX_URL + '?tab=fwtabs__policies',
                              tenant_id=tenant_id)

        self.assertTemplateUsed(res, 'project/firewalls_v2/details_tabs.html')
        self.assertTemplateUsed(res, 'horizon/common/_detail_table.html')
        self.assertEqual(len(res.context['policiestable_table'].data),
                         len(self.fw_policies_v2.list()))

    @test.create_stubs({api_fwaas_v2: ('firewall_list_for_tenant',
                                       'policy_list_for_tenant',
                                       'rule_list_for_tenant',),
                        api_neutron: ('is_extension_supported',), })
    def test_index_rules(self):
        self.set_up_expect()

        self.mox.ReplayAll()

        tenant_id = self.tenant.id

        res = self.client.get(self.INDEX_URL + '?tab=fwtabs__rules',
                              tenant_id=tenant_id)

        self.assertTemplateUsed(res, 'project/firewalls_v2/details_tabs.html')
        self.assertTemplateUsed(res, 'horizon/common/_detail_table.html')
        self.assertEqual(len(res.context['rulestable_table'].data),
                         len(self.fw_rules_v2.list()))

    @test.create_stubs({api_fwaas_v2: ('firewall_list_for_tenant',
                                       'policy_list_for_tenant',
                                       'rule_list_for_tenant'),
                        api_neutron: ('is_extension_supported',), })
    def test_index_exception_firewallgroups(self):
        self.set_up_expect_with_exception()

        self.mox.ReplayAll()

        tenant_id = self.tenant.id

        res = self.client.get(self.INDEX_URL, tenant_id=tenant_id)

        self.assertTemplateUsed(res, 'project/firewalls_v2/details_tabs.html')
        self.assertTemplateUsed(res, 'horizon/common/_detail_table.html')
        self.assertEqual(len(res.context['table'].data), 0)

    @test.create_stubs({api_fwaas_v2: ('firewall_list_for_tenant',
                                       'policy_list_for_tenant',
                                       'rule_list_for_tenant'),
                        api_neutron: ('is_extension_supported',), })
    def test_index_exception_policies(self):
        self.set_up_expect_with_exception()

        self.mox.ReplayAll()

        tenant_id = self.tenant.id

        res = self.client.get(self.INDEX_URL + '?tab=fwtabs__policies',
                              tenant_id=tenant_id)

        self.assertTemplateUsed(res, 'project/firewalls_v2/details_tabs.html')
        self.assertTemplateUsed(res,
                                'horizon/common/_detail_table.html')
        self.assertEqual(len(res.context['policiestable_table'].data), 0)

    @test.create_stubs({api_fwaas_v2: ('firewall_list_for_tenant',
                                       'policy_list_for_tenant',
                                       'rule_list_for_tenant'),
                        api_neutron: ('is_extension_supported',), })
    def test_index_exception_rules(self):
        self.set_up_expect_with_exception()

        self.mox.ReplayAll()

        tenant_id = self.tenant.id

        res = self.client.get(self.INDEX_URL + '?tab=fwtabs__rules',
                              tenant_id=tenant_id)

        self.assertTemplateUsed(res, 'project/firewalls_v2/details_tabs.html')
        self.assertTemplateUsed(res, 'horizon/common/_detail_table.html')
        self.assertEqual(len(res.context['rulestable_table'].data), 0)

    @test.create_stubs({api_fwaas_v2: ('rule_create',), })
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

        api_fwaas_v2.rule_create(
            IsA(http.HttpRequest), **form_data).AndReturn(rule1)

        self.mox.ReplayAll()

        res = self.client.post(reverse(self.ADDRULE_PATH), form_data)

        self.assertNoFormErrors(res)
        self.assertRedirectsNoFollow(res, str(self.INDEX_URL))

    @test.create_stubs({api_fwaas_v2: ('rule_create',), })
    def test_add_rule_post_src_None(self):
        rule1 = self.fw_rules_v2.first()
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

        api_fwaas_v2.rule_create(
            IsA(http.HttpRequest), **form_data).AndReturn(rule1)

        self.mox.ReplayAll()

        res = self.client.post(reverse(self.ADDRULE_PATH), form_data)

        self.assertNoFormErrors(res)
        self.assertRedirectsNoFollow(res, str(self.INDEX_URL))

    @test.create_stubs({api_fwaas_v2: ('rule_create',), })
    def test_add_rule_post_dest_None(self):
        rule1 = self.fw_rules_v2.first()
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

        api_fwaas_v2.rule_create(
            IsA(http.HttpRequest), **form_data).AndReturn(rule1)

        self.mox.ReplayAll()

        res = self.client.post(reverse(self.ADDRULE_PATH), form_data)

        self.assertNoFormErrors(res)
        self.assertRedirectsNoFollow(res, str(self.INDEX_URL))

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

        self.mox.ReplayAll()

        res = self.client.post(reverse(self.ADDRULE_PATH), form_data)

        self.assertFormErrors(res, 3)

    @test.create_stubs({api_fwaas_v2: ('policy_create',
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
        api_fwaas_v2.rule_list_for_tenant(
            IsA(http.HttpRequest), tenant_id).AndReturn(rules)
        api_fwaas_v2.policy_create(
            IsA(http.HttpRequest), **form_data).AndReturn(policy)

        self.mox.ReplayAll()

        res = self.client.post(reverse(self.ADDPOLICY_PATH), post_data)

        self.assertNoFormErrors(res)
        self.assertRedirectsNoFollow(res, str(self.INDEX_URL))

    @test.create_stubs({api_fwaas_v2: ('policy_create',
                                       'rule_list_for_tenant'), })
    def test_add_policy_post_with_error(self):
        policy = self.fw_policies_v2.first()
        rules = self.fw_rules_v2.list()
        tenant_id = self.tenant.id
        form_data = {'description': policy.description,
                     'firewall_rules': None,
                     'shared': policy.shared,
                     'audited': policy.audited
                     }
        api_fwaas_v2.rule_list_for_tenant(
            IsA(http.HttpRequest), tenant_id).AndReturn(rules)

        self.mox.ReplayAll()

        res = self.client.post(reverse(self.ADDPOLICY_PATH), form_data)

        self.assertFormErrors(res, 1)

    @test.create_stubs({api_fwaas_v2: ('firewall_group_create',
                                       'policy_list_for_tenant',
                                       'fwg_port_list_for_tenant',),
                        api_neutron: ('is_extension_supported',), })
    def test_add_firewall_group_post(self):
        firewall_group = self.firewall_groups_v2.first()
        policies = self.fw_policies_v2.list()
        tenant_id = self.tenant.id

        form_data = {'name': firewall_group.name,
                     'description': firewall_group.description,
                     'ingress_firewall_policy_id':
                     firewall_group.ingress_firewall_policy_id,
                     'egress_firewall_policy_id':
                     firewall_group.egress_firewall_policy_id,
                     'admin_state_up': firewall_group.admin_state_up
                     }
        api_fwaas_v2.policy_list_for_tenant(
            IsA(http.HttpRequest), tenant_id).AndReturn(policies)
        api_fwaas_v2.fwg_port_list_for_tenant(
            IsA(http.HttpRequest), tenant_id).AndReturn([])
        api_fwaas_v2.firewall_group_create(
            IsA(http.HttpRequest), **form_data).AndReturn(firewall_group)
        self.mox.ReplayAll()

        res = self.client.post(reverse(self.ADDFIREWALLGROUP_PATH), form_data)
        self.assertNoFormErrors(res)
        self.assertRedirectsNoFollow(res, str(self.INDEX_URL))

    # TODO(SarathMekala) : Fix this test.
    # @test.create_stubs({api_fwaas_v2: ('firewall_group_create',
    #                                   'policy_list_for_tenant',
    #                                   'fwg_port_list_for_tenant',),
    #                    api_neutron: ('is_extension_supported',), })
    # def test_add_firewall_post_with_error(self):
    #    firewall_groups = self.firewall_groups_v2.first()
    #    policies = self.fw_policies_v2.list()
    #    tenant_id = self.tenant.id
    #    form_data = {'name': firewall_groups.name,
    #                 'description': firewall_groups.description,
    #                 'admin_state_up': False
    #                 }
    #    api_fwaas_v2.policy_list_for_tenant(
    #        IsA(http.HttpRequest), tenant_id).AndReturn(policies)
    #
    #    self.mox.ReplayAll()
    #    res = self.client.post(reverse(self.ADDFIREWALLGROUP_PATH), form_data)
    #
    #    self.assertFormErrors(res, 1)

    @test.create_stubs({api_fwaas_v2: ('rule_get',)})
    def test_update_rule_get(self):
        rule = self.fw_rules_v2.first()

        api_fwaas_v2.rule_get(IsA(http.HttpRequest), rule.id).AndReturn(rule)

        self.mox.ReplayAll()

        res = self.client.get(reverse(self.UPDATERULE_PATH, args=(rule.id,)))

        self.assertTemplateUsed(res, 'project/firewalls_v2/updaterule.html')

    @test.create_stubs({api_fwaas_v2: ('rule_get', 'rule_update')})
    def test_update_rule_post(self):
        rule = self.fw_rules_v2.first()

        api_fwaas_v2.rule_get(IsA(http.HttpRequest), rule.id).AndReturn(rule)

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

        api_fwaas_v2.rule_update(IsA(http.HttpRequest), rule.id, **data)\
            .AndReturn(rule)

        self.mox.ReplayAll()

        form_data = data.copy()
        form_data['destination_ip_address'] = ''
        form_data['source_port'] = ''

        res = self.client.post(
            reverse(self.UPDATERULE_PATH, args=(rule.id,)), form_data)

        self.assertNoFormErrors(res)
        self.assertRedirectsNoFollow(res, str(self.INDEX_URL))

    @test.create_stubs({api_fwaas_v2: ('rule_get', 'rule_update')})
    def test_update_protocol_any_rule_post(self):
        # protocol any means protocol == None in neutron context.
        rule = self.fw_rules_v2.get(protocol=None)

        api_fwaas_v2.rule_get(IsA(http.HttpRequest), rule.id).AndReturn(rule)

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

        api_fwaas_v2.rule_update(IsA(http.HttpRequest), rule.id, **data)\
            .AndReturn(rule)

        self.mox.ReplayAll()

        form_data = data.copy()
        form_data['destination_ip_address'] = ''
        form_data['source_port'] = ''

        res = self.client.post(
            reverse(self.UPDATERULE_PATH, args=(rule.id,)), form_data)

        self.assertNoFormErrors(res)
        self.assertRedirectsNoFollow(res, str(self.INDEX_URL))

    @test.create_stubs({api_fwaas_v2: ('rule_get', 'rule_update')})
    def test_update_rule_protocol_to_ANY_post(self):
        rule = self.fw_rules_v2.first()

        api_fwaas_v2.rule_get(IsA(http.HttpRequest), rule.id).AndReturn(rule)

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
        api_fwaas_v2.rule_update(IsA(http.HttpRequest), rule.id, **data)\
            .AndReturn(rule)

        self.mox.ReplayAll()

        form_data = data.copy()
        form_data['destination_ip_address'] = ''
        form_data['source_port'] = ''
        form_data['protocol'] = 'any'

        res = self.client.post(
            reverse(self.UPDATERULE_PATH, args=(rule.id,)), form_data)

        self.assertNoFormErrors(res)
        self.assertRedirectsNoFollow(res, str(self.INDEX_URL))

    @test.create_stubs({api_fwaas_v2: ('policy_get',)})
    def test_update_policy_get(self):
        policy = self.fw_policies_v2.first()

        api_fwaas_v2.policy_get(IsA(http.HttpRequest),
                                policy.id).AndReturn(policy)

        self.mox.ReplayAll()

        res = self.client.get(
            reverse(self.UPDATEPOLICY_PATH, args=(policy.id,)))

        self.assertTemplateUsed(res, 'project/firewalls_v2/updatepolicy.html')

    @test.create_stubs({api_fwaas_v2: ('policy_get', 'policy_update',
                                       'rule_list_for_tenant')})
    def test_update_policy_post(self):
        policy = self.fw_policies_v2.first()

        api_fwaas_v2.policy_get(IsA(http.HttpRequest),
                                policy.id).AndReturn(policy)

        data = {'name': 'new name',
                'description': 'new desc',
                'shared': True,
                'audited': False
                }

        api_fwaas_v2.policy_update(IsA(http.HttpRequest), policy.id, **data)\
            .AndReturn(policy)

        self.mox.ReplayAll()

        res = self.client.post(
            reverse(self.UPDATEPOLICY_PATH, args=(policy.id,)), data)

        self.assertNoFormErrors(res)
        self.assertRedirectsNoFollow(res, str(self.INDEX_URL))

    @test.create_stubs({api_fwaas_v2: ('firewall_get',
                                       'policy_list_for_tenant')})
    def test_update_firewall_group_get(self):
        firewall_group = self.firewall_groups_v2.first()
        policies = self.fw_policies_v2.list()
        tenant_id = self.tenant.id

        api_fwaas_v2.policy_list_for_tenant(
            IsA(http.HttpRequest), tenant_id).AndReturn(policies)

        api_fwaas_v2.firewall_get(IsA(http.HttpRequest),
                                  firewall_group.id).AndReturn(firewall_group)

        self.mox.ReplayAll()

        res = self.client.get(
            reverse(self.UPDATEFIREWALLGROUP_PATH, args=(firewall_group.id,)))

        self.assertTemplateUsed(res,
                                'project/firewalls_v2/updatefirewall.html')

    @test.create_stubs({api_fwaas_v2: ('firewall_get',
                                       'policy_list_for_tenant',
                                       'firewall_update')})
    def test_update_firewall_post(self):
        firewall_group = self.firewall_groups_v2.first()
        tenant_id = self.tenant.id
        api_fwaas_v2.firewall_get(IsA(http.HttpRequest),
                                  firewall_group.id).AndReturn(firewall_group)

        data = {'name': 'new name',
                'description': 'new desc',
                'ingress_firewall_policy_id':
                        firewall_group.ingress_firewall_policy_id,
                'admin_state_up': False
                }

        policies = self.fw_policies_v2.list()
        api_fwaas_v2.policy_list_for_tenant(
            IsA(http.HttpRequest), tenant_id).AndReturn(policies)

        api_fwaas_v2.firewall_update(
            IsA(http.HttpRequest), firewall_group.id, **data)\
            .AndReturn(firewall_group)

        self.mox.ReplayAll()

        res = self.client.post(
            reverse(
                self.UPDATEFIREWALLGROUP_PATH,
                args=(
                    firewall_group.id,
                )),
            data)

        self.assertNoFormErrors(res)
        self.assertRedirectsNoFollow(res, str(self.INDEX_URL))

    @test.create_stubs({api_fwaas_v2: ('policy_get', 'policy_insert_rule',
                                       'rule_list_for_tenant', 'rule_get')})
    def test_policy_insert_rule(self):
        policy = self.fw_policies_v2.first()
        tenant_id = self.tenant.id
        rules = self.fw_rules_v2.list()

        new_rule_id = rules[2].id

        data = {'firewall_rule_id': new_rule_id,
                'insert_before': rules[1].id,
                'insert_after': rules[0].id}

        api_fwaas_v2.policy_get(IsA(http.HttpRequest),
                                policy.id).AndReturn(policy)

        policy.firewall_rules = [rules[0].id,
                                 new_rule_id,
                                 rules[1].id]

        api_fwaas_v2.rule_list_for_tenant(
            IsA(http.HttpRequest), tenant_id).AndReturn(rules)
        api_fwaas_v2.rule_get(
            IsA(http.HttpRequest), new_rule_id).AndReturn(rules[2])
        api_fwaas_v2.policy_insert_rule(
            IsA(http.HttpRequest), policy.id, **data) .AndReturn(policy)

        self.mox.ReplayAll()

        res = self.client.post(
            reverse(self.INSERTRULE_PATH, args=(policy.id,)), data)

        self.assertNoFormErrors(res)
        self.assertRedirectsNoFollow(res, str(self.INDEX_URL))

    @test.create_stubs({api_fwaas_v2: ('policy_get', 'policy_remove_rule',
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

        api_fwaas_v2.policy_get(IsA(http.HttpRequest),
                                policy.id).AndReturn(policy)
        api_fwaas_v2.rule_list_for_tenant(
            IsA(http.HttpRequest), tenant_id).AndReturn(rules)
        api_fwaas_v2.rule_get(
            IsA(http.HttpRequest), remove_rule_id).AndReturn(rules[0])
        api_fwaas_v2.policy_remove_rule(IsA(http.HttpRequest), policy.id, **data)\
            .AndReturn(after_remove_policy)

        self.mox.ReplayAll()

        res = self.client.post(
            reverse(self.REMOVERULE_PATH, args=(policy.id,)), data)

        self.assertNoFormErrors(res)
        self.assertRedirectsNoFollow(res, str(self.INDEX_URL))

    @test.create_stubs({api_fwaas_v2: ('rule_list_for_tenant',
                                       'rule_delete'),
                        api_neutron: ('is_extension_supported',)})
    def test_delete_rule(self):
        rule = self.fw_rules_v2.list()[2]
        api_fwaas_v2.rule_list_for_tenant(
            IsA(http.HttpRequest),
            self.tenant.id).AndReturn(self.fw_rules_v2.list())
        api_fwaas_v2.rule_delete(IsA(http.HttpRequest), rule.id)
        self.mox.ReplayAll()

        form_data = {"action": "rulestable__deleterule__%s" % rule.id}
        res = self.client.post(self.INDEX_URL, form_data)

        self.assertNoFormErrors(res)

    @test.create_stubs({api_fwaas_v2: ('policy_list_for_tenant',
                                       'policy_delete'),
                        api_neutron: ('is_extension_supported',)})
    def test_delete_policy(self):
        policy = self.fw_policies_v2.first()
        api_fwaas_v2.policy_list_for_tenant(
            IsA(http.HttpRequest),
            self.tenant.id).AndReturn(self.fw_policies_v2.list())
        api_fwaas_v2.policy_delete(IsA(http.HttpRequest), policy.id)
        self.mox.ReplayAll()

        form_data = {"action": "policiestable__deletepolicy__%s" % policy.id}
        res = self.client.post(self.INDEX_URL, form_data)

        self.assertNoFormErrors(res)

    @test.create_stubs({api_fwaas_v2: ('firewall_list_for_tenant',
                                       'policy_list_for_tenant',
                                       'firewall_delete',),
                        api_neutron: ('is_extension_supported',)})
    def test_delete_firewall_group(self):
        fwl = self.firewall_groups_v2.first()
        api_fwaas_v2.firewall_list_for_tenant(
            IsA(http.HttpRequest), self.tenant.id).AndReturn([fwl])
        api_fwaas_v2.policy_list_for_tenant(
            IsA(http.HttpRequest),
            self.tenant.id).AndReturn(self.fw_policies_v2.list())
        api_fwaas_v2.firewall_delete(IsA(http.HttpRequest), fwl.id)
        self.mox.ReplayAll()

        form_data = {
            "action": "FirewallGroupsTable__deletefirewallgroup__%s" %
            fwl.id}
        res = self.client.post(self.INDEX_URL, form_data)

        self.assertNoFormErrors(res)
