# Copyright 2017 Juniper Networks
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

import copy

from openstack_dashboard.test.test_data import utils

from neutron_fwaas_dashboard.api import fwaas_v2 as fwaas


def data(TEST):
    # Data returned by openstack_dashboard.api.neutron wrapper.
    TEST.firewall_groups_v2 = utils.TestDataContainer()
    TEST.fw_policies_v2 = utils.TestDataContainer()
    TEST.fw_rules_v2 = utils.TestDataContainer()

    # Data return by neutronclient.
    TEST.api_firewall_groups_v2 = utils.TestDataContainer()
    TEST.api_fw_policies_v2 = utils.TestDataContainer()
    TEST.api_fw_rules_v2 = utils.TestDataContainer()

    # 1st rule (used by 1st policy)
    rule1_dict = {
        'action': 'allow',
        'description': 'rule1 description',
        'destination_ip_address': '4.5.6.7/32',
        'destination_port': '1:65535',
        'enabled': True,
        'id': 'f0881d38-c3eb-4fee-9763-12de3338041d',
        'ip_version': '4',
        'name': 'rule1',
        'protocol': 'tcp',
        'shared': True,
        'source_ip_address': '1.2.3.0/24',
        'source_port': '80',
        'tenant_id': '1',
    }
    TEST.api_fw_rules_v2.add(rule1_dict)

    rule1 = fwaas.Rule(copy.deepcopy(rule1_dict))
    TEST.fw_rules_v2.add(rule1)

    # 2nd rule (used by 2nd policy; no name)
    rule2_dict = {
        'action': 'deny',
        'description': '',
        'destination_ip_address': None,
        'destination_port': '1:65535',
        'enabled': True,
        'id': 'c6298a93-850f-4f64-b78a-959fd4f1e5df',
        'ip_version': '6',
        'name': '',
        'protocol': 'udp',
        'shared': False,
        'source_ip_address': '2001:db8::/32',
        'source_port': '80',
        'tenant_id': '1',
    }
    TEST.api_fw_rules_v2.add(rule2_dict)

    rule2 = fwaas.Rule(copy.deepcopy(rule2_dict))
    TEST.fw_rules_v2.add(rule2)

    # 3rd rule (not used by any policy)
    rule3_dict = {
        'action': 'allow',
        'description': 'rule3 description',
        'destination_ip_address': '4.5.6.7/32',
        'destination_port': '1:65535',
        'enabled': True,
        'id': 'h0881d38-c3eb-4fee-9763-12de3338041d',
        'ip_version': '4',
        'name': 'rule3',
        'protocol': None,
        'shared': True,
        'source_ip_address': '1.2.3.0/24',
        'source_port': '80',
        'tenant_id': '1',
    }
    TEST.api_fw_rules_v2.add(rule3_dict)

    rule3 = fwaas.Rule(copy.deepcopy(rule3_dict))
    TEST.fw_rules_v2.add(rule3)

    # 1st policy (associated with 2 rules)
    policy1_dict = {
        'audited': True,
        'description': 'policy with two rules',
        'firewall_rules': [rule1_dict['id'], rule2_dict['id']],
        'id': 'abcdef-c3eb-4fee-9763-12de3338041e',
        'name': 'policy1',
        'shared': True,
        'tenant_id': '1',
    }
    TEST.api_fw_policies_v2.add(policy1_dict)

    policy1 = fwaas.Policy(copy.deepcopy(policy1_dict))
    policy1._apidict['rules'] = [rule1, rule2]
    TEST.fw_policies_v2.add(policy1)

    # 2nd policy (associated with no rules; no name)
    policy2_dict = {
        'audited': False,
        'description': '',
        'firewall_rules': [],
        'id': 'cf50b331-787a-4623-825e-da794c918d6a',
        'name': '',
        'shared': False,
        'tenant_id': '1',
    }
    TEST.api_fw_policies_v2.add(policy2_dict)

    policy2 = fwaas.Policy(copy.deepcopy(policy2_dict))
    policy2._apidict['rules'] = []
    TEST.fw_policies_v2.add(policy2)

    # 1st firewall group
    fwg1_dict = {
        'admin_state_up': True,
        'description': 'firewall description',
        'egress_firewall_policy_id': 'cf50b331-787a-4623-825e-da794c918d6a',
        'id': '8913dde8-4915-4b90-8d3e-b95eeedb0d49',
        'ingress_firewall_policy_id': 'abcdef-c3eb-4fee-9763-12de3338041e',
        'name': 'firewallgroup1',
        'ports': [],
        'shared': False,
        'status': 'PENDING_CREATE',
        'tenant_id': '1',
    }
    TEST.api_firewall_groups_v2.add(fwg1_dict)

    fwg1 = fwaas.FirewallGroup(copy.deepcopy(fwg1_dict))
    fwg1._apidict['ingress_policy'] = policy1
    fwg1._apidict['egress_policy'] = policy2
    fwg1._apidict['port_ids'] = []
    TEST.firewall_groups_v2.add(fwg1)

    # 2nd firewall group (no name)
    fwg2_dict = {
        'admin_state_up': True,
        'description': '',
        'egress_firewall_policy_id': None,
        'id': '1aa75150-415f-458e-bae5-5a362a4fb1f7',
        'ingress_firewall_policy_id': None,
        'name': '',
        'ports': [],
        'shared': False,
        'status': 'INACTIVE',
        'tenant_id': '1',
    }
    TEST.api_firewall_groups_v2.add(fwg2_dict)

    fwg2 = fwaas.FirewallGroup(copy.deepcopy(fwg2_dict))
    fwg2._apidict['ingress_policy'] = None
    fwg2._apidict['egress_policy'] = None
    TEST.firewall_groups_v2.add(fwg2)
