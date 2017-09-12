# Copyright 2012 Nebula, Inc.
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

from neutron_fwaas_dashboard.api import fwaas


def data(TEST):
    # Data returned by openstack_dashboard.api.neutron wrapper.
    TEST.firewalls = utils.TestDataContainer()
    TEST.fw_policies = utils.TestDataContainer()
    TEST.fw_rules = utils.TestDataContainer()

    # Data return by neutronclient.
    TEST.api_firewalls = utils.TestDataContainer()
    TEST.api_fw_policies = utils.TestDataContainer()
    TEST.api_fw_rules = utils.TestDataContainer()

    # 1st rule (used by 1st policy)
    rule1_dict = {'id': 'f0881d38-c3eb-4fee-9763-12de3338041d',
                  'tenant_id': '1',
                  'name': 'rule1',
                  'description': 'rule1 description',
                  'protocol': 'tcp',
                  'action': 'allow',
                  'source_ip_address': '1.2.3.0/24',
                  'source_port': '80',
                  'destination_ip_address': '4.5.6.7/32',
                  'destination_port': '1:65535',
                  'firewall_policy_id': 'abcdef-c3eb-4fee-9763-12de3338041e',
                  'position': 1,
                  'shared': True,
                  'enabled': True,
                  'ip_version': '4'}
    TEST.api_fw_rules.add(rule1_dict)

    rule1 = fwaas.Rule(copy.deepcopy(rule1_dict))
    # NOTE: rule1['policy'] is set below
    TEST.fw_rules.add(rule1)

    # 2nd rule (used by 2nd policy; no name)
    rule2_dict = {'id': 'c6298a93-850f-4f64-b78a-959fd4f1e5df',
                  'tenant_id': '1',
                  'name': '',
                  'description': '',
                  'protocol': 'udp',
                  'action': 'deny',
                  'source_ip_address': '1.2.3.0/24',
                  'source_port': '80',
                  'destination_ip_address': '4.5.6.7/32',
                  'destination_port': '1:65535',
                  'firewall_policy_id': 'abcdef-c3eb-4fee-9763-12de3338041e',
                  'position': 2,
                  'shared': True,
                  'enabled': True,
                  'ip_version': '6'}
    TEST.api_fw_rules.add(rule2_dict)

    rule2 = fwaas.Rule(copy.deepcopy(rule2_dict))
    # NOTE: rule2['policy'] is set below
    TEST.fw_rules.add(rule2)

    # 3rd rule (not used by any policy)
    rule3_dict = {'id': 'h0881d38-c3eb-4fee-9763-12de3338041d',
                  'tenant_id': '1',
                  'name': 'rule3',
                  'description': 'rule3 description',
                  'protocol': None,
                  'action': 'allow',
                  'source_ip_address': '1.2.3.0/24',
                  'source_port': '80',
                  'destination_ip_address': '4.5.6.7/32',
                  'destination_port': '1:65535',
                  'firewall_policy_id': None,
                  'position': None,
                  'shared': True,
                  'enabled': True,
                  'ip_version': '4'}
    TEST.api_fw_rules.add(rule3_dict)

    rule3 = fwaas.Rule(copy.deepcopy(rule3_dict))
    # rule3 is not associated with any rules
    rule3._apidict['policy'] = None
    TEST.fw_rules.add(rule3)

    # 1st policy (associated with 2 rules)
    policy1_dict = {'id': 'abcdef-c3eb-4fee-9763-12de3338041e',
                    'tenant_id': '1',
                    'name': 'policy1',
                    'description': 'policy with two rules',
                    'firewall_rules': [rule1_dict['id'], rule2_dict['id']],
                    'audited': True,
                    'shared': True}
    TEST.api_fw_policies.add(policy1_dict)

    policy1 = fwaas.Policy(copy.deepcopy(policy1_dict))
    policy1._apidict['rules'] = [rule1, rule2]
    TEST.fw_policies.add(policy1)

    # Reverse relations (rule -> policy)
    rule1._apidict['policy'] = policy1
    rule2._apidict['policy'] = policy1

    # 2nd policy (associated with no rules; no name)
    policy2_dict = {'id': 'cf50b331-787a-4623-825e-da794c918d6a',
                    'tenant_id': '1',
                    'name': '',
                    'description': '',
                    'firewall_rules': [],
                    'audited': False,
                    'shared': False}
    TEST.api_fw_policies.add(policy2_dict)

    policy2 = fwaas.Policy(copy.deepcopy(policy2_dict))
    policy2._apidict['rules'] = []
    TEST.fw_policies.add(policy2)

    # 1st firewall
    fw1_dict = {'id': '8913dde8-4915-4b90-8d3e-b95eeedb0d49',
                'tenant_id': '1',
                'firewall_policy_id':
                    'abcdef-c3eb-4fee-9763-12de3338041e',
                'name': 'firewall1',
                'router_ids': [TEST.routers.first().id],
                'description': 'firewall description',
                'status': 'PENDING_CREATE',
                'admin_state_up': True}
    TEST.api_firewalls.add(fw1_dict)

    fw1 = fwaas.Firewall(copy.deepcopy(fw1_dict))
    fw1._apidict['policy'] = policy1
    fw1._apidict['routers'] = [TEST.routers.first()]
    TEST.firewalls.add(fw1)

    # 2nd firewall (no name)
    fw2_dict = {'id': '1aa75150-415f-458e-bae5-5a362a4fb1f7',
                'tenant_id': '1',
                'firewall_policy_id':
                    'abcdef-c3eb-4fee-9763-12de3338041e',
                'name': '',
                'router_ids': [],
                'description': '',
                'status': 'PENDING_CREATE',
                'admin_state_up': True}
    TEST.api_firewalls.add(fw2_dict)

    fw2 = fwaas.Firewall(copy.deepcopy(fw2_dict))
    fw2._apidict['policy'] = policy1
    fw2._apidict['routers'] = []
    TEST.firewalls.add(fw2)
