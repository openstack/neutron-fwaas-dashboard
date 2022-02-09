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

import collections

from openstack_dashboard.api import neutron
import openstack_dashboard.api.nova as nova
from openstack_dashboard.contrib.developer.profiler import api as profiler


neutronclient = neutron.neutronclient


class Port(neutron.NeutronAPIDictWrapper):
    """Wrapper for neutron port."""


class Rule(neutron.NeutronAPIDictWrapper):
    """Wrapper for neutron firewall rule."""


class Policy(neutron.NeutronAPIDictWrapper):
    """Wrapper for neutron firewall policy."""


class FirewallGroup(neutron.NeutronAPIDictWrapper):
    """Wrapper for neutron firewall group."""


def rule_create(request, **kwargs):
    """Create a firewall rule

    :param request: request context
    :param name: name for rule
    :param description: description for rule
    :param protocol: protocol for rule
    :param action: action for rule
    :param source_ip_address: source IP address or subnet
    :param source_port: integer in [1, 65535] or range in a:b
    :param destination_ip_address: destination IP address or subnet
    :param destination_port: integer in [1, 65535] or range in a:b
    :param shared: boolean (default false)
    :param enabled: boolean (default true)
    :return: Rule object
    """
    body = {'firewall_rule': kwargs}
    rule = neutronclient(request).create_fwaas_firewall_rule(
        body).get('firewall_rule')
    return Rule(rule)


@profiler.trace
def get_network_names(request):
    networks = neutronclient(request).list_networks(fields=["name", "id"])\
        .get('networks', [])
    mapped = {n['id']: neutron.Network(n) for n in networks}
    return mapped


@profiler.trace
def get_router_names(request):
    routers = neutronclient(request).list_routers(fields=["name", "id"])\
        .get('routers', [])
    mapped = {r['id']: neutron.Router(r) for r in routers}
    return mapped


@profiler.trace
def get_servers(request):
    servers = nova.server_list(request)[0]
    mapped = {s.id: s for s in servers}
    return mapped


@profiler.trace
def rule_list(request, **kwargs):
    return _rule_list(request, **kwargs)


@profiler.trace
def port_list(request, tenant_id, **kwargs):
    kwargs['tenant_id'] = tenant_id
    ports = neutronclient(request).list_ports(**kwargs).get('ports')

    return {
        p['id']: Port(p) for p in ports if _is_target(p)
    }


# Gets ids of all ports assigned to firewall groups
@profiler.trace
def fwg_port_list(request, **kwargs):
    fwgs = neutronclient(request).list_fwaas_firewall_groups(
        **kwargs).get('firewall_groups')
    ports = set()
    for fwg in fwgs:
        if fwg['ports']:
            ports.update(fwg['ports'])
    return ports


@profiler.trace
def fwg_port_list_for_tenant(request, tenant_id, **kwargs):
    kwargs['tenant_id'] = tenant_id
    ports = neutronclient(request).list_ports(**kwargs).get('ports')
    # TODO(SarathMekala): Remove ports which are already associated with a FWG
    fwgs = neutronclient(request).list_fwaas_firewall_groups(
        **kwargs).get('firewall_groups')
    fwg_ports = []
    for fwg in fwgs:
        if not fwg['ports']:
            continue
        fwg_ports += fwg['ports']
    return [Port(p) for p in ports
            if _is_target(p) and p['id'] not in fwg_ports]


def _is_target(port):
    return (port['device_owner'].startswith('compute:') or
            port['device_owner'].startswith('network:router_interface'))


@profiler.trace
def rule_list_for_tenant(request, tenant_id, **kwargs):
    """Return a rule list available for the tenant.

    The list contains rules owned by the tenant and shared rules.
    This is required because Neutron returns all resources including
    all tenants if a user has admin role.
    """
    rules = rule_list(request, tenant_id=tenant_id, shared=False, **kwargs)
    shared_rules = rule_list(request, shared=True, **kwargs)
    return rules + shared_rules


def _rule_list(request, **kwargs):
    rules = neutronclient(request).list_fwaas_firewall_rules(
        **kwargs).get('firewall_rules')
    return [Rule(r) for r in rules]


@profiler.trace
def rule_get(request, rule_id):
    return _rule_get(request, rule_id)


def _rule_get(request, rule_id):
    rule = neutronclient(request).show_fwaas_firewall_rule(
        rule_id).get('firewall_rule')
    return Rule(rule)


@profiler.trace
def rule_delete(request, rule_id):
    neutronclient(request).delete_fwaas_firewall_rule(rule_id)


@profiler.trace
def rule_update(request, rule_id, **kwargs):
    body = {'firewall_rule': kwargs}
    rule = neutronclient(request).update_fwaas_firewall_rule(
        rule_id, body).get('firewall_rule')
    return Rule(rule)


@profiler.trace
def policy_create(request, **kwargs):
    """Create a firewall policy

    :param request: request context
    :param name: name for policy
    :param description: description for policy
    :param firewall_rules: ordered list of rules in policy
    :param shared: boolean (default false)
    :param audited: boolean (default false)
    :return: Policy object
    """
    body = {'firewall_policy': kwargs}
    policy = neutronclient(request).create_fwaas_firewall_policy(
        body).get('firewall_policy')
    return Policy(policy)


@profiler.trace
def policy_list(request, **kwargs):
    return _policy_list(request, expand_rule=True, **kwargs)


@profiler.trace
def policy_list_for_tenant(request, tenant_id, **kwargs):
    """Return a policy list available for the tenant.

    The list contains policies owned by the tenant and shared policies.
    This is required because Neutron returns all resources including
    all tenants if a user has admin role.
    """
    policies = policy_list(request, tenant_id=tenant_id,
                           shared=False, **kwargs)
    shared_policies = policy_list(request, shared=True, **kwargs)
    return policies + shared_policies


def _policy_list(request, expand_rule, **kwargs):
    policies = neutronclient(request).list_fwaas_firewall_policies(
        **kwargs).get('firewall_policies')
    if expand_rule and policies:
        rules = _rule_list(request)
        rule_dict = collections.OrderedDict((rule.id, rule) for rule in rules)
        for p in policies:
            p['rules'] = [rule_dict.get(rule) for rule in p['firewall_rules']]
    return [Policy(p) for p in policies]


@profiler.trace
def policy_get(request, policy_id):
    return _policy_get(request, policy_id, expand_rule=True)


def _policy_get(request, policy_id, expand_rule):
    policy = neutronclient(request).show_fwaas_firewall_policy(
        policy_id).get('firewall_policy')
    if expand_rule:
        policy_rules = policy['firewall_rules']
        if policy_rules:
            rules = _rule_list(request, firewall_policy_id=policy_id)
            rule_dict = collections.OrderedDict((rule.id, rule)
                                                for rule in rules)
            policy['rules'] = [rule_dict.get(rule) for rule in policy_rules]
        else:
            policy['rules'] = []
    return Policy(policy)


@profiler.trace
def policy_delete(request, policy_id):
    neutronclient(request).delete_fwaas_firewall_policy(policy_id)


@profiler.trace
def policy_update(request, policy_id, **kwargs):
    body = {'firewall_policy': kwargs}
    policy = neutronclient(request).update_fwaas_firewall_policy(
        policy_id, body).get('firewall_policy')
    return Policy(policy)


@profiler.trace
def policy_insert_rule(request, policy_id, **kwargs):
    policy = neutronclient(request).insert_rule_fwaas_firewall_policy(
        policy_id, kwargs)
    return Policy(policy)


@profiler.trace
def policy_remove_rule(request, policy_id, **kwargs):
    policy = neutronclient(request).remove_rule_fwaas_firewall_policy(
        policy_id, kwargs)
    return Policy(policy)


@profiler.trace
def firewall_group_create(request, **kwargs):
    """Create a firewall group for specified policy

    :param request: request context
    :param name: name for firewall group
    :param description: description for firewall group
    :param firewall_policy_id: policy id used by firewall group
    :param shared: boolean (default false)
    :param admin_state_up: boolean (default true)
    :return: Firewall group object
    """
    body = {'firewall_group': kwargs}
    firewall_group = neutronclient(request).create_fwaas_firewall_group(body)
    return FirewallGroup(firewall_group['firewall_group'])


@profiler.trace
def firewall_group_list(request, **kwargs):
    return _firewall_group_list(request, **kwargs)


@profiler.trace
def firewall_group_list_for_tenant(request, tenant_id, **kwargs):
    """Return a firewall group list available for the tenant.

    The list contains firewall groups owned by the tenant and shared firewall
    groups. This is required because Neutron returns all resources including
    all tenants if a user has admin role.
    """
    fwg = firewall_group_list(request, tenant_id=tenant_id,
                              shared=False, **kwargs)
    shared_fwg = firewall_group_list(request, shared=True, **kwargs)
    return fwg + shared_fwg


# TODO(SarathMekala): Support expand_policy for _firewall_group_list
def _firewall_group_list(request, **kwargs):
    firewall_groups = neutronclient(request).list_fwaas_firewall_groups(
        **kwargs).get('firewall_groups')
    return [FirewallGroup(f) for f in firewall_groups]


@profiler.trace
def firewall_group_get(request, firewallgroup_id):
    return _firewall_group_get(request, firewallgroup_id, expand_policy=True)


def _firewall_group_get(request, firewallgroup_id, expand_policy):
    firewall_group = neutronclient(request).show_fwaas_firewall_group(
        firewallgroup_id).get('firewall_group')
    if expand_policy:
        ingress_policy_id = firewall_group['ingress_firewall_policy_id']
        if ingress_policy_id:
            firewall_group['ingress_policy'] = _policy_get(
                request, ingress_policy_id, expand_rule=False)
        else:
            firewall_group['ingress_policy'] = None

        egress_policy_id = firewall_group['egress_firewall_policy_id']
        if egress_policy_id:
            firewall_group['egress_policy'] = _policy_get(
                request, egress_policy_id, expand_rule=False)
        else:
            firewall_group['egress_policy'] = None
    return FirewallGroup(firewall_group)


@profiler.trace
def firewall_group_delete(request, firewallgroup_id):
    neutronclient(request).delete_fwaas_firewall_group(firewallgroup_id)


@profiler.trace
def firewall_group_update(request, firewallgroup_id, **kwargs):
    body = {'firewall_group': kwargs}
    firewall_group = neutronclient(request).update_fwaas_firewall_group(
        firewallgroup_id, body).get('firewall_group')
    return FirewallGroup(firewall_group)
