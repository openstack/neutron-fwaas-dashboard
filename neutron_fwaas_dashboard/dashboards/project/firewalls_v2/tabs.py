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

from django.utils.translation import gettext_lazy as _

from horizon import exceptions
from horizon import tabs
from openstack_dashboard.api import neutron as api_neutron

from neutron_fwaas_dashboard.api import fwaas_v2 as api_fwaas_v2
from neutron_fwaas_dashboard.dashboards.project.firewalls_v2 import tables

FirewallGroupsTable = tables.FirewallGroupsTable
PoliciesTable = tables.PoliciesTable
RulesTable = tables.RulesTable


class RulesTab(tabs.TableTab):
    table_classes = (RulesTable,)
    name = _("Firewall Rules")
    slug = "rules"
    template_name = "horizon/common/_detail_table.html"

    def get_rulestable_data(self):
        try:
            tenant_id = self.request.user.tenant_id
            request = self.tab_group.request
            rules = api_fwaas_v2.rule_list_for_tenant(request, tenant_id)
        except Exception:
            rules = []
            exceptions.handle(self.tab_group.request,
                              _('Unable to retrieve rules list.'))

        return rules


class PoliciesTab(tabs.TableTab):
    table_classes = (PoliciesTable,)
    name = _("Firewall Policies")
    slug = "policies"
    template_name = "horizon/common/_detail_table.html"

    def get_policiestable_data(self):
        try:
            tenant_id = self.request.user.tenant_id
            request = self.tab_group.request
            policies = api_fwaas_v2.policy_list_for_tenant(request, tenant_id)
        except Exception:
            policies = []
            exceptions.handle(self.tab_group.request,
                              _('Unable to retrieve policies list.'))

        return policies


class FirewallGroupsTab(tabs.TableTab):
    table_classes = (FirewallGroupsTable,)
    name = _("Firewall Groups")
    slug = "firewallgroups"
    template_name = "horizon/common/_detail_table.html"

    def get_policy_dict(self, policies):
        return dict((policy.id, policy) for policy in policies)

    def get_FirewallGroupsTable_data(self):
        try:
            tenant_id = self.request.user.tenant_id
            request = self.tab_group.request
            fw_groups = api_fwaas_v2.firewall_group_list_for_tenant(request,
                                                                    tenant_id)
            tenant_policies = api_fwaas_v2.policy_list_for_tenant(
                request, tenant_id)
            policy_dict = self.get_policy_dict(policies=tenant_policies)
            for fw_group in fw_groups:
                if fw_group['ingress_firewall_policy_id'] in policy_dict:
                    fw_group.ingress_policy = \
                        policy_dict[fw_group['ingress_firewall_policy_id']]
                if fw_group['egress_firewall_policy_id'] in policy_dict:
                    fw_group.egress_policy = \
                        policy_dict[fw_group['egress_firewall_policy_id']]
        except Exception:
            fw_groups = []
            exceptions.handle(self.tab_group.request,
                              _('Unable to retrieve firewall group list.'))

        return fw_groups


class RuleDetailsTab(tabs.Tab):
    name = _("Rule")
    slug = "ruledetails"
    template_name = "project/firewalls_v2/_rule_details.html"

    def get_context_data(self, request):
        return {"rule": self.tab_group.kwargs['rule']}


class PolicyDetailsTab(tabs.Tab):
    name = _("Policy")
    slug = "policydetails"
    template_name = "project/firewalls_v2/_policy_details.html"

    def get_context_data(self, request):
        return {"policy": self.tab_group.kwargs['policy']}


class FirewallGroupDetailsTab(tabs.Tab):
    name = _("FirewallGroup")
    slug = "firewallgroupdetails"
    template_name = "project/firewalls_v2/_firewallgroup_details.html"

    def get_context_data(self, request):
        return {"firewall_group": self.tab_group.kwargs['firewallgroup']}


class FirewallGroupPortsTab(tabs.TableTab):
    name = _("Ports")
    slug = "ports_tab"
    table_classes = (tables.FirewallGroupPortsTable,)
    template_name = ("horizon/common/_detail_table.html")
    preload = False

    def get_ports_data(self):
        port_ids = self.tab_group.kwargs['firewallgroup']['ports']
        if not port_ids:
            return []
        try:
            ports = api_neutron.port_list(self.request, id=port_ids)
        except Exception:
            ports = []
            msg = _('Failed to retrieve port list of the firewall group.')
            exceptions.handle(self.request, msg)
        return ports


class FirewallGroupTabs(tabs.TabGroup):
    slug = "fwtabs"
    tabs = (FirewallGroupsTab, PoliciesTab, RulesTab)
    sticky = True


class RuleDetailsTabs(tabs.DetailTabsGroup):
    slug = "ruletabs"
    tabs = (RuleDetailsTab,)


class PolicyDetailsTabs(tabs.DetailTabsGroup):
    slug = "policytabs"
    tabs = (PolicyDetailsTab,)


class FirewallGroupDetailsTabs(tabs.DetailTabsGroup):
    slug = "firewallgrouptabs"
    tabs = (FirewallGroupDetailsTab, FirewallGroupPortsTab)
