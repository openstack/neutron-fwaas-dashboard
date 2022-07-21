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

from django.urls import reverse
from django.urls import reverse_lazy
from django.utils.translation import gettext_lazy as _

from horizon import exceptions
from horizon import forms
from horizon import tabs
from horizon.utils import memoized
from horizon import workflows

from neutron_fwaas_dashboard.api import fwaas_v2 as api_fwaas_v2
from neutron_fwaas_dashboard.dashboards.project.firewalls_v2 \
    import forms as fw_forms
from neutron_fwaas_dashboard.dashboards.project.firewalls_v2 \
    import tabs as fw_tabs
from neutron_fwaas_dashboard.dashboards.project.firewalls_v2 \
    import workflows as fw_workflows

InsertRuleToPolicy = fw_forms.InsertRuleToPolicy

RemoveRuleFromPolicy = fw_forms.RemoveRuleFromPolicy
UpdateFirewall = fw_forms.UpdateFirewall
UpdatePolicy = fw_forms.UpdatePolicy
UpdateRule = fw_forms.UpdateRule
AddPort = fw_forms.AddPort
RemovePort = fw_forms.RemovePort

FirewallGroupDetailsTabs = fw_tabs.FirewallGroupDetailsTabs
FirewallGroupTabs = fw_tabs.FirewallGroupTabs
PolicyDetailsTabs = fw_tabs.PolicyDetailsTabs
RuleDetailsTabs = fw_tabs.RuleDetailsTabs

AddFirewallGroup = fw_workflows.AddFirewallGroup
AddPolicy = fw_workflows.AddPolicy
AddRule = fw_workflows.AddRule


class IndexView(tabs.TabbedTableView):
    tab_group_class = FirewallGroupTabs
    template_name = 'project/firewalls_v2/details_tabs.html'
    page_title = _("Firewall Groups")


class AddRuleView(workflows.WorkflowView):
    workflow_class = AddRule
    template_name = "project/firewalls_v2/addrule.html"
    page_title = _("Add New Rule")


class AddPolicyView(workflows.WorkflowView):
    workflow_class = AddPolicy
    template_name = "project/firewalls_v2/addpolicy.html"
    page_title = _("Add New Policy")


class AddFirewallGroupView(workflows.WorkflowView):
    workflow_class = AddFirewallGroup
    template_name = "project/firewalls_v2/addfirewallgroup.html"
    page_title = _("Add New Firewall Group")


class RuleDetailsView(tabs.TabView):
    tab_group_class = (RuleDetailsTabs)
    template_name = 'horizon/common/_detail.html'
    page_title = "{{ rule.name|default:rule.id }}"
    failure_url = reverse_lazy('horizon:project:firewalls_v2:index')

    def get_context_data(self, **kwargs):
        context = super(RuleDetailsView, self).get_context_data(**kwargs)
        rule = self.get_data()
        table = fw_tabs.RulesTable(self.request)
        breadcrumb = [
            (_("Rules"), reverse_lazy('horizon:project:firewalls_v2:rules'))]
        context["custom_breadcrumb"] = breadcrumb
        context["rule"] = rule
        context["url"] = self.failure_url
        context["actions"] = table.render_row_actions(rule)
        return context

    @memoized.memoized_method
    def get_data(self):
        try:
            rule_id = self.kwargs['rule_id']
            rule = api_fwaas_v2.rule_get(self.request, rule_id)
        except Exception:
            exceptions.handle(self.request,
                              _('Unable to retrieve rule details.'),
                              redirect=self.failure_url)
        return rule

    def get_tabs(self, request, *args, **kwargs):
        rule = self.get_data()
        return self.tab_group_class(request, rule=rule, **kwargs)


class PolicyDetailsView(tabs.TabView):
    tab_group_class = (PolicyDetailsTabs)
    template_name = 'horizon/common/_detail.html'
    page_title = "{{ policy.name|default:policy.id }}"
    failure_url = reverse_lazy('horizon:project:firewalls_v2:index')

    def get_context_data(self, **kwargs):
        context = super(PolicyDetailsView, self).get_context_data(**kwargs)
        policy = self.get_data()
        table = fw_tabs.PoliciesTable(self.request)
        breadcrumb = [
            (_("Policies"),
             reverse_lazy('horizon:project:firewalls_v2:policies'))]
        context["custom_breadcrumb"] = breadcrumb
        context["policy"] = policy
        context["url"] = self.failure_url
        context["actions"] = table.render_row_actions(policy)
        return context

    @memoized.memoized_method
    def get_data(self):
        try:
            policy_id = self.kwargs['policy_id']
            policy = api_fwaas_v2.policy_get(self.request, policy_id)
        except Exception:
            exceptions.handle(self.request,
                              _('Unable to retrieve policy details.'),
                              redirect=self.failure_url)
        return policy

    def get_tabs(self, request, *args, **kwargs):
        policy = self.get_data()
        return self.tab_group_class(request, policy=policy, **kwargs)


class FirewallGroupDetailsView(tabs.TabView):
    tab_group_class = (FirewallGroupDetailsTabs)
    template_name = 'horizon/common/_detail.html'
    page_title = "{{ firewall_group.name|default:firewall_group.id }}"
    failure_url = reverse_lazy('horizon:project:firewalls_v2:index')

    def get_context_data(self, **kwargs):
        context = super(FirewallGroupDetailsView, self) \
            .get_context_data(**kwargs)
        firewall_group = self.get_data()
        table = fw_tabs.FirewallGroupsTable(self.request)
        context["firewall_group"] = firewall_group
        context["url"] = self.failure_url
        context["actions"] = table.render_row_actions(firewall_group)
        return context

    @memoized.memoized_method
    def get_data(self):
        try:
            firewallgroup_id = self.kwargs['firewallgroup_id']
            firewall_group = api_fwaas_v2.firewall_group_get(self.request,
                                                             firewallgroup_id)
        except Exception:
            exceptions.handle(self.request,
                              _('Unable to retrieve firewall group details.'),
                              redirect=self.failure_url)
        return firewall_group

    def get_tabs(self, request, *args, **kwargs):
        firewall_group = self.get_data()
        return self.tab_group_class(request, firewallgroup=firewall_group,
                                    **kwargs)


class UpdateRuleView(forms.ModalFormView):
    form_class = UpdateRule
    form_id = "update_rule_form"
    template_name = "project/firewalls_v2/updaterule.html"
    context_object_name = 'rule'
    submit_label = _("Save Changes")
    submit_url = "horizon:project:firewalls_v2:updaterule"
    success_url = reverse_lazy("horizon:project:firewalls_v2:index")
    page_title = _("Edit Rule {{ name }}")

    def get_context_data(self, **kwargs):
        context = super(UpdateRuleView, self).get_context_data(**kwargs)
        context['rule_id'] = self.kwargs['rule_id']
        args = (self.kwargs['rule_id'],)
        context['submit_url'] = reverse(self.submit_url, args=args)
        obj = self._get_object()
        if obj:
            context['name'] = obj.name_or_id
        return context

    @memoized.memoized_method
    def _get_object(self, *args, **kwargs):
        rule_id = self.kwargs['rule_id']
        try:
            rule = api_fwaas_v2.rule_get(self.request, rule_id)
            return rule
        except Exception:
            redirect = self.success_url
            msg = _('Unable to retrieve rule details.')
            exceptions.handle(self.request, msg, redirect=redirect)

    def get_initial(self):
        rule = self._get_object()
        initial = rule.to_dict()
        protocol = initial['protocol']
        initial['protocol'] = protocol.upper() if protocol else 'ANY'
        initial['action'] = initial['action'].upper()
        return initial


class UpdatePolicyView(forms.ModalFormView):
    form_class = UpdatePolicy
    form_id = "update_policy_form"
    template_name = "project/firewalls_v2/updatepolicy.html"
    context_object_name = 'policy'
    submit_label = _("Save Changes")
    submit_url = "horizon:project:firewalls_v2:updatepolicy"
    success_url = reverse_lazy("horizon:project:firewalls_v2:index")
    page_title = _("Edit Policy {{ name }}")

    def get_context_data(self, **kwargs):
        context = super(UpdatePolicyView, self).get_context_data(**kwargs)
        context["policy_id"] = self.kwargs['policy_id']
        args = (self.kwargs['policy_id'],)
        context['submit_url'] = reverse(self.submit_url, args=args)
        obj = self._get_object()
        if obj:
            context['name'] = obj.name_or_id
        return context

    @memoized.memoized_method
    def _get_object(self, *args, **kwargs):
        policy_id = self.kwargs['policy_id']
        try:
            policy = api_fwaas_v2.policy_get(self.request, policy_id)
            return policy
        except Exception:
            redirect = self.success_url
            msg = _('Unable to retrieve policy details.')
            exceptions.handle(self.request, msg, redirect=redirect)

    def get_initial(self):
        policy = self._get_object()
        initial = policy.to_dict()
        return initial


class UpdateFirewallView(forms.ModalFormView):
    form_class = UpdateFirewall
    form_id = "update_firewall_form"
    template_name = "project/firewalls_v2/updatefirewall.html"
    context_object_name = 'firewall'
    submit_label = _("Save Changes")
    submit_url = "horizon:project:firewalls_v2:updatefirewall"
    success_url = reverse_lazy("horizon:project:firewalls_v2:index")
    page_title = _("Edit FirewallGroup {{ name }}")

    def get_context_data(self, **kwargs):
        context = super(UpdateFirewallView, self).get_context_data(**kwargs)
        context["firewall_id"] = self.kwargs['firewall_id']
        args = (self.kwargs['firewall_id'],)
        context['submit_url'] = reverse(self.submit_url, args=args)
        obj = self._get_object()
        if obj:
            context['name'] = obj.name
        return context

    @memoized.memoized_method
    def _get_object(self, *args, **kwargs):
        fwg_id = self.kwargs['firewall_id']
        try:
            fwg = api_fwaas_v2.firewall_group_get(self.request, fwg_id)
            return fwg
        except Exception:
            redirect = self.success_url
            msg = _('Unable to retrieve firewall group details.')
            exceptions.handle(self.request, msg, redirect=redirect)

    def get_initial(self):
        fwg = self._get_object()
        initial = fwg.to_dict()
        return initial


class AddPortView(forms.ModalFormView):
    form_class = AddPort
    form_id = "update_firewall_port_form"
    template_name = "project/firewalls_v2/addport.html"
    context_object_name = 'firewallgroup'
    submit_label = _("Save Changes")
    submit_url = "horizon:project:firewalls_v2:addport"
    success_url = reverse_lazy("horizon:project:firewalls_v2:index")
    page_title = _("Add port to Firewall Group {{ name }}")

    def get_context_data(self, **kwargs):
        context = super(AddPortView, self).get_context_data(**kwargs)
        context["firewallgroup_id"] = self.kwargs['firewallgroup_id']
        args = (self.kwargs['firewallgroup_id'],)
        context['submit_url'] = reverse(self.submit_url, args=args)
        obj = self._get_object()
        if obj:
            context['name'] = obj.name
        return context

    @memoized.memoized_method
    def _get_object(self, *args, **kwargs):
        firewallgroup_id = self.kwargs['firewallgroup_id']
        try:
            firewallgroup = api_fwaas_v2.firewall_group_get(self.request,
                                                            firewallgroup_id)
            return firewallgroup
        except Exception:
            redirect = self.success_url
            msg = _('Unable to retrieve firewallgroup details.')
            exceptions.handle(self.request, msg, redirect=redirect)

    def get_initial(self):
        firewallgroup = self._get_object()
        initial = firewallgroup.to_dict()
        return initial


class RemovePortView(forms.ModalFormView):
    form_class = RemovePort
    form_id = "update_firewall_port_form"
    template_name = "project/firewalls_v2/removeport.html"
    context_object_name = 'firewallgroup'
    submit_label = _("Save Changes")
    submit_url = "horizon:project:firewalls_v2:removeport"
    success_url = reverse_lazy("horizon:project:firewalls_v2:index")
    page_title = _("Remove port from FirewallGroup {{ name }}")

    def get_context_data(self, **kwargs):
        context = super(RemovePortView, self).get_context_data(**kwargs)
        context["firewallgroup_id"] = self.kwargs['firewallgroup_id']
        args = (self.kwargs['firewallgroup_id'],)
        context['submit_url'] = reverse(self.submit_url, args=args)
        obj = self._get_object()
        if obj:
            context['name'] = obj.name
        return context

    @memoized.memoized_method
    def _get_object(self, *args, **kwargs):
        firewallgroup_id = self.kwargs['firewallgroup_id']
        try:
            firewallgroup = api_fwaas_v2.firewall_group_get(self.request,
                                                            firewallgroup_id)
            return firewallgroup
        except Exception:
            redirect = self.success_url
            msg = _('Unable to retrieve firewall group details.')
            exceptions.handle(self.request, msg, redirect=redirect)

    def get_initial(self):
        firewallgroup = self._get_object()
        initial = firewallgroup.to_dict()
        return initial


class InsertRuleToPolicyView(forms.ModalFormView):
    form_class = InsertRuleToPolicy
    form_id = "update_policy_form"
    template_name = "project/firewalls_v2/insert_rule_to_policy.html"
    context_object_name = 'policy'
    submit_url = "horizon:project:firewalls_v2:insertrule"
    submit_label = _("Save Changes")
    success_url = reverse_lazy("horizon:project:firewalls_v2:index")
    page_title = _("Insert Rule to Policy")

    def get_context_data(self, **kwargs):
        context = super(InsertRuleToPolicyView,
                        self).get_context_data(**kwargs)
        context["policy_id"] = self.kwargs['policy_id']
        args = (self.kwargs['policy_id'],)
        context['submit_url'] = reverse(self.submit_url, args=args)
        obj = self._get_object()
        if obj:
            context['name'] = obj.name_or_id
        return context

    @memoized.memoized_method
    def _get_object(self, *args, **kwargs):
        policy_id = self.kwargs['policy_id']
        try:
            policy = api_fwaas_v2.policy_get(self.request, policy_id)
            return policy
        except Exception:
            redirect = self.success_url
            msg = _('Unable to retrieve policy details.')
            exceptions.handle(self.request, msg, redirect=redirect)

    def get_initial(self):
        policy = self._get_object()
        initial = policy.to_dict()
        initial['policy_id'] = initial['id']
        return initial


class RemoveRuleFromPolicyView(forms.ModalFormView):
    form_class = RemoveRuleFromPolicy
    form_id = "update_policy_form"
    template_name = "project/firewalls_v2/remove_rule_from_policy.html"
    context_object_name = 'policy'
    submit_label = _("Save Changes")
    submit_url = "horizon:project:firewalls_v2:removerule"
    success_url = reverse_lazy("horizon:project:firewalls_v2:index")
    page_title = _("Remove Rule from Policy")

    def get_context_data(self, **kwargs):
        context = super(RemoveRuleFromPolicyView,
                        self).get_context_data(**kwargs)
        context["policy_id"] = self.kwargs['policy_id']
        args = (self.kwargs['policy_id'],)
        context['submit_url'] = reverse(self.submit_url, args=args)
        obj = self._get_object()
        if obj:
            context['name'] = obj.name_or_id
        return context

    @memoized.memoized_method
    def _get_object(self, *args, **kwargs):
        policy_id = self.kwargs['policy_id']
        try:
            policy = api_fwaas_v2.policy_get(self.request, policy_id)
            return policy
        except Exception:
            redirect = self.success_url
            msg = _('Unable to retrieve policy details.')
            exceptions.handle(self.request, msg, redirect=redirect)

    def get_initial(self):
        policy = self._get_object()
        initial = policy.to_dict()
        initial['policy_id'] = initial['id']
        return initial
