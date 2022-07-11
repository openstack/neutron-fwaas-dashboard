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
from operator import attrgetter

from django.utils.translation import gettext_lazy as _
from horizon import exceptions
from horizon import forms
from horizon.utils import validators
from horizon import workflows
import netaddr

from neutron_fwaas_dashboard.api import fwaas_v2 as api_fwaas_v2

port_validator = validators.validate_port_or_colon_separated_port_range


class AddRuleAction(workflows.Action):
    name = forms.CharField(
        max_length=80,
        label=_("Name"),
        required=False)
    description = forms.CharField(
        max_length=80,
        label=_("Description"),
        required=False)
    protocol = forms.ThemableChoiceField(
        label=_("Protocol"),
        choices=[('tcp', _('TCP')),
                 ('udp', _('UDP')),
                 ('icmp', _('ICMP')),
                 ('any', _('ANY'))],)
    action = forms.ThemableChoiceField(
        label=_("Action"),
        choices=[('allow', _('ALLOW')),
                 ('deny', _('DENY')),
                 ('reject', _('REJECT'))],)
    source_ip_address = forms.IPField(
        label=_("Source IP Address/Subnet"),
        version=forms.IPv4 | forms.IPv6,
        required=False, mask=True)
    destination_ip_address = forms.IPField(
        label=_("Destination IP Address/Subnet"),
        version=forms.IPv4 | forms.IPv6,
        required=False, mask=True)
    source_port = forms.CharField(
        max_length=80,
        label=_("Source Port/Port Range"),
        required=False,
        validators=[port_validator])
    destination_port = forms.CharField(
        max_length=80,
        label=_("Destination Port/Port Range"),
        required=False,
        validators=[port_validator])
    ip_version = forms.ThemableChoiceField(
        label=_("IP Version"), required=False,
        choices=[('4', '4'), ('6', '6')])
    shared = forms.BooleanField(
        label=_("Shared"), initial=False, required=False)
    enabled = forms.BooleanField(
        label=_("Enabled"), initial=True, required=False)

    def _check_ip_addr_and_ip_version(self, cleaned_data):
        ip_version = int(str(cleaned_data.get('ip_version')))
        src_ip = cleaned_data.get('source_ip_address')
        dst_ip = cleaned_data.get('destination_ip_address')
        msg = _('Source/Destination Network Address and IP version '
                'are inconsistent. Please make them consistent.')
        if (src_ip and
                netaddr.IPNetwork(src_ip).version != ip_version):
            self._errors['ip_version'] = self.error_class([msg])

        elif (dst_ip and
              netaddr.IPNetwork(dst_ip).version != ip_version):
            self._errors['ip_version'] = self.error_class([msg])

    def clean(self):
        cleaned_data = super(AddRuleAction, self).clean()
        self._check_ip_addr_and_ip_version(cleaned_data)

    class Meta(object):
        name = _("Rule")
        permissions = ('openstack.services.network',)
        help_text = _("Create a firewall rule.\n\n"
                      "A Firewall rule is an association of the following "
                      "attributes:\n\n"
                      "<li>IP Addresses: The addresses from/to which the "
                      "traffic filtration needs to be applied.</li>"
                      "<li>IP Version: The type of IP packets (IP V4/V6) "
                      "that needs to be filtered.</li>"
                      "<li>Protocol: Type of packets (UDP, ICMP, TCP, Any) "
                      "that needs to be checked.</li>"
                      "<li>Action: Action is the type of filtration "
                      "required, it can be Reject/Deny/Allow data "
                      "packets.</li>\n"
                      "The protocol and action fields are required, all "
                      "others are optional.")


class AddRuleStep(workflows.Step):
    action_class = AddRuleAction
    contributes = ("name", "description", "protocol", "action",
                   "source_ip_address", "source_port",
                   "destination_ip_address", "destination_port",
                   "enabled", "shared", "ip_version")

    def contribute(self, data, context):
        context = super(AddRuleStep, self).contribute(data, context)
        if data:
            if context['protocol'] == 'any':
                del context['protocol']
            for field in ['source_port',
                          'destination_port',
                          'source_ip_address',
                          'destination_ip_address']:
                if not context[field]:
                    del context[field]
            return context


class AddRule(workflows.Workflow):
    slug = "addrule"
    name = _("Add Rule")
    finalize_button_name = _("Add")
    success_message = _('Added Rule "%s".')
    failure_message = _('Unable to add Rule "%s".')
    success_url = "horizon:project:firewalls_v2:index"
    default_steps = (AddRuleStep,)

    def format_status_message(self, message):
        return message % self.context.get('name')

    def handle(self, request, context):
        try:
            api_fwaas_v2.rule_create(request, **context)
            return True
        except Exception as e:
            msg = self.format_status_message(self.failure_message) + str(e)
            exceptions.handle(request, msg)
            return False


class SelectRulesAction(workflows.Action):
    rule = forms.MultipleChoiceField(
        label=_("Rules"),
        required=False,
        widget=forms.ThemableCheckboxSelectMultiple(),
        help_text=_("Create a policy with selected rules."))

    class Meta(object):
        name = _("Rules")
        permissions = ('openstack.services.network',)
        help_text = _("Select rules for your policy.")

    def populate_rule_choices(self, request, context):
        try:
            tenant_id = self.request.user.tenant_id
            rules = api_fwaas_v2.rule_list_for_tenant(request, tenant_id)
            rules = sorted(rules,
                           key=attrgetter('name_or_id'))
            rule_list = [(rule.id, rule.name_or_id) for rule in rules]
        except Exception as e:
            rule_list = []
            exceptions.handle(request, _('Unable to retrieve rules (%s).') % e)
        return rule_list


class SelectRulesStep(workflows.Step):
    action_class = SelectRulesAction
    template_name = "project/firewalls_v2/_update_rules.html"
    contributes = ("firewall_rules",)

    def contribute(self, data, context):
        if data:
            rules = self.workflow.request.POST.getlist("rule")
            if rules:
                rules = [r for r in rules if r]
                context['firewall_rules'] = rules
            return context


class AddPolicyAction(workflows.Action):
    name = forms.CharField(max_length=80,
                           label=_("Name"))
    description = forms.CharField(max_length=80,
                                  label=_("Description"),
                                  required=False)
    shared = forms.BooleanField(label=_("Shared"),
                                initial=False,
                                required=False)
    audited = forms.BooleanField(label=_("Audited"),
                                 initial=False,
                                 required=False)

    class Meta(object):
        name = _("Policy")
        permissions = ('openstack.services.network',)
        help_text = _("Create a firewall policy with an ordered list "
                      "of firewall rules.\n\n"
                      "A firewall policy is an ordered collection of firewall "
                      "rules. So if the traffic matches the first rule, the "
                      "other rules are not executed. If the traffic does not "
                      "match the current rule, then the next rule is "
                      "executed. A firewall policy has the following "
                      "attributes:\n\n"
                      "<li>Shared: A firewall policy can be shared across "
                      "tenants. Thus it can also be made part of an audit "
                      "workflow wherein the firewall policy can be audited "
                      "by the relevant entity that is authorized.</li>"
                      "<li>Audited: When audited is set to True, it indicates "
                      "that the firewall policy has been audited. "
                      "Each time the firewall policy or the associated "
                      "firewall rules are changed, this attribute will be "
                      "set to False and will have to be explicitly set to "
                      "True through an update operation.</li>\n"
                      "The name field is required, all others are optional.")


class AddPolicyStep(workflows.Step):
    action_class = AddPolicyAction
    contributes = ("name", "description", "shared", "audited")

    def contribute(self, data, context):
        context = super(AddPolicyStep, self).contribute(data, context)
        if data:
            return context


class AddPolicy(workflows.Workflow):
    slug = "addpolicy"
    name = _("Add Policy")
    finalize_button_name = _("Add")
    success_message = _('Added Policy "%s".')
    failure_message = _('Unable to add Policy "%s".')
    success_url = "horizon:project:firewalls_v2:index"
    default_steps = (AddPolicyStep, SelectRulesStep)

    def format_status_message(self, message):
        return message % self.context.get('name')

    def handle(self, request, context):
        try:
            api_fwaas_v2.policy_create(request, **context)
            return True
        except Exception as e:
            msg = self.format_status_message(self.failure_message) + str(e)
            exceptions.handle(request, msg)
            return False


class AddFWGPortsAction(workflows.Action):
    port = forms.MultipleChoiceField(
        label=_("Ports"),
        required=False,
        widget=forms.ThemableCheckboxSelectMultiple(),
        help_text=_("Create a Firewall Group with selected ports."))

    class Meta(object):
        name = _("Ports")
        permissions = ('openstack.services.network',)
        help_text = _("Select ports for your firewall group.")

    def populate_port_choices(self, request, context):
        try:
            tenant_id = self.request.user.tenant_id
            ports = api_fwaas_v2.fwg_port_list_for_tenant(request, tenant_id)
            ports = sorted(ports,
                           key=attrgetter('name_or_id'))
            port_list = [(port.id, port.name_or_id) for port in ports]
        except Exception as e:
            port_list = []
            exceptions.handle(request, _('Unable to retrieve ports (%s).') % e)
        return port_list


class AddFWGPortsStep(workflows.Step):
    action_class = AddFWGPortsAction
    template_name = "project/firewalls_v2/_update_ports.html"
    contributes = ("ports")

    def contribute(self, data, context):
        if data:
            ports = self.workflow.request.POST.getlist("port")
            if ports:
                ports = [r for r in ports if r != '']
                context['ports'] = ports
            else:
                context['ports'] = []
            return context


class AddFirewallGroupAction(workflows.Action):
    name = forms.CharField(max_length=80,
                           label=_("Name"),
                           required=False)
    description = forms.CharField(max_length=80,
                                  label=_("Description"),
                                  required=False)
    ingress_firewall_policy_id = forms.ThemableChoiceField(
        label=_("Ingress Policy"),
        required=False)
    egress_firewall_policy_id = forms.ThemableChoiceField(
        label=_("Egress Policy"),
        required=False)
    admin_state_up = forms.BooleanField(
        label=_("Admin State"), initial=True, required=False)
    shared = forms.BooleanField(
        label=_("Shared"), initial=False, required=False)

    def __init__(self, request, *args, **kwargs):
        super(AddFirewallGroupAction, self).__init__(request, *args, **kwargs)

        firewall_policy_id_choices = [('', _("Select a Policy"))]
        try:
            tenant_id = self.request.user.tenant_id
            policies = api_fwaas_v2.policy_list_for_tenant(request, tenant_id)
            policies = sorted(policies, key=attrgetter('name'))
        except Exception as e:
            exceptions.handle(request,
                              _('Unable to retrieve policy list (%s).') % e)
            policies = []
        for p in policies:
            firewall_policy_id_choices.append((p.id, p.name_or_id))
        self.fields['ingress_firewall_policy_id'].choices = \
            firewall_policy_id_choices
        self.fields['egress_firewall_policy_id'].choices = \
            firewall_policy_id_choices

    def clean(self):
        cleaned_data = super(AddFirewallGroupAction, self).clean()
        for field in ('ingress_firewall_policy_id',
                      'egress_firewall_policy_id'):
            if not cleaned_data[field]:
                cleaned_data[field] = None
        return cleaned_data

    class Meta(object):
        name = _("FirewallGroup")
        permissions = ('openstack.services.network',)
        help_text = _("Create a firewall group based on a policy.\n\n"
                      "A firewall group represents a logical firewall "
                      "resource that a tenant can instantiate and manage. "
                      "A firewall group must be associated with one policy, "
                      "all other fields are optional.")


class AddFirewallGroupStep(workflows.Step):
    action_class = AddFirewallGroupAction
    contributes = ("name", "description", "admin_state_up", "shared",
                   "ingress_firewall_policy_id",
                   "egress_firewall_policy_id")

    def contribute(self, data, context):
        context = super(AddFirewallGroupStep, self).contribute(data, context)
        return context


class AddFirewallGroup(workflows.Workflow):
    slug = "addfirewallgroup"
    name = _("Add Firewall Group")
    finalize_button_name = _("Add")
    success_message = _('Added Firewall Group"%s".')
    failure_message = _('Unable to add Firewall Group "%s".')
    success_url = "horizon:project:firewalls_v2:index"
    default_steps = (AddFirewallGroupStep, AddFWGPortsStep)

    def format_status_message(self, message):
        return message % self.context.get('name')

    def handle(self, request, context):
        try:
            api_fwaas_v2.firewall_group_create(request, **context)
            return True
        except Exception as e:
            msg = self.format_status_message(self.failure_message) + str(e)
            exceptions.handle(request, msg)
            return False
