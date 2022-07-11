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

import logging
from operator import attrgetter

from django.urls import reverse
from django.utils.translation import gettext_lazy as _
from horizon import exceptions
from horizon import forms
from horizon import messages
from horizon.utils import validators

from neutron_fwaas_dashboard.api import fwaas_v2 as api_fwaas_v2
from neutron_fwaas_dashboard.dashboards.project.firewalls_v2 import widgets

port_validator = validators.validate_port_or_colon_separated_port_range

LOG = logging.getLogger(__name__)


class UpdateRule(forms.SelfHandlingForm):
    name = forms.CharField(max_length=80, label=_("Name"), required=False)
    description = forms.CharField(
        required=False,
        max_length=80, label=_("Description"))
    protocol = forms.ThemableChoiceField(
        label=_("Protocol"),
        choices=[('tcp', _('TCP')), ('udp', _('UDP')), ('icmp', _('ICMP')),
                 ('any', _('ANY'))],
        help_text=_('Protocol for the firewall rule'))
    action = forms.ThemableChoiceField(
        label=_("Action"),
        choices=[('allow', _('ALLOW')), ('deny', _('DENY')),
                 ('reject', _('REJECT'))],
        help_text=_('Action for the firewall rule'))
    source_ip_address = forms.IPField(
        label=_("Source IP Address/Subnet"),
        version=forms.IPv4 | forms.IPv6,
        required=False, mask=True,
        help_text=_('Source IP address or subnet'))
    destination_ip_address = forms.IPField(
        label=_('Destination IP Address/Subnet'),
        version=forms.IPv4 | forms.IPv6,
        required=False, mask=True,
        help_text=_('Destination IP address or subnet'))
    source_port = forms.CharField(
        max_length=80,
        label=_("Source Port/Port Range"),
        required=False,
        validators=[port_validator],
        help_text=_('Source port (integer in [1, 65535] or range in a:b)'))
    destination_port = forms.CharField(
        max_length=80,
        label=_("Destination Port/Port Range"),
        required=False,
        validators=[port_validator],
        help_text=_('Destination port (integer in [1, 65535] or range'
                    ' in a:b)'))
    ip_version = forms.ThemableChoiceField(
        label=_("IP Version"),
        choices=[('4', '4'), ('6', '6')],
        help_text=_('IP Version for Firewall Rule'))
    shared = forms.BooleanField(label=_("Shared"), required=False)
    enabled = forms.BooleanField(label=_("Enabled"), required=False)

    failure_url = 'horizon:project:firewalls_v2:index'

    def _convert_req_body(self, body):
        for key in ['source_port', 'source_ip_address',
                    'destination_port', 'destination_ip_address']:
            if key in body and not body[key]:
                body[key] = None
        if body.get('protocol') == 'any':
            body['protocol'] = None
        return body

    def handle(self, request, context):
        rule_id = self.initial['id']
        name_or_id = context.get('name') or rule_id
        body = self._convert_req_body(_get_request_body(context, self.initial))
        try:
            rule = api_fwaas_v2.rule_update(request, rule_id, **body)
            msg = _('Rule %s was successfully updated.') % name_or_id
            messages.success(request, msg)
            return rule
        except Exception as e:
            msg = (_('Failed to update rule %(name)s: %(reason)s') %
                   {'name': name_or_id, 'reason': e})
            redirect = reverse(self.failure_url)
            exceptions.handle(request, msg, redirect=redirect)


class UpdatePolicy(forms.SelfHandlingForm):
    name = forms.CharField(max_length=80, label=_("Name"), required=False)
    description = forms.CharField(required=False,
                                  max_length=80, label=_("Description"))
    shared = forms.BooleanField(label=_("Shared"), required=False)
    audited = forms.BooleanField(label=_("Audited"), required=False)

    failure_url = 'horizon:project:firewalls_v2:index'

    def handle(self, request, context):
        policy_id = self.initial['id']
        name_or_id = context.get('name') or policy_id
        body = _get_request_body(context, self.initial)
        try:
            policy = api_fwaas_v2.policy_update(request, policy_id, **body)
            msg = _('Policy %s was successfully updated.') % name_or_id
            messages.success(request, msg)
            return policy
        except Exception as e:
            msg = (_('Failed to update policy %(name)s: %(reason)s') %
                   {'name': name_or_id, 'reason': e})
            redirect = reverse(self.failure_url)
            exceptions.handle(request, msg, redirect=redirect)


class UpdateFirewall(forms.SelfHandlingForm):
    name = forms.CharField(max_length=80,
                           label=_("Name"),
                           required=False)
    description = forms.CharField(max_length=80,
                                  label=_("Description"),
                                  required=False)
    ingress_firewall_policy_id = forms.ThemableChoiceField(
        label=_("Ingress Policy"), required=False)
    egress_firewall_policy_id = forms.ThemableChoiceField(
        label=_("Egress Policy"), required=False)
    admin_state_up = forms.BooleanField(label=_("Admin State"),
                                        required=False)
    shared = forms.BooleanField(label=_("Shared"), required=False)
    failure_url = 'horizon:project:firewalls_v2:index'

    def __init__(self, request, *args, **kwargs):
        super(UpdateFirewall, self).__init__(request, *args, **kwargs)

        try:
            tenant_id = self.request.user.tenant_id
            policies = api_fwaas_v2.policy_list_for_tenant(request, tenant_id)
            policies = sorted(policies, key=attrgetter('name'))
        except Exception:
            exceptions.handle(request, _('Unable to retrieve policy list.'))
            policies = []

        egress_policy_id_choices = []
        ingress_policy_id_choices = []
        ingress_policy_id = kwargs['initial']['ingress_firewall_policy_id']
        if ingress_policy_id:
            ingress_policy_name = [
                p.name for p in policies if p.id == ingress_policy_id][0]
            ingress_policy_id_choices.append(
                (ingress_policy_id, ingress_policy_name))
        egress_policy_id = kwargs['initial']['egress_firewall_policy_id']
        if egress_policy_id:
            egress_policy_name = [
                p.name for p in policies if p.id == egress_policy_id][0]
            egress_policy_id_choices.append((egress_policy_id,
                                             egress_policy_name))

        ingress_policy_id_choices.append(('', _('None')))
        egress_policy_id_choices.append(('', _('None')))

        for p in policies:
            if p.id != ingress_policy_id:
                ingress_policy_id_choices.append((p.id, p.name_or_id))
            if p.id != egress_policy_id:
                egress_policy_id_choices.append((p.id, p.name_or_id))

        self.fields['ingress_firewall_policy_id'].choices = \
            ingress_policy_id_choices
        self.fields['egress_firewall_policy_id'].choices = \
            egress_policy_id_choices

    def _convert_req_body(self, body):
        for key in ['ingress_firewall_policy_id', 'egress_firewall_policy_id']:
            if key in body and not body[key]:
                body[key] = None
        return body

    def handle(self, request, context):
        firewallgroup_id = self.initial['id']
        name_or_id = context.get('name') or firewallgroup_id
        body = self._convert_req_body(_get_request_body(context, self.initial))
        try:
            fwg = api_fwaas_v2.firewall_group_update(request,
                                                     firewallgroup_id,
                                                     **body)
            msg = _('Firewall group %s was successfully updated.') % name_or_id
            messages.success(request, msg)
            return fwg
        except Exception as e:
            msg = (_('Failed to update firewall group %(name)s: %(reason)s') %
                   {'name': name_or_id, 'reason': e})
            redirect = reverse(self.failure_url)
            exceptions.handle(request, msg, redirect=redirect)


class PortSelectionForm(forms.SelfHandlingForm):
    port_id = forms.ThemableDynamicChoiceField(
        label=_("Ports"),
        required=False,
        widget=widgets.TableSelectWidget(
            columns=['Port', 'Network', 'Owner', 'Device'],
            alternate_xs=True
        )
    )

    networks = {}
    routers = {}
    servers = {}
    ports = {}

    def __init__(self, request, *args, **kwargs):
        super(PortSelectionForm, self).__init__(request, *args, **kwargs)

        tenant_id = self.request.user.tenant_id

        self.ports = api_fwaas_v2.port_list(request, tenant_id, **kwargs)
        self.networks = api_fwaas_v2.get_network_names(request)
        self.routers = api_fwaas_v2.get_router_names(request)
        self.servers = api_fwaas_v2.get_servers(request)

        self.fields['port_id'].widget.build_columns = self._build_col
        self.fields['port_id'].choices = self.get_ports(request)

    def get_ports(self, request):
        return []

    def _build_col(self, option):
        port = self.ports[option[0]]
        columns = self._build_option(port)
        return columns

    def _build_option(self, port):
        network = self.networks.get(port.network_id)

        network_label = network.name_or_id if network else port.network_id
        owner_label = ''
        device_label = ''

        if port.device_owner.startswith('network'):
            owner_label = 'network'
            router = self.routers.get(port.device_id, None)
            device_label = router.name_or_id if router else port.device_id
        elif port.device_owner.startswith('compute'):
            owner_label = 'compute'
            server = self.servers.get(port.device_id, None)
            device_label = server.name_or_id if server else port.device_id

        columns = (port.name_or_id, network_label, owner_label, device_label)

        # The return value works off of the original themeable select widget
        # This needs to be maintained for the original javascript to work
        return columns


class AddPort(PortSelectionForm):
    failure_url = 'horizon:project:firewalls_v2:index'

    def get_ports(self, request):
        used_ports = api_fwaas_v2.fwg_port_list(request)
        ports = self.ports.values()
        return [(p.id, p.id) for p in ports if p.id not in used_ports]

    def handle(self, request, context):
        firewallgroup_id = self.initial['id']
        name_or_id = context.get('name') or firewallgroup_id
        body = _get_request_body(context, self.initial)
        add_port = context['port_id']
        if add_port:
            ports = self.initial['ports']
            ports.append(add_port)
            body['ports'] = ports
        try:
            firewallgroup = api_fwaas_v2.firewall_group_update(
                request, firewallgroup_id, **body)
            msg = (_('Added the port(s) to the firewall group %s '
                     'successfully.') % name_or_id)
            messages.success(request, msg)
            return firewallgroup
        except Exception as e:
            msg = (_('Failed to add the port(s) to the firewall group '
                     '%(name)s: %(reason)s') %
                   {'name': name_or_id, 'reason': e})
            redirect = reverse(self.failure_url)
            exceptions.handle(request, msg, redirect=redirect)


class RemovePort(PortSelectionForm):
    failure_url = 'horizon:project:firewalls_v2:index'

    def get_ports(self, request):
        ports = self.initial['ports']
        return [(p, p) for p in ports]

    def handle(self, request, context):
        firewallgroup_id = self.initial['id']
        name_or_id = context.get('name') or firewallgroup_id
        body = _get_request_body(context, self.initial)
        remove_port = context['port_id']
        if remove_port:
            ports = self.initial['ports']
            ports.remove(remove_port)
            body['ports'] = ports
        try:
            firewallgroup = api_fwaas_v2.firewall_group_update(
                request, firewallgroup_id, **body)
            msg = _('Removed the port(s) from the firewall group %s '
                    'successfully.') % name_or_id
            messages.success(request, msg)
            return firewallgroup
        except Exception as e:
            msg = (_('Failed to remove the port(s) from the firewall group '
                     '%(name)s: %(reason)s') %
                   {'name': name_or_id, 'reason': e})
            redirect = reverse(self.failure_url)
            exceptions.handle(request, msg, redirect=redirect)


class InsertRuleToPolicy(forms.SelfHandlingForm):
    firewall_rule_id = forms.ThemableChoiceField(label=_("Insert Rule"))
    insert_before = forms.ThemableChoiceField(label=_("Before"),
                                              required=False)
    insert_after = forms.ThemableChoiceField(label=_("After"),
                                             required=False)

    failure_url = 'horizon:project:firewalls_v2:index'

    def __init__(self, request, *args, **kwargs):
        super(InsertRuleToPolicy, self).__init__(request, *args, **kwargs)

        try:
            tenant_id = self.request.user.tenant_id
            all_rules = api_fwaas_v2.rule_list_for_tenant(request, tenant_id)
            all_rules = sorted(all_rules, key=attrgetter('name_or_id'))

            available_rules = [r for r in all_rules]

            current_rules = []
            for x in kwargs['initial']['firewall_rules']:
                r_obj = [rule for rule in all_rules if x == rule.id][0]
                current_rules.append(r_obj)

            available_choices = [(r.id, r.name_or_id) for r in available_rules]
            current_choices = [(r.id, r.name_or_id) for r in current_rules]

        except Exception as e:
            msg = _('Failed to retrieve available rules: %s') % e
            redirect = reverse(self.failure_url)
            exceptions.handle(request, msg, redirect=redirect)

        self.fields['firewall_rule_id'].choices = available_choices
        self.fields['insert_before'].choices = [('', _('-'))] + current_choices
        self.fields['insert_after'].choices = [('', _('-'))] + current_choices

    def handle(self, request, context):
        policy_id = self.initial['id']
        policy_name_or_id = self.initial['name'] or policy_id
        try:
            insert_rule_id = context['firewall_rule_id']
            insert_rule = api_fwaas_v2.rule_get(request, insert_rule_id)
            body = {'firewall_rule_id': insert_rule_id,
                    'insert_before': context['insert_before'],
                    'insert_after': context['insert_after']}
            policy = api_fwaas_v2.policy_insert_rule(request, policy_id,
                                                     **body)
            msg = (_('Rule %(rule)s was successfully inserted to policy '
                     '%(policy)s.') %
                   {'rule': insert_rule.name or insert_rule.id,
                    'policy': policy_name_or_id})
            messages.success(request, msg)
            return policy
        except Exception as e:
            msg = (_('Failed to insert rule to policy %(name)s: %(reason)s') %
                   {'name': policy_id, 'reason': e})
            redirect = reverse(self.failure_url)
            exceptions.handle(request, msg, redirect=redirect)


class RemoveRuleFromPolicy(forms.SelfHandlingForm):
    firewall_rule_id = forms.ThemableChoiceField(label=_("Remove Rule"))

    failure_url = 'horizon:project:firewalls_v2:index'

    def __init__(self, request, *args, **kwargs):
        super(RemoveRuleFromPolicy, self).__init__(request, *args, **kwargs)

        try:
            tenant_id = request.user.tenant_id
            all_rules = api_fwaas_v2.rule_list_for_tenant(request, tenant_id)

            current_rules = []
            for r in kwargs['initial']['firewall_rules']:
                r_obj = [rule for rule in all_rules if r == rule.id][0]
                current_rules.append(r_obj)

            current_choices = [(r.id, r.name_or_id) for r in current_rules]
        except Exception as e:
            msg = (_('Failed to retrieve current rules in policy %(name)s: '
                     '%(reason)s') %
                   {'name': self.initial['name'], 'reason': e})
            redirect = reverse(self.failure_url)
            exceptions.handle(request, msg, redirect=redirect)

        self.fields['firewall_rule_id'].choices = current_choices

    def handle(self, request, context):
        policy_id = self.initial['id']
        policy_name_or_id = self.initial['name'] or policy_id
        try:
            remove_rule_id = context['firewall_rule_id']
            remove_rule = api_fwaas_v2.rule_get(request, remove_rule_id)
            body = {'firewall_rule_id': remove_rule_id}
            policy = api_fwaas_v2.policy_remove_rule(request, policy_id,
                                                     **body)
            msg = (_('Rule %(rule)s was successfully removed from policy '
                     '%(policy)s.') %
                   {'rule': remove_rule.name or remove_rule.id,
                    'policy': policy_name_or_id})
            messages.success(request, msg)
            return policy
        except Exception as e:
            msg = (_('Failed to remove rule from policy %(name)s: %(reason)s')
                   % {'name': self.initial['name'], 'reason': e})
            redirect = reverse(self.failure_url)
            exceptions.handle(request, msg, redirect=redirect)


def _get_request_body(context, initial_values):
    body = {}
    for key, value in context.items():
        # TODO(yushiro): Refactor after Q-2.
        if key == 'port_id':
            continue
        if value != initial_values[key]:
            body[key] = value
    return body
