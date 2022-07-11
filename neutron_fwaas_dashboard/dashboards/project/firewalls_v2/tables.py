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

from django.template import defaultfilters as filters
from django.urls import reverse
from django.utils.translation import gettext_lazy as _
from django.utils.translation import ngettext_lazy
from django.utils.translation import pgettext_lazy

from horizon import exceptions
from horizon import tables
from openstack_dashboard.dashboards.project.networks.ports \
    import tables as port_tables
from openstack_dashboard import policy

from neutron_fwaas_dashboard.api import fwaas_v2 as api_fwaas_v2


LOG = logging.getLogger(__name__)


class AddRuleLink(tables.LinkAction):
    name = "addrule"
    verbose_name = _("Add Rule")
    url = "horizon:project:firewalls_v2:addrule"
    classes = ("ajax-modal",)
    icon = "plus"
    policy_rules = (("neutron-fwaas", "create_fwaas_firewall_rule"),)


class AddPolicyLink(tables.LinkAction):
    name = "addpolicy"
    verbose_name = _("Add Policy")
    url = "horizon:project:firewalls_v2:addpolicy"
    classes = ("ajax-modal", "btn-addpolicy",)
    icon = "plus"
    policy_rules = (("neutron-fwaas", "create_fwaas_firewall_policy"),)


class AddFirewallGroupLink(tables.LinkAction):
    name = "addfirewallgroup"
    verbose_name = _("Create Firewall Group")
    url = "horizon:project:firewalls_v2:addfirewallgroup"
    classes = ("ajax-modal",)
    icon = "plus"
    policy_rules = (("neutron-fwaas", "create_fwaas_firewall_group"),)


class DeleteRuleLink(policy.PolicyTargetMixin, tables.DeleteAction):
    name = "deleterule"
    policy_rules = (("neutron-fwaas", "delete_fwaas_firewall_rule"),)

    @staticmethod
    def action_present(count):
        return ngettext_lazy(
            u"Delete Rule",
            u"Delete Rules",
            count
        )

    @staticmethod
    def action_past(count):
        return ngettext_lazy(
            u"Scheduled deletion of Rule",
            u"Scheduled deletion of Rules",
            count
        )

    def allowed(self, request, datum=None):
        # TODO(Sarath Mekala): If the rule is associated with a policy then
        # return false.
        return True

    def delete(self, request, obj_id):
        try:
            api_fwaas_v2.rule_delete(request, obj_id)
        except Exception as e:
            exceptions.handle(request, _('Unable to delete rule. %s') % e)


class DeletePolicyLink(policy.PolicyTargetMixin, tables.DeleteAction):
    name = "deletepolicy"
    policy_rules = (("neutron-fwaas", "delete_fwaas_firewall_policy"),)

    @staticmethod
    def action_present(count):
        return ngettext_lazy(
            u"Delete Policy",
            u"Delete Policies",
            count
        )

    @staticmethod
    def action_past(count):
        return ngettext_lazy(
            u"Scheduled deletion of Policy",
            u"Scheduled deletion of Policies",
            count
        )

    def delete(self, request, obj_id):
        try:
            api_fwaas_v2.policy_delete(request, obj_id)
        except Exception as e:
            exceptions.handle(request, _('Unable to delete policy. %s') % e)


class DeleteFirewallGroupLink(policy.PolicyTargetMixin,
                              tables.DeleteAction):
    name = "deletefirewallgroup"
    policy_rules = (("neutron-fwaas", "delete_fwaas_firewall_group"),)

    @staticmethod
    def action_present(count):
        return ngettext_lazy(
            u"Delete Firewall Group",
            u"Delete Firewall Groups",
            count
        )

    @staticmethod
    def action_past(count):
        return ngettext_lazy(
            u"Scheduled deletion of Firewall Group",
            u"Scheduled deletion of Firewall Groups",
            count
        )

    def delete(self, request, obj_id):
        try:
            api_fwaas_v2.firewall_group_delete(request, obj_id)
        except Exception as e:
            exceptions.handle(request,
                              _('Unable to delete firewall group. %s') % e)


class UpdateRuleLink(policy.PolicyTargetMixin, tables.LinkAction):
    name = "updaterule"
    verbose_name = _("Edit Rule")
    classes = ("ajax-modal", "btn-update",)
    policy_rules = (("neutron-fwaas", "update_fwaas_firewall_rule"),)

    def get_link_url(self, rule):
        return reverse("horizon:project:firewalls_v2:updaterule",
                       kwargs={'rule_id': rule.id})


class UpdatePolicyLink(policy.PolicyTargetMixin, tables.LinkAction):
    name = "updatepolicy"
    verbose_name = _("Edit Policy")
    classes = ("ajax-modal", "btn-update",)
    policy_rules = (("neutron-fwaas", "update_fwaas_firewall_policy"),)

    def get_link_url(self, policy):
        return reverse("horizon:project:firewalls_v2:updatepolicy",
                       kwargs={'policy_id': policy.id})


class UpdateFirewallGroupLink(policy.PolicyTargetMixin, tables.LinkAction):
    name = "updatefirewall"
    verbose_name = _("Edit Firewall Group")
    classes = ("ajax-modal", "btn-update",)
    policy_rules = (("neutron-fwaas", "update_firewall"),)

    def get_link_url(self, firewallgroup):
        return reverse("horizon:project:firewalls_v2:updatefirewall",
                       kwargs={'firewall_id': firewallgroup.id})

    def allowed(self, request, firewallgroup):
        return firewallgroup.status not in (
            "PENDING_CREATE",
            "PENDING_UPDATE",
            "PENDING_DELETE")


class InsertRuleToPolicyLink(policy.PolicyTargetMixin,
                             tables.LinkAction):
    name = "insertrule"
    verbose_name = _("Insert Rule")
    classes = ("ajax-modal", "btn-update",)
    policy_rules = (("neutron-fwaas", "show_fwaas_firewall_policy"),
                    ("neutron-fwaas", "insert_rule_fwaas_firewall_policy"),)

    def get_link_url(self, policy):
        return reverse("horizon:project:firewalls_v2:insertrule",
                       kwargs={'policy_id': policy.id})


class RemoveRuleFromPolicyLink(policy.PolicyTargetMixin,
                               tables.LinkAction):
    name = "removerule"
    verbose_name = _("Remove Rule")
    classes = ("ajax-modal",)
    policy_rules = (("neutron-fwaas", "show_fwaas_firewall_policy"),
                    ("neutron-fwaas", "firewall_policy_remove_rule"),)
    action_type = "danger"

    def get_link_url(self, policy):
        return reverse("horizon:project:firewalls_v2:removerule",
                       kwargs={'policy_id': policy.id})

    def allowed(self, request, policy):
        return bool(policy.rules)


class AddPortToFirewallGroupLink(policy.PolicyTargetMixin,
                                 tables.LinkAction):
    name = "addport"
    verbose_name = _("Add Port")
    classes = ("ajax-modal", "btn-update",)
    policy_rules = (("neutron-fwaas", "update_fwaas_firewall_group"),)

    def get_link_url(self, firewallgroup):
        return reverse("horizon:project:firewalls_v2:addport",
                       kwargs={'firewallgroup_id': firewallgroup.id})

    def allowed(self, request, firewallgroup):
        return firewallgroup.status not in (
            "PENDING_CREATE",
            "PENDING_UPDATE",
            "PENDING_DELETE")


class RemovePortFromFirewallGroupLink(policy.PolicyTargetMixin,
                                      tables.LinkAction):
    name = "removeport"
    verbose_name = _("Remove Port")
    classes = ("ajax-modal", "btn-update",)
    policy_rules = (("neutron-fwaas", "update_fwaas_firewall_group"),)

    def get_link_url(self, firewallgroup):
        return reverse("horizon:project:firewalls_v2:removeport",
                       kwargs={'firewallgroup_id': firewallgroup.id})

    def allowed(self, request, firewallgroup):
        return firewallgroup.status not in (
            "PENDING_CREATE",
            "PENDING_UPDATE",
            "PENDING_DELETE")


def get_rules_name(datum):
    return ', '.join([rule.name_or_id for rule in datum.rules])


def get_ports_name(datum):
    return len(datum.ports)


def get_ports_link(datum):
    url = reverse("horizon:project:firewalls_v2:firewallgroupdetails",
                  args=(datum.id,))
    return '%s?tab=%s__%s' % (url, 'firewallgrouptabs', 'ports_tab')


def get_ingress_policy_link(datum):
    if datum.ingress_firewall_policy_id:
        return reverse('horizon:project:firewalls_v2:policydetails',
                       kwargs={'policy_id': datum.ingress_firewall_policy_id})


def get_egress_policy_link(datum):
    if datum.egress_firewall_policy_id:
        return reverse('horizon:project:firewalls_v2:policydetails',
                       kwargs={'policy_id': datum.egress_firewall_policy_id})


def get_ingress_policy_name(datum):
    if datum.ingress_firewall_policy_id:
        return datum.ingress_policy.name


def get_egress_policy_name(datum):
    if datum.egress_firewall_policy_id:
        return datum.egress_policy.name


class RulesTable(tables.DataTable):
    ACTION_DISPLAY_CHOICES = (
        ("Allow", pgettext_lazy("Action Name of a Firewall Rule", u"ALLOW")),
        ("Deny", pgettext_lazy("Action Name of a Firewall Rule", u"DENY")),
        ("Reject", pgettext_lazy("Action Name of a Firewall Rule", u"REJECT")),
    )
    name = tables.Column("name_or_id",
                         verbose_name=_("Name"),
                         link="horizon:project:firewalls_v2:ruledetails")
    description = tables.Column('description', verbose_name=_('Description'))
    ip_version = tables.Column('ip_version', verbose_name=('IP Version'))
    protocol = tables.Column("protocol",
                             filters=(lambda v: filters.default(v, _("ANY")),
                                      filters.upper,),
                             verbose_name=_("Protocol"))
    source_ip_address = tables.Column("source_ip_address",
                                      verbose_name=_("Source IP"))
    source_port = tables.Column("source_port",
                                verbose_name=_("Source Port"))
    destination_ip_address = tables.Column("destination_ip_address",
                                           verbose_name=_("Destination IP"))
    destination_port = tables.Column("destination_port",
                                     verbose_name=_("Destination Port"))
    action = tables.Column("action",
                           display_choices=ACTION_DISPLAY_CHOICES,
                           verbose_name=_("Action"))
    shared = tables.Column("shared",
                           verbose_name=_("Shared"),
                           filters=(filters.yesno, filters.capfirst))
    enabled = tables.Column("enabled",
                            verbose_name=_("Enabled"),
                            filters=(filters.yesno, filters.capfirst))

    class Meta(object):
        name = "rulestable"
        verbose_name = _("Rules")
        table_actions = (AddRuleLink,
                         DeleteRuleLink,
                         tables.NameFilterAction)
        row_actions = (UpdateRuleLink, DeleteRuleLink)


class PoliciesTable(tables.DataTable):
    name = tables.Column("name_or_id",
                         verbose_name=_("Name"),
                         link="horizon:project:firewalls_v2:policydetails")
    description = tables.Column('description', verbose_name=_('Description'))
    firewall_rules = tables.Column(get_rules_name,
                                   verbose_name=_("Rules"))
    shared = tables.Column("shared",
                           verbose_name=_("Shared"),
                           filters=(filters.yesno, filters.capfirst))
    audited = tables.Column("audited",
                            verbose_name=_("Audited"),
                            filters=(filters.yesno, filters.capfirst))

    class Meta(object):
        name = "policiestable"
        verbose_name = _("Policies")
        table_actions = (AddPolicyLink,
                         DeletePolicyLink,
                         tables.NameFilterAction)
        row_actions = (UpdatePolicyLink, InsertRuleToPolicyLink,
                       RemoveRuleFromPolicyLink, DeletePolicyLink)


class FirewallGroupsTable(tables.DataTable):
    STATUS_DISPLAY_CHOICES = (
        ("Active", pgettext_lazy("Current status of a Firewall Group",
                                 u"Active")),
        ("Down", pgettext_lazy("Current status of a Firewall Group",
                               u"Down")),
        ("Error", pgettext_lazy("Current status of a Firewall Group",
                                u"Error")),
        ("Created", pgettext_lazy("Current status of a Firewall Group",
                                  u"Created")),
        ("Pending_Create", pgettext_lazy("Current status of a Firewall Group",
                                         u"Pending Create")),
        ("Pending_Update", pgettext_lazy("Current status of a Firewall Group",
                                         u"Pending Update")),
        ("Pending_Delete", pgettext_lazy("Current status of a Firewall Group",
                                         u"Pending Delete")),
        ("Inactive", pgettext_lazy("Current status of a Firewall Group",
                                   u"Inactive")),
    )
    ADMIN_STATE_DISPLAY_CHOICES = (
        ("UP", pgettext_lazy("Admin state of a Firewall Group", u"UP")),
        ("DOWN", pgettext_lazy("Admin state of a Firewall Group", u"DOWN")),
    )

    name = tables.Column(
        "name_or_id",
        verbose_name=_("Name"),
        link="horizon:project:firewalls_v2:firewallgroupdetails")
    description = tables.Column('description', verbose_name=_('Description'))
    ingress_firewall_policy_id = tables.Column(
        get_ingress_policy_name,
        link=get_ingress_policy_link,
        verbose_name=_("Ingress Policy"))
    egress_firewall_policy_id = tables.Column(get_egress_policy_name,
                                              link=get_egress_policy_link,
                                              verbose_name=_("Egress Policy"))
    ports = tables.Column(get_ports_name,
                          link=get_ports_link,
                          verbose_name=_("Ports"))

    status = tables.Column("status",
                           verbose_name=_("Status"),
                           display_choices=STATUS_DISPLAY_CHOICES)
    admin_state_up = tables.Column("admin_state_up",
                                   verbose_name=_("Admin State"))
    shared = tables.Column("shared",
                           verbose_name=_("Shared"),
                           filters=(filters.yesno, filters.capfirst))

    class Meta(object):
        name = "FirewallGroupsTable"
        verbose_name = _("Firewall Groups")
        table_actions = (AddFirewallGroupLink,
                         DeleteFirewallGroupLink,
                         tables.NameFilterAction)
        row_actions = (
            UpdateFirewallGroupLink,
            DeleteFirewallGroupLink,
            AddPortToFirewallGroupLink,
            RemovePortFromFirewallGroupLink)


class FirewallGroupPortsTable(port_tables.PortsTable):

    class Meta(object):
        name = 'ports'
        verbose_name = _('Ports')
        table_actions = []
        row_actions = []
