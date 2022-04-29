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

from django.urls import re_path

from neutron_fwaas_dashboard.dashboards.project.firewalls_v2 import views

# TODO(Sarath Mekala) : Fix 'firewall' --> 'firewallgroup' in URLs as
# well as in other places.
urlpatterns = [
    re_path(r'^$', views.IndexView.as_view(), name='index'),
    re_path(r'^\?tab=fwtabs__firewalls$',
            views.IndexView.as_view(), name='firewalls'),
    re_path(r'^\?tab=fwtabs__rules$', views.IndexView.as_view(),
            name='rules'),
    re_path(r'^\?tab=fwtabs__policies$',
            views.IndexView.as_view(), name='policies'),
    re_path(r'^addrule$', views.AddRuleView.as_view(), name='addrule'),
    re_path(r'^addpolicy$', views.AddPolicyView.as_view(), name='addpolicy'),
    re_path(r'^addfirewallgroup$',
            views.AddFirewallGroupView.as_view(),
            name='addfirewallgroup'),
    re_path(r'^insertrule/(?P<policy_id>[^/]+)/$',
            views.InsertRuleToPolicyView.as_view(), name='insertrule'),
    re_path(r'^removerule/(?P<policy_id>[^/]+)/$',
            views.RemoveRuleFromPolicyView.as_view(), name='removerule'),
    re_path(r'^updaterule/(?P<rule_id>[^/]+)/$',
            views.UpdateRuleView.as_view(), name='updaterule'),
    re_path(r'^updatepolicy/(?P<policy_id>[^/]+)/$',
            views.UpdatePolicyView.as_view(), name='updatepolicy'),
    re_path(r'^updatefirewall/(?P<firewall_id>[^/]+)/$',
            views.UpdateFirewallView.as_view(), name='updatefirewall'),
    re_path(r'^addport/(?P<firewallgroup_id>[^/]+)/$',
            views.AddPortView.as_view(), name='addport'),
    re_path(r'^removeport/(?P<firewallgroup_id>[^/]+)/$',
            views.RemovePortView.as_view(), name='removeport'),
    re_path(r'^rule/(?P<rule_id>[^/]+)/$',
            views.RuleDetailsView.as_view(), name='ruledetails'),
    re_path(r'^policy/(?P<policy_id>[^/]+)/$',
            views.PolicyDetailsView.as_view(), name='policydetails'),
    re_path(r'^firewallgroup/(?P<firewallgroup_id>[^/]+)/$',
            views.FirewallGroupDetailsView.as_view(),
            name='firewallgroupdetails'),
]
