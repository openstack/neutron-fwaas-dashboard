# plugin.sh - DevStack plugin.sh dispatch script neutron-fwaas-dashboard

FWAAS_DASHBOARD_DIR=$(cd $(dirname $BASH_SOURCE)/.. && pwd)
FWAAS_ENABLED_DIR=$FWAAS_DASHBOARD_DIR/neutron_fwaas_dashboard/enabled
HORIZON_ENABLED_DIR=$DEST/horizon/openstack_dashboard/local/enabled

function install_neutron_fwaas_dashboard {
    setup_develop $FWAAS_DASHBOARD_DIR
}

function configure_neutron_fwaas_dashboard {
    if is_service_enabled neutron-fwaas-v1-dashboard; then
        cp -a $FWAAS_ENABLED_DIR/_1460_project_firewalls_panel.py $HORIZON_ENABLED_DIR
    fi
    # The following is to make vpnaas dashboard work with
    # the master horizon with neutron vpnaas support.
    # At now it seems overriding enabled file does not work.
    # (horizon bug 1700325)
    rm -f $DEST/horizon/openstack_dashboard/enabled/_1460_project_firewalls_panel.py*
    rm -f $DEST/horizon/openstack_dashboard/enabled/__pycache__/_1460_project_firewalls_panel.*
    # NOTE: If locale directory does not exist, compilemessages will fail,
    # so check for an existence of locale directory is required.
    if [ -d $FWAAS_DASHBOARD_DIR/neutron_fwaas_dashboard/locale ]; then
        (cd $FWAAS_DASHBOARD_DIR/neutron_fwaas_dashboard; \
         DJANGO_SETTINGS_MODULE=openstack_dashboard.settings ../manage.py compilemessages)
    fi
}

# check for service enabled
if is_service_enabled neutron-fwaas-v1-dashboard neutron-fwaas-v2-dashboard; then

    if [[ "$1" == "stack" && "$2" == "pre-install"  ]]; then
        # Set up system services
        # no-op
        :

    elif [[ "$1" == "stack" && "$2" == "install"  ]]; then
        # Perform installation of service source
        echo_summary "Installing Neutron FWaaS Dashboard"
        install_neutron_fwaas_dashboard

    elif [[ "$1" == "stack" && "$2" == "post-config"  ]]; then
        # Configure after the other layer 1 and 2 services have been configured
        echo_summary "Configurng Neutron FWaaS Dashboard"
        configure_neutron_fwaas_dashboard

    elif [[ "$1" == "stack" && "$2" == "extra"  ]]; then
        # no-op
        :
    fi

    if [[ "$1" == "unstack"  ]]; then
        # Remove enabled file(s)
        for _enabled_file in $FWAAS_ENABLED_DIR/_[0-9]*.py; do
            _enabled_basename=$(basename $_enabled_file .py)
            rm -f $HORIZON_ENABLED_DIR/${_enabled_basename}.py*
            rm -f $HORIZON_ENABLED_DIR/__pycache__/${_enabled_basename}.*pyc
        done
    fi

    if [[ "$1" == "clean"  ]]; then
        # Remove state and transient data
        # Remember clean.sh first calls unstack.sh
        # no-op
        :
    fi
fi
