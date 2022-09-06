#
# iscsi systemd stuff
#

# templated systemd service files
iscsi_etc_systemd_service_units = ['iscsi-init', 'iscsid', 'iscsi', 'iscsiuio']
iscsi_etc_systemd_service_units_arr = {}
foreach u: iscsi_etc_systemd_service_units
  iscsi_etc_systemd_service_units_arr += {u + '.service': files(u + '.service.template')}
endforeach

# socket files
iscsi_etc_systemd_socket_units = files(['iscsid.socket', 'iscsiuio.socket'])

# systemd generator file
iscsi_etc_systemd_generator_src = files('ibft-rule-generator')
