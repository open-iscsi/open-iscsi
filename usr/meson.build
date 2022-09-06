subdir('fwparam_ibft')

iscsi_lib_srcs = [
  'iscsi_util.c',
  'io.c',
  'auth.c',
  'iscsi_timer.c',
  'login.c',
  'log.c',
  'iface.c',
  'idbm.c',
  'sysfs.c',
  'host.c',
  'session_info.c',
  'iscsi_sysfs.c',
  'iscsi_net_util.c',
  'iscsid_req.c',
  'transport.c',
  'iser.c',
  'cxgbi.c',
  'be2iscsi.c',
  'initiator_common.c',
  'iscsi_err.c',
  'flashnode.c',
  'uip_mgmt_ipc.c',
  'netlink.c']
initiator_srcs = [
  'initiator.c',
  'scsi.c',
  'actor.c',
  'event_poll.c',
  'mgmt_ipc.c',
  'kern_err_table.c']
discovery_srcs = [
  'local_strings.c',
  'discovery.c']
iscsid_srcs = [
  'iscsid.c',
  'session_mgmt.c',
  'discoveryd.c',
  'mntcheck.c']
iscsiadm_srcs = [
  'iscsiadm.c',
  'session_mgmt.c',
  'mntcheck.c']
iscsistart_srcs = [
  'iscsistart.c']

iscsid_src_files = files([iscsi_lib_srcs, initiator_srcs, discovery_srcs, iscsid_srcs])
iscsiadm_src_files = files([iscsi_lib_srcs, discovery_srcs, iscsiadm_srcs])
iscsistart_src_files = files([iscsi_lib_srcs, initiator_srcs, iscsistart_srcs])

iscsi_usr_arr = {
  'iscsid': iscsid_src_files,
  'iscsiadm': iscsiadm_src_files,
  'iscsistart': iscsistart_src_files}
