#
# meson build file for iscsiuio/src/unix
#

# build date files since 'libs' needs them

build_date_cmd = find_program('build_date.sh')

src_date_epoch = get_option('source_date_epoch')
epoch_date_arg = []
message('Source Date Epoch: ' + src_date_epoch)
if src_date_epoch != 'NONE'
  epoch_date_arg = ['-s', src_date_epoch]
endif

build_date_src = custom_target('build_date.c',
  output: 'build_date.c',
  command: [build_date_cmd, '-c', '@OUTPUT@'] + epoch_date_arg)

build_date_inc = custom_target('build_date.h',
  output: 'build_date.h',
  command: [build_date_cmd, '-i', '@OUTPUT@'])

subdir('libs')

iscsiuio_srcs = files(
  'main.c',
  'clock-arch.c',
  'logger.c',
  'nic.c',
  'nic_id.c',
  'nic_vlan.c',
  'nic_nl.c',
  'nic_utils.c',
  'packet.c',
  'iscsid_ipc.c',
  'ping.c')
