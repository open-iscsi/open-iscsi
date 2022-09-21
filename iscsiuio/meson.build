#
# meson control file for iscsiuio
#
# this file is meant to be more-or-less standalone, so
# all work is done from here, not requiring anything from
# the parallel open-iscsi directories, except an include file (iscsi_if.h)
#

# TODO: setup handling systemd vs no-systemd


subdir('src')
subdir('docs')

log_rotate_dir = get_option('sysconfdir') / 'logrotate.d'

#
# our VERSION
#
iscsiuio_version = '0.7.8.6'
release_template = '-DPACKAGE_VERSION="@0@"'
release_str = release_template.format(iscsiuio_version)

#
# set up include directories
#
src_uip_inc = include_directories('src/uip')
src_unix_inc = include_directories('src/unix')
src_unix_libs_inc = include_directories('src/unix/libs')
src_apps_dhcpc_inc = include_directories('src/apps/dhcpc')
src_apps_brcm_iscsi_inc = include_directories('src/apps/brcm-iscsi')
# make nice names for the stuff outside of our tree (in open-iscsi tree)
open_iscsi_include_inc = main_inc
open_iscsi_usr_inc = usr_inc

#
# C arguments
#
iscsiuio_c_args = [release_str]
if no_systemd
  iscsiuio_c_args += '-DNO_SYSTEMD'
endif

#
# build the all the static libs that we will need
#

lib_apps_dhcpc = static_library('apps_dhcpc', dhcpc_srcs,
  include_directories: [src_uip_inc, src_unix_inc, open_iscsi_include_inc])

lib_apps_brcm_iscsi = static_library('apps_brcm_iscsi', brcm_iscsi_srcs,
  include_directories: [src_uip_inc, src_unix_inc, open_iscsi_include_inc])

lib_iscsi_uip = static_library('iscsi_uip', lib_iscsi_uip_srcs,
  include_directories: [
    src_unix_inc,
    src_apps_dhcpc_inc,
    src_uip_inc,
    open_iscsi_include_inc,
    src_apps_brcm_iscsi_inc])

lib_iscsiuio_hw_cnic = static_library('iscsiuio_hw_cnic',
  lib_iscsiuio_hw_cnic_srcs,
  include_directories: [
    src_uip_inc,
    src_unix_inc,
    open_iscsi_include_inc,
    open_iscsi_usr_inc],
  c_args: iscsiuio_c_args)

#
# finally, build the iscsiuo binary
#

# set up dependencies
dhcpc_dep = declare_dependency(link_with: lib_apps_dhcpc)
brcm_dep = declare_dependency(link_with: lib_apps_brcm_iscsi)
iscsi_uip_dep = declare_dependency(link_with: lib_iscsi_uip)
iscsiuio_hw_cnic_dep = declare_dependency(link_with: lib_iscsiuio_hw_cnic)
pthread_dep = dependency('threads')

iscsiuio_deps = [
  dhcpc_dep,
  brcm_dep,
  iscsi_uip_dep,
  iscsiuio_hw_cnic_dep,
  sysdeps_dep,
  pthread_dep]

if not no_systemd
  iscsiuio_deps += systemd_dep
endif

# build the binary itself
iscsiuio = executable('iscsiuio',
  [iscsiuio_srcs, build_date_src, build_date_inc],
  dependencies: iscsiuio_deps,
  include_directories: [
    src_uip_inc,
    src_apps_dhcpc_inc,
    src_unix_inc,
    open_iscsi_include_inc,
    open_iscsi_usr_inc,
    src_unix_libs_inc,
    src_apps_brcm_iscsi_inc],
  c_args: iscsiuio_c_args,
  install: true,
  install_dir: iscsi_sbindir)

# now make a symlink (only works on newer meson versions)
if meson.version().version_compare('>= 0.61.0')
  install_symlink('brcm_iscsiuio',
    install_dir: iscsi_sbindir,
    pointing_to: 'iscsiuio')
else
  warning('You must create the brcm_iscsiuio->iscsiuio symlink yourself in this version of meson.')
endif

# install uiolog
install_data(files('iscsiuiolog'), install_dir: log_rotate_dir)

# install man page
install_man(iscsiuio_doc_man_page_src, install_dir: man_dir_8)
