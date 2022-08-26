project('open-iscsi', 'c',
  meson_version: '>= 0.53.0',
  version: '2.1.7',
  license: 'LGPL-2.1-or-later',
  default_options: [
    'c_std=gnu99',
    'warning_level=1',
    'buildtype=release',
    'prefix=/usr',
    'sbindir=/sbin']
  )

#
# TODO: figure out how to use version from here
#  in a config file, so it doesn't have to be defined
#  3 times
#

home_dir_absolute = get_option('homedir')
db_root_absolute = get_option('dbroot')
sbin_dir_absolute = get_option('sbindir')
rules_dir_absolute = get_option('rulesdir')
systemd_dir_absolute = get_option('systemddir')

# systemd unit dir
unit_dir_absolute = join_paths(systemd_dir_absolute, 'system')
generator_dir_absolute = join_paths(systemd_dir_absolute, 'system-generators')

#
# get list of sources from subdirs
#
subdir('sysdeps')
subdir('usr')
subdir('libopeniscsiusr')
subdir('utils')
subdir('etc')
subdir('doc')
#subdir('iscsiuio')

conf = configuration_data()
conf.set('SBINDIR', sbin_dir_absolute)
conf.set('HOMEDIR', home_dir_absolute)
conf.set('DBROOT', db_root_absolute)

home_dir_template = '-DLOCK_DIR="@0@"'
home_dir_str = home_dir_template.format(home_dir_absolute)
db_root_template = '-DISCSI_DB_ROOT="@0@"'
db_root_str = db_root_template.format(db_root_absolute)

# sett up general C args
genl_cargs = ['-D_GNU_SOURCE', '-DOFFLOAD_BOOT_SUPPORTED', home_dir_str, db_root_str]

#
# set up include directories
#
main_inc = include_directories('include')
lib_inc = include_directories('libopeniscsiusr')
usr_inc = include_directories('usr')


# set up dependencies
kmod_dep = dependency('libkmod')
crypto_dep = dependency('libcrypto')
mount_dep = dependency('mount')
sysd_dep = dependency('libsystemd')

#
# build two static libs that programs in 'usr' will need, which
# do not depend on anything local
#
libsysdeps = static_library('sysdeps', sysdeps_files,
  include_directories: [usr_inc, main_inc, lib_inc],
  c_args: '-Wno-all')
libfwparam = static_library('fwparam', fwparam_files,
  include_directories: [usr_inc, main_inc, lib_inc],
  c_args: [genl_cargs, '-Wno-all'])

#
# build libopeniscsiusr, since it does not
# depend on anything else locally
#

# build man pages for externally available interfaces

# for each header file, get a list of man pages
# from that file, then process each page, one
# at a time
foreach api_file: libiscsi_usr_doc_headers
  # get a list of pages for this header file
  c = run_command(list_pages_cmd, api_file, check: true)
  man_pages = c.stdout().split()
  # process each page, one at a time, generating dependencies
  foreach page: man_pages
#   message('DEBUG: generating man page: ' + page + ' from ' + '@0@'.format(api_file))
    custom_target(
      page.underscorify() + '_man',
      input: api_file,
      output: page + '.3',
      capture: true,
      command: [
        kernel_doc_cmd,
        '-module', 'libopeniscsiusr',
        '-man',
        '-function', page,
        api_file],
      install: true,
      install_dir: 'share/man/man3')
  endforeach
endforeach

# install our static man page(s)
install_man(libiscsi_usr_docs, install_dir: 'share/man/man3')

# build the shared library
libiscsi_usr = shared_library('openiscsiusr',
  libiscsi_usr_srcs,
  include_directories: [libiscsi_usr_private_includes, libiscsi_usr_public_includes],
  dependencies: kmod_dep,
  version: '0.2.0',
  c_args: genl_cargs,
  install: true)

# build pkg-config for libopeniscsiusr
pkg_mod = import('pkgconfig')
pkg_mod.generate(libraries: libiscsi_usr,
                 version: '0.2.0',
                 name: 'libopeniscsiusr',
                 filebase: 'libopeniscsiusr',
                 description: 'iSCSI userspace library')

install_headers([libiscsi_usr_doc_headers, libiscsi_usr_headers])

#
# handle building the main binaries, in 'usr'
#

# set up dependencies based on static libs we built
sysdeps_dep = declare_dependency(link_with: libsysdeps)
fwparam_dep = declare_dependency(link_with: libfwparam)
libiscsi_usr_dep = declare_dependency(link_with: libiscsi_usr)

# build libopeniscsi tests
foreach a,v: test_arr
  e = executable('test_' + a,
    sources: v,
    include_directories: [lib_inc],
    dependencies: libiscsi_usr_dep,
    c_args: genl_cargs)
#    install: true)
  test('test ' + a, e)
endforeach

# set up usr dependences and link args
usr_deps = [kmod_dep, crypto_dep, mount_dep, sysd_dep, sysdeps_dep, fwparam_dep, libiscsi_usr_dep]
usr_largs = []

# handle two libs that may not be found with "dependency()"
libs_needed = ['rt', 'isns']
cc = meson.get_compiler('c')
foreach l: libs_needed
  l_dep = dependency('lib' + l, required: false)
  if not l_dep.found()
    l_dep = cc.find_library(l, required: false)
  endif
  if l_dep.found()
    usr_deps += l_dep
  else
    usr_largs += '-l' + l
  endif
endforeach

# build iscsid, iscsiadm, and iscsistart
foreach k,v: iscsi_usr_arr
  executable(k,
    sources: v,
    include_directories: [usr_inc, main_inc, lib_inc],
    dependencies: usr_deps,
    link_args: usr_largs,
    c_args: genl_cargs,
    install: true,
    install_dir: sbin_dir_absolute)
endforeach

#
# handle utility programs and scripts from 'utils'
#

# build the one binary from utils
executable('iscsi-iname',
  sources: iscsi_iname_src_files,
  c_args: genl_cargs,
  install: true,
  install_dir: sbin_dir_absolute)

# process shell templates (2 steps)
foreach k,v: iscsi_util_sh_template_arr
  subst = configure_file(
    input: v,
    output: k + '.sh',
    configuration: conf)
  configure_file(
    input: subst,
    output: k,
    copy: true,
    install: true,
    install_dir: sbin_dir_absolute,
    install_mode: 'rwxr-xr-x')
endforeach

# process shell scripts
foreach k,v: iscsi_util_sh_arr
  configure_file(
    input: v,
    output: k,
    copy: true,
    install: true,
    install_dir: sbin_dir_absolute,
    install_mode: 'rwxr-xr-x')
endforeach

# process other templated files (not installed for now)
foreach k,v: iscsi_util_other_template_arr
  configure_file(
    input: v,
    output: k,
    configuration: conf,
    install: true,
    install_dir: rules_dir_absolute,
    install_mode: 'rw-r--r--')
endforeach

#
# handle stuff (systemd, config files, ...) from 'etc'
#

# handle templated service files
foreach k,v: iscsi_etc_systemd_service_units_arr
  configure_file(
    input: v,
    output: k,
    configuration: conf,
    install: true,
    install_dir: unit_dir_absolute)
endforeach

# handle socket service files (not templated)
foreach k,v: iscsi_etc_systemd_socket_units_arr
  configure_file(
    input: v,
    output: k,
    copy: true,
    install: true,
    install_dir: unit_dir_absolute)
endforeach

# the systemd generator file
foreach k,v: iscsi_etc_systemd_generator_arr
  configure_file(
    input: v,
    output: k,
    copy: true,
    install: true,
    install_dir: generator_dir_absolute,
    install_mode: 'rwxr-xr-x')
endforeach

# the iface.example file
foreach k,v: iscsi_etc_iface_file_arr
  configure_file(
    input: v,
    output: k,
    copy: true,
    install: true,
    install_dir: join_paths(home_dir_absolute, 'ifaces'))
endforeach

# the iscsid.conf config file
foreach k,v: iscsi_etc_config_file_arr
  configure_file(
    input: v,
    output: k,
    copy: true,
    install: true,
    install_dir: home_dir_absolute)
endforeach

#
# handle documentation from 'doc'
#

# handle template files
foreach k,v: iscsi_doc_man_pages_template_arr
# message('building: ' + k)
  configure_file(
    input: v,
    output: k,
    configuration: conf,
    install: true,
    install_dir: 'share/man/man8')
endforeach

# handle regular files
foreach k,v: iscsi_doc_man_pages_static_arr
# message('building: ' + k)
  configure_file(
    input: v,
    output: k,
    copy: true,
    install: true,
    install_dir: 'share/man/man8')
endforeach
