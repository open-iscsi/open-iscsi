#
# master meson.build file for open-iscsi project
#

project('open-iscsi', 'c',
  meson_version: '>= 0.54.0',
  version: '2.1.8',
  license: 'LGPL-2.1-or-later',
  default_options: [
    'c_std=gnu99',
    'warning_level=1',
    'buildtype=release',
    'prefix=/usr']
  )
# can't set sbindir=/sbin (vs /usr/sbin) here, since that only
# works on newer version of meson (>0.63.0)

# needed for path checking
fs = import('fs')

# handle options
no_systemd = get_option('no_systemd')
home_dir = get_option('homedir')
if not fs.is_absolute(home_dir)
  home_dir = get_option('sysconfdir') / home_dir
endif
db_root = get_option('dbroot')
if not fs.is_absolute(db_root)
  db_root = get_option('sysconfdir') / db_root
endif
lock_dir = get_option('lockdir')
rules_dir = get_option('rulesdir')
if not fs.is_absolute(rules_dir)
  rules_dir = get_option('sysconfdir') / rules_dir
endif
if not no_systemd
  systemd_dir = get_option('systemddir')
  unit_dir = systemd_dir / 'system'
  generator_dir = systemd_dir /'system-generators'
endif
c_args = get_option('c_args')
man_dir = get_option('mandir')
iscsi_sbindir = get_option('iscsi_sbindir')

#
# get list of sources from subdirs (iscsiuio included at bottom)
#
subdir('sysdeps')
subdir('usr')
subdir('libopeniscsiusr')
subdir('utils')
subdir('etc')
subdir('doc')

conf = configuration_data()
conf.set('SBINDIR', iscsi_sbindir)
conf.set('HOMEDIR', home_dir)
conf.set('DBROOT', db_root)


# set up general C args
genl_cargs = [
  '-D_GNU_SOURCE',
  '-DOFFLOAD_BOOT_SUPPORTED',
  '-DISCSI_CONFIG_ROOT="@0@"'.format(home_dir),
  '-DISCSI_DB_ROOT="@0@"'.format(db_root),
  '-DLOCK_DIR="@0@"'.format(lock_dir),
  '-DISCSI_VERSION_STR="@0@"'.format(meson.project_version())]

# set up no-system flag, if needed
if no_systemd
  genl_cargs += '-DNO_SYSTEMD'
endif

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
if not no_systemd
  systemd_dep = dependency('libsystemd')
endif

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
      install_dir: man_dir / 'man3')
  endforeach
endforeach

# install our static man page(s)
install_man(libiscsi_usr_docs)

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
  test('test ' + a, e)
endforeach

# set up usr dependences and link args
usr_deps = [kmod_dep, crypto_dep, mount_dep, sysdeps_dep, fwparam_dep, libiscsi_usr_dep]
if not no_systemd
  usr_deps += systemd_dep
endif

# handle two libs that won't be found with "dependency()"
cc = meson.get_compiler('c')
usr_deps += cc.find_library('rt')
usr_deps += cc.find_library('isns')

# build iscsid, iscsiadm, and iscsistart
foreach k,v: iscsi_usr_arr
  executable(k,
    sources: v,
    include_directories: [usr_inc, main_inc, lib_inc],
    dependencies: usr_deps,
    c_args: genl_cargs,
    install: true,
    install_dir: iscsi_sbindir)
endforeach

#
# handle utility programs and scripts from 'utils'
#

# build the one binary from utils
iname_cmd = executable('iscsi-iname',
  sources: iscsi_iname_src_files,
  c_args: genl_cargs,
  install: true,
  install_dir: iscsi_sbindir)

# process shell templates (2 steps)
foreach k,v: iscsi_util_sh_template_arr
  subst = configure_file(
    input: v,
    output: k,
    configuration: conf,
    install: true,
    install_dir: iscsi_sbindir,
    install_mode: 'rwxr-xr-x')
endforeach

# process shell scripts
foreach k,v: iscsi_util_sh_arr
  install_data(v,
    rename: k,
    install_dir: iscsi_sbindir,
    install_mode: 'rwxr-xr-x')
endforeach

# process other templated files (not installed for now)
foreach k,v: iscsi_util_other_template_arr
  configure_file(
    input: v,
    output: k,
    configuration: conf,
    install: true,
    install_dir: rules_dir)
endforeach

if not no_systemd
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
      install_dir: unit_dir)
  endforeach

  # handle socket service files (not templated)
  install_data(iscsi_etc_systemd_socket_units,
    install_dir: unit_dir)

  # the systemd generator file
  install_data(iscsi_etc_systemd_generator_src,
    install_dir: generator_dir,
    install_mode: 'rwxr-xr-x')
endif

# the iface.example file
install_data(iscsi_etc_iface_file_src, install_dir: db_root / 'ifaces')

# the iscsid.conf config file
install_data(iscsi_etc_config_file_src, install_dir: home_dir)

# create a *unique* initiatorname file
if not meson.is_cross_build()
  custom_target(
    'initiatorname_file',
    output: 'initiatorname.iscsi',
    capture: true,
    command: [iname_cmd, '-g'],
    install: true,
    install_dir: home_dir,
    install_mode: 'rw-r--r--')
endif

#
# handle documentation from 'doc'
#

# handle template files
man_dir_8 = man_dir / 'man8'
foreach k,v: iscsi_doc_man_pages_template_arr
  configure_file(
    input: v,
    output: k,
    configuration: conf,
    install: true,
    install_dir: man_dir_8)
endforeach

# handle regular/static man pages
install_man(iscsi_doc_man_pages_static)

#
# lastly, build iscsiuio, which does not rely on anything outside itself -- all
#   the work is done in the meson.build file there
#
subdir('iscsiuio')
