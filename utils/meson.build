# meson build file for utils

# sources for iscsi_iname
iscsi_iname_src_files = [files(
  'iscsi-iname.c',
  'md5.c')]

# templated shell scripts (NAME.sh.template -> NAME.sh -> NAME)
iscsi_util_sh_template_tgts = [
  'iscsi_fw_login',
  'iscsi-gen-initiatorname']
iscsi_util_sh_template_arr = {}
foreach t: iscsi_util_sh_template_tgts
  iscsi_util_sh_template_arr += {t: files(t + '.sh.template')}
endforeach

# regular shell scripts (NAME.sh -> NAME)
iscsi_util_sh_tgts = [
  'iscsi_discovery',
  'iscsi_offload']
iscsi_util_sh_arr = {}
foreach t: iscsi_util_sh_tgts 
  iscsi_util_sh_arr += {t: files(t + '.sh')}
endforeach

# other templated files (NAME.template -> NAME)
iscsi_util_other_template_tgts = [
  '50-iscsi-firmware-login.rules']
iscsi_util_other_template_arr = {}
foreach t: iscsi_util_other_template_tgts
  iscsi_util_other_template_arr += {t: files(t + '.template')}
endforeach
