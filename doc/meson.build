# doc subdirectory meson file list

# static man pages
iscsi_doc_man_pages_static = files([
  'iscsi_discovery.8',
  'iscsi_fw_login.8',
  'iscsi-iname.8'])

# template man pages
iscsi_doc_man_pages_templates = [
  'iscsid',
  'iscsiadm',
  'iscsi-gen-initiatorname',
  'iscsistart']
iscsi_doc_man_pages_template_arr = {}
foreach t: iscsi_doc_man_pages_templates
  iscsi_doc_man_pages_template_arr += {t + '.8': files(t + '.8.template')}
endforeach
