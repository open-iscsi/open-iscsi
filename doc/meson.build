# doc subdirectory meson file list

# static man pages
iscsi_doc_man_pages_static = [
  'iscsi_discovery',
  'iscsi_fw_login',
  'iscsi-iname']
iscsi_doc_man_pages_static_arr = {}
foreach p: iscsi_doc_man_pages_static
  iscsi_doc_man_pages_static_arr += {p + '.8': files(p + '.8')}
endforeach

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
