#ifndef __ISCSI_NET_UTIL_h__
#define __ISCSI_NET_UTIL_h__

#define ISCSI_HWADDRESS_BUF_SIZE 18

extern int net_get_transport_name_from_iface(char *iface, char *transport);
extern int net_get_dev_from_hwaddress(char *hwaddress, char *netdev);

#endif
