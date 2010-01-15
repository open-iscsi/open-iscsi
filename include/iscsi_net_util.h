#ifndef __ISCSI_NET_UTIL_h__
#define __ISCSI_NET_UTIL_h__

#define ISCSI_HWADDRESS_BUF_SIZE 18

extern int net_get_transport_name_from_netdev(char *netdev, char *transport);
extern int net_get_netdev_from_hwaddress(char *hwaddress, char *netdev);
extern int net_setup_netdev(char *netdev, char *local_ip, char *mask,
			    char *gateway, char *remote_ip, int needs_bringup);

#endif
