#ifndef __ISCSI_NET_UTIL_h__
#define __ISCSI_NET_UTIL_h__

#define ISCSI_HWADDRESS_BUF_SIZE 18

#ifndef SBINDIR
#define SBINDIR	"/sbin"
#endif

#define ISCSIUIO_PATH SBINDIR"/iscsiuio"

extern int net_get_transport_name_from_netdev(char *netdev, char *transport);
extern int net_get_netdev_from_hwaddress(char *hwaddress, char *netdev);
extern int net_get_ip_version(char *ip);
extern int net_setup_netdev_ipv4(char *netdev, char *local_ip, char *mask,
				 char *gateway, char *vlan, char *remote_ip,
				 int needs_bringup);
extern int net_setup_netdev_ipv6(char *netdev, char *local_ip, int prefix,
				 char *gateway, char *vlan, char *remote_ip,
				 int needs_bringup);
extern int net_ifup_netdev(char *netdev);

#endif
