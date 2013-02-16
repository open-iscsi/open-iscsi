#ifndef __UIP_ETH_H__
#define __UIP_ETH_H__

#include "uipopt.h"

/*******************************************************************************
 * Ether types
 ******************************************************************************/
#define UIP_ETHTYPE_ARP		0x0806
#define UIP_ETHTYPE_IPv4	0x0800
#define UIP_ETHTYPE_8021Q	0x8100
#define UIP_ETHTYPE_IPv6	0x86dd

/**
 * Representation of a 48-bit Ethernet address.
 */
struct uip_eth_addr {
	u8_t addr[6];
};

/**
 * The Ethernet header.
 */
struct __attribute__ ((__packed__)) uip_eth_hdr {
	struct uip_eth_addr dest;
	struct uip_eth_addr src;
	u16_t type;
};

/**
 * The 802.1Q Ethernet header (VLAN).
 */
struct __attribute__ ((__packed__)) uip_vlan_eth_hdr {
	struct uip_eth_addr dest;
	struct uip_eth_addr src;
	u16_t tpid;
	u16_t vid;
	u16_t type;
};

int is_vlan_packet(struct uip_vlan_eth_hdr *hdr);

#endif /* __UIP_ETH_H__ */
