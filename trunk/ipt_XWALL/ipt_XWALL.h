#ifndef _IPT_XWALL_H
#define _IPT_XWALL_H

/* Data structure only supports IPv4. */
struct ipt_XWALL_info {
	__be32 gateway;	/* Virtual gateway. Network order */
	__be16 udp_port; 	/* The UDP port the virtual gateway listens on.  Network order */
	__u8 xor_key; 	/* Encrytion key, ignore when type is none. */
}; 

enum {
	IPT_XWALL_PARAM_GATEWAY = 1 << 0,
	IPT_XWALL_PARAM_XOR = 1 << 1,
	IPT_XWALL_PARAM_UDP_PORT = 1 << 2,
};

#endif /* _IPT_XWALL_H */

