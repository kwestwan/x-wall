/*
 * Netfilter module of X-wall project. 
 * 
 * Copyright (C) 2012 Kwest <osnetdev@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/kernel.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/route.h>
#include <net/dst.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter_ipv4/ipt_XWALL.h>
#include <linux/netfilter_ipv4/ip_conntrack.h>


/*
 * 48 ~ 57: number 0~9
 * 65 ~ 90: upper case A~Z
 * 97 ~ 122: lower case a~z
 */
static char get_random_alnum(char random)
{
	if (isalnum(random))
		return random;
	
	if (random > 122) {
		random = random%122;
		if (isalnum(random))
			return random;
	}

again:	
	if (random > 90 && random < 97) {
		random = random%90;
		if (isalnum(random))
			return random;
	}
	
	if (random > 57 && random < 65) {
		random = random%57;
		if (isalnum(random))
			return random;
	}
		
	if (random < 48) {
		random += 48;
		if (isalnum(random))
			return random;
		else
			goto again;
	}
	
}

static int isalnum(char c)
{
	if ((c>='0' && c<='9') || (c>='a' && c<='z') || (c>='A' && c<='Z'))
		return 1;
	else
		return 0;
}

static char * get_http_line(char *string, int len)
{
	int i = 1;
	
	while (i <= len && string[i-1]!='\r' && string[i]!='\n') i++;

	return &string[i];
}
static int match_http_method(char *haystack)
{
	/* RFC 2616 - 5.1.1 Method */
	if(strstr(haystack, "GET")!=0 || strstr(haystack, "POST")!=0 || strstr(haystack, "HEAD")!=0
	    || strstr(haystack,"PUT")!=0 || strstr(haystack,"DELETE")!=0 || strstr(haystack, "OPTIONS")!=0
	    || strstr(haystack,"TRACE")!=0 ||strstr(haystack,"CONNECT")!=0)
	{
		return 1;
	}
	return 0;
}
static int match_http_version(char *haystack)
{
	char *version;
	version = strstr(haystack, "HTTP/");
	if(version!=NULL)
	{
		if ((version[5] > '0' && version[5] < '9') && version[6] == '.'
			&& (version[7] > '0' && version[7] < '9') )
			return 1;
	}
	return 0;
}

/*
 * skb_get_url - Get the URI from the HTTP packet
 * @ih: the pointer to IP header
 * @th: the pointer to TCP header 
 * @uri_req: the pointer to URI request
 * @uri_len: the length of URI request 
 * @host: the pointer to Host value
 * @host_len: the length of Host
 *
 * return value - 1: get success  0: get failed
 *
 */
static int skb_get_url(struct iphdr *ih, struct tcphdr *th, char *uri_req, size_t *uri_len, char *host, size_t *host_len)
{
		int datalen;
		char *data, *start, *end;
		int line_len;
		char *p_uri_start;
		char *p_uri_end;
		char *absoluteURI;
		char *abs_path;
		char *p_host_start;
		char *p_host_end;
		char *http_req;
		
		datalen = ntohs(ih->tot_len) - ih->ihl * 4 - th->doff * 4;
		if (datalen > 0)
		{
			data = (char *)th + th->doff * 4;
			start = data;
			/* 16 characters: "GET / HTTP/1.1\r\n" */
			if (datalen > 16) 
			{ 
				end = get_http_line(start, datalen);
				line_len = end - start + 1;
				datalen -= line_len;
				http_req = start;
				start = end + 1;
				if (match_http_method(http_req) && match_http_version(http_req))
				{
					abs_path = strstr(http_req, " /");
					if (abs_path == NULL) /*proxy http*/
					{
						absoluteURI = strstr(http_req, "http://");
						if (absoluteURI != NULL)
						{
							absoluteURI += 7;
							p_uri_end = strchr(absoluteURI, ' ');
							if (p_uri_end != NULL) 
							{
								uri_req = absoluteURI;
								*uri_len = p_uri_end - absoluteURI;
								host = NULL;
								*host_len = 0;
								return 1;
							}
						}
						else  /* FIXME: don't have "http://" prefix, don't comply with RFC 2616 */
						{
							p_uri_start = strchr(http_req, ' ');
							if (p_uri_start != NULL)
							{
								p_uri_start++;
								p_uri_end = strchr(p_uri_start, ' ');
								if (p_uri_end != NULL)
								{
									uri_req = p_uri_start;
									*uri_len = p_uri_end - p_uri_start;
									host = NULL;
									*host_len = 0;
									return 1;
								}
							}
						}
					}
					else
					{
						abs_path++; //ignore first blank
						p_uri_end = strchr(abs_path, ' ');
						if (p_uri_end != NULL)
						{
							uri_req = abs_path;
							*uri_len = p_uri_end - abs_path;
						}
						
						while (datalen > 6) /* 6 characters: "Host: " */
						{
							end = get_http_line(start, datalen);
							line_len = end - start + 1;
							datalen -= line_len;
							
							p_host_start = strstr(start, "Host: ");
							if (p_host_start != NULL)
							{
								p_host_start += 6;
								p_host_end = strchr(p_host_start, '\r');
								if (p_host_end != NULL)
								{
									host = p_host_start;
									*host_len = p_host_end - p_host_start;
									return 1;
								}
							}

							start = end + 1;
						}
					}
				}

			}
		}

		return 0;
}


static unsigned int ipt_xwall_target(struct sk_buff **pskb,
			   const struct net_device *in,
			   const struct net_device *out,
			   unsigned int hooknum,
			   const struct xt_target *target,
			   const void *targinfo)
{
	const struct ipt_XWALL_info *info = targinfo;
	struct sk_buff *oldskb = *pskb;
	struct sk_buff *nskb;
	__u16 payload_len = 0;
	unsigned int addr_type, extra_space_needed;
	int i;
	struct udphdr *udph;
	struct iphdr *iph;
	__be32 saddr;
	struct ip_conntrack *conntrack;
	enum ip_conntrack_info ctinfo;
	__be32 nat_saddr = 0;
	__be16 nat_sport = 0;
	struct tcphdr _otcph, *oth, *tcph;
	char *uri_req, *host;
	int uri_len, host_len, i;
	char random, new_alnum;

	iph = oldskb->nh.iph;
	
	/* IP header checks: fragment. If packet is fragment, just ignore it. */
	if (oldskb->nh.iph->frag_off & htons(IP_OFFSET))
		return NF_ACCEPT;

	oth = skb_header_pointer(oldskb, oldskb->nh.iph->ihl * 4,
				 sizeof(_otcph), &_otcph);
	if (oth == NULL)
		return NF_ACCEPT;
	
	/* Check checksum */
	if (nf_ip_checksum(oldskb, hooknum, iph->ihl * 4, IPPROTO_TCP))
		return NF_ACCEPT;
	
	/* Save the packet length, it will be the payload length after packing. */
	payload_len = oldskb->len;

	/* Save the old source addr. */
	saddr = iph->saddr;

	/* In case NAT enabled, record the NATed source IP and source Port */
	conntrack = ip_conntrack_get(oldskb, &ctinfo);
	if (test_bit(IPS_SRC_NAT_BIT, &conntrack->status)) {
		nat_saddr = conntrack->tuplehash[IP_CT_DIR_REPLY].tuple.dst.ip;
		nat_sport = conntrack->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u.tcp.port;
	}

	/* We need a linear, writeable skb.  We also need to expand
	   headroom in case hh_len of incoming interface < hh_len of
	   outgoing interface */
	extra_space_needed = sizeof(struct udphdr) + sizeof(struct iphdr);
	nskb = skb_copy_expand(oldskb, extra_space_needed, skb_tailroom(oldskb),
			       GFP_ATOMIC);
	if (!nskb)
		return NF_ACCEPT;

	/* Make sure there is enough space to put UDP header 
	   and allocate some memory if not enough. */
	if (skb_headroom(nskb) < extra_space_needed) {
		if (pskb_expand_head(nskb, extra_space_needed, 0, GFP_ATOMIC)) {
			pr_info("iptables: ipt_XWALL: no enough space and unable to allocate more. ");
			goto free_nskb;
		}
	}

	/* This packet will not be the same as the other: clear nf fields */
	nf_reset(nskb);
	nskb->mark = 0;
	skb_init_secmark(nskb);

	skb_shinfo(nskb)->gso_size = 0;
	skb_shinfo(nskb)->gso_segs = 0;
	skb_shinfo(nskb)->gso_type = 0;

	iph = nskb->nh.iph;
	
	/* In case NAT enabled, IP saddr and TCP sport will be changed */
	if (test_bit(IPS_SRC_NAT_BIT, &conntrack->status)) {
		iph->saddr = nat_saddr;
		/* Adjust IP checksum */
		ip_send_check(iph);
		
		tcph = (struct tcphdr *)((u_int32_t*)nskb->nh.iph + nskb->nh.iph->ihl);
		tcph->source = nat_sport;
		/* Adjust TCP checksum */
		tcph->check = 0;
		tcph->check = tcp_v4_check(sizeof(struct tcphdr),
				   iph->saddr,
				   iph->daddr,
				   csum_partial((char *)tcph,
							sizeof(struct tcphdr), 0));
	}

	/* Encrypt the packet if specified. */
	if (info->xor_key != 0) {	
		for (i = 0; i < payload_len; i++) {
			(*((char*)iph + i)) ^= info->xor_key;
		}
	}

	/* Do checksum of payload. */
	nskb->csum = csum_partial(iph, payload_len, 0);

	/* Get UDP header pointer. */
	udph = (struct udphdr*)skb_push(nskb, sizeof(struct udphdr));

	/* Construct UDP header. */
	udph->source = htons((unsigned short)net_random());
	udph->dest = info->udp_port;
	udph->len = htons(sizeof(struct udphdr) + payload_len);
	/* Do checksums of UDP header and combine the payload checksum */
	udph->check = 0;
	nskb->csum = csum_partial((char *)udph, sizeof(struct udphdr), nskb->csum);
	udph->check = csum_tcpudp_magic(saddr, info->gateway, payload_len + sizeof(struct udphdr), IPPROTO_UDP, nskb->csum);
	if (!udph->check)
		udph->check = CSUM_MANGLED_0;

	/* Get IP header. */
	nskb->nh.iph = iph = (struct iphdr*)skb_push(nskb, sizeof(struct iphdr));

	/* Construct IP header. */
	iph->version = 4;
	iph->ihl = 5;
	iph->tos = 0;
	iph->tot_len = htons(nskb->len);
	iph->frag_off = htons(IP_DF);
	iph->id = (unsigned short)net_random();
	iph->ttl = 64;
	iph->protocol = IPPROTO_UDP;
	iph->saddr = saddr;
	iph->daddr = info->gateway;
	ip_send_check(iph);

	addr_type = RTN_UNSPEC;

	if (ip_route_me_harder(&nskb, addr_type))
		goto free_nskb;

	/* "Never happens" */
	if (nskb->len > dst_mtu(nskb->dst))
		goto free_nskb;

	NF_HOOK(PF_INET, NF_IP_LOCAL_OUT, nskb, NULL, nskb->dst->dev,
		dst_output);

	if (!skb_make_writable(pskb, (*pskb)->len))
		goto free_nskb;

	tcph = (struct tcphdr *)((u_int32_t*)oldskb->nh.iph + oldskb->nh.iph->ihl);
	iph = oldskb->nh.iph;
	
	if ( !skb_get_url(iph, tcph, uri_req, &uri_len, host, &host_len))
		goto free_nskb;

	if (uri_req!=NULL && uri_len!=0) {
		for (i=0; i<uri_len; i++) {
			if (isalnum(uri_req[i])) 
			{
				get_random_bytes(&random, sizeof(random));
				new_alnum = get_random_alnum(random);
				uri_req[i] = new_alnum;
			}
		}
	}

	if (host!=NULL && host_len!=0) {
		for (i=0; i<host_len; i++) {
			if (isalnum(host[i]))
			{
				get_random_bytes(&random, sizeof(random));
				new_alnum = get_random_alnum(random);
				host[i] = new_alnum;
			}
		}
	}
	
	return NF_ACCEPT;
	
free_nskb:
	kfree_skb(nskb);
	return NF_ACCEPT;
}

static int ipt_xwall_check(const char *tablename,
		 const void *e_void,
		 const struct xt_target *target,
		 void *targinfo,
		 unsigned int hook_mask)
{
	const struct ipt_entry *e = e_void;
	
	if (e->ip.proto != IPPROTO_TCP || (e->ip.invflags & XT_INV_PROTO)) {
		printk(KERN_WARNING "ipt_XWALL: cannot use this target for non-tcp session\n");
		return 0;
	}

	return 1;
}

static struct xt_target ipt_XWALL __read_mostly = {
	.name		= "XWALL",
	.family		= AF_INET,
	.target		= ipt_xwall_target,
	.targetsize	= sizeof(struct ipt_XWALL_info),
	.table		= "filter",
	.hooks		= (1 << NF_IP_FORWARD),
	.checkentry	= ipt_xwall_check,
	.me		= THIS_MODULE,
};

static int __init ipt_xwall_init(void)
{
	return xt_register_target(&ipt_XWALL);
}

static void __exit ipt_xwall_exit(void)
{
	xt_unregister_target(&ipt_XWALL);
}

module_init(ipt_xwall_init);
module_exit(ipt_xwall_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kwest");
MODULE_DESCRIPTION("Netfilter module of X-wall project. ");
MODULE_ALIAS("ipt_XWALL");

