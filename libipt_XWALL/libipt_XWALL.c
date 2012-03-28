/*
 * Shared library add-on to iptables to add X-wall support.
 *
 * Copyright (C) 2012 Kwest <osnetdev@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */
#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <iptables.h>
#include <linux/types.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter_ipv4/ipt_XWALL.h>

/* Function which prints out usage message. */
static void help(void)
{
	printf(
"XWALL v%s target options:\n"
"  --gateway                The target host to redirect traffic. \n"
"  --udp-port               The UDP port X-wall server listens on. \n"
"  --xor                         Use logical xor to encrypt packet. 1 ~255 \n\n",
IPTABLES_VERSION);
}

static struct option opts[] = {
	{ "gateway", 1, 0, '1'},
	{ "xor", 1, 0, '2'},
	{ "udp-port", 1, 0, '3'},
	{ 0 }
};

/* Initialize the target. */
static void
init(struct ipt_entry_target *t, unsigned int *nfcache)
{
	struct ipt_XWALL_info *info = (struct ipt_XWALL_info *)t->data;
	
	info->xor_key = 0;
}

/* Function which parses command options; returns true if it
   ate an option */
static int
parse(int c, char **argv, int invert, unsigned int *flags,
      const struct ipt_entry *entry,
      struct ipt_entry_target **target)
{
	struct ipt_XWALL_info *info = (struct ipt_XWALL_info *)(*target)->data;

	switch (c) {
		case '1': /* --gateway */
		{
			if (check_inverse(optarg, &invert, NULL, 0)) {
				exit_error(PARAMETER_PROBLEM, "Unexpected `!' after --gateway");
			}
			
			if (*flags & IPT_XWALL_PARAM_GATEWAY) {
				exit_error(PARAMETER_PROBLEM, "Multiple --gateway not supported");
			}

			struct in_addr *addr;
			addr = dotted_to_addr(optarg);
			if (!addr) {
				exit_error(PARAMETER_PROBLEM, "Bad IP address \"%s\"\n", optarg);
			}
			info->gateway = addr->s_addr;
			*flags |= IPT_XWALL_PARAM_GATEWAY;
			
			break;
		}
		case '2': /* --xor */
		{
			if (check_inverse(optarg, &invert, NULL, 0)) {
				exit_error(PARAMETER_PROBLEM, "Unexpected `!' after --xor");
			}

			if (*flags & IPT_XWALL_PARAM_XOR) {
				exit_error(PARAMETER_PROBLEM, "Multiple --xor not supported");
			}
			if (atoi(optarg) < 0 || atoi(optarg) > 255) {
				exit_error(PARAMETER_PROBLEM, "--xor option out of range");
			}
			if (atoi(optarg) == 0) {
				exit_error(PARAMETER_PROBLEM, "--xor 0 is meaningless");
			}
			info->xor_key = atoi(optarg);
			*flags |= IPT_XWALL_PARAM_XOR;
			
			break;
		}
		case '3': /* --udp-port */
		{
			if (check_inverse(optarg, &invert, NULL, 0)) {
				exit_error(PARAMETER_PROBLEM, "Unexpected `!' after --udp-port");
			}
			
			if (*flags & IPT_XWALL_PARAM_UDP_PORT) {
				exit_error(PARAMETER_PROBLEM, "Multiple --udp-port not supported");
			}
			unsigned int t_port = atoi(optarg);
			if (t_port < 1 || t_port > 65535) {
				exit_error(PARAMETER_PROBLEM, "Port number should be between 1~65535");
			}
			info->udp_port = htons(t_port);
			*flags |= IPT_XWALL_PARAM_UDP_PORT;
			
			break;
		}

		default:
			return 0;
	}
	return 1;
}

static void final_check(unsigned int flags)
{
	if (!(flags & IPT_XWALL_PARAM_GATEWAY)) {
		exit_error(PARAMETER_PROBLEM, "XWALL target: Parameter --gateway is required");
	}
	if (!(flags & IPT_XWALL_PARAM_UDP_PORT)) {
		exit_error(PARAMETER_PROBLEM, "XWALL target: Parameter --udp-port is required");
	}
}

/* Prints out the targinfo. */
static void
print(const struct ipt_ip *ip,
      const struct ipt_entry_target *target,
      int numeric)
{
	struct ipt_XWALL_info *info = (struct ipt_XWALL_info *)target->data;
	struct in_addr addr;
	char *gateway;
	unsigned short udp_port;

	addr.s_addr = info->gateway;
	gateway = addr_to_dotted(&addr);
	udp_port = ntohs(info->udp_port);
	
	printf(" tunnel to %s:%d %s", gateway, udp_port, (info->xor_key? "encrypted" : ""));
}

/* Saves the union ipt_targinfo in parsable form to stdout. */
static void
save(const struct ipt_ip *ip, const struct ipt_entry_target *target)
{
	struct ipt_XWALL_info *info = (struct ipt_XWALL_info *)target->data;
	struct in_addr addr;

	addr.s_addr = info->gateway;	
	printf("--gateway %s ", addr_to_dotted(&addr));
	printf("--udp-port %d ", ntohs(info->udp_port));
	if (info->xor_key != 0) {
		printf("--xor %i ", info->xor_key);
	}
}

static struct iptables_target xwall = {
	.next	       = NULL,
	.name	       = "XWALL",
	.version       = IPTABLES_VERSION,
	.size	       = IPT_ALIGN(sizeof(struct ipt_XWALL_info)),
	.userspacesize = IPT_ALIGN(sizeof(struct ipt_XWALL_info)),
	.help	       = &help,
	.init          = &init,
	.parse	       = &parse,
	.final_check   = &final_check,
	.print         = &print,
	.save	       = &save,
	.extra_opts    = opts,	
};

void _init(void)
{
	register_target(&xwall);
}




