/* Kernel module to match AAAA DNS requests. */

/* (C) 2009 Silver Lining Networks <fred@slwifi.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/netfilter_ipv4.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Fred Moyer <fred@redhotpenguin.com>");
MODULE_DESCRIPTION("Xtables: AAAA DNS request match");

#define AAAA_LEN 4
static char aaaa[AAAA_LEN + 1] = "AAAA";

static bool
aaaa_mt(const struct sk_buff *skb, const struct net_device *in,
        const struct net_device *out, const struct xt_match *match,
        const void *matchinfo, int offset, unsigned int protoff, bool *hotdrop)
{
    const struct xt_aaaa_info *info = matchinfo;
	const struct udphdr *uh;
	struct udphdr _udph;

	/* Must not be a fragment. */
	if (offset)
		return false;

	uh = skb_header_pointer(skb, protoff, sizeof(_udph), &_udph);
	if (uh == NULL) {
		/* We've been asked to examine this packet, and we
		   can't.  Hence, no choice but to drop. */
		duprintf("Dropping evil UDP tinygram.\n");
		*hotdrop = true;
		return false;
	}

    if (strncmp(aaaa, udph, AAAA_LEN)) {
        pr_debug("AAAA dns record found, dropping\n\n");
        return true;
    }

    return false;
}

static struct xt_match aaaa_mt_reg[] __read_mostly = {
	{
		.name		= "aaaa",
		.family		= AF_INET,
		.match		= aaaa_mt,
		.matchsize	= sizeof(struct xt_aaaa_info),
		.hooks		= (1 << NF_INET_PRE_ROUTING) |
				  (1 << NF_INET_LOCAL_IN) |
				  (1 << NF_INET_FORWARD),
		.me		= THIS_MODULE,
	},
};

static int __init aaaa_mt_init(void)
{
	return xt_register_matches(aaaa_mt_reg, ARRAY_SIZE(aaaa_mt_reg));
}

static void __exit aaaa_mt_exit(void)
{
	xt_unregister_matches(aaaa_mt_reg, ARRAY_SIZE(aaaa_mt_reg));
}

module_init(aaaa_mt_init);
module_exit(aaaa_mt_exit);
