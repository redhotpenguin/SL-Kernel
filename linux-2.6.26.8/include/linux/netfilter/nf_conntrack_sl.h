#ifndef _NF_CONNTRACK_SL_H
#define _NF_CONNTRACK_SL_H

#ifdef __KERNEL__

/* enable for module debugging */
#define SL_DEBUG 1

/* packets must be on port 80 to have fun */
#define SL_PORT 80

/* packets must have this much data to go on the ride */
#define MIN_PACKET_LEN 256

/* length of SL header
   X-SLR: 9db44d24|0013102d6976\r\n */
#define SL_HEADER_LEN 30

/* salt for the hashing */
#define JHASH_SALT 420

/* maximum packet length */ 
#define MAX_PACKET_LEN 1480

/* length of the mac address */
#define MACADDR_SIZE 12

/* max length for host header search */
#define HOST_SEARCH_LEN 1024

enum sl_strings {
	HOST,
	PORT,
	NEWLINE,
};

static struct {
		char		*string;
		size_t	  len;
		struct ts_config		*ts;
} search[] __read_mostly = {
		[HOST] = {
	.string = "Host",
	.len	= 4,
		},
		[PORT] = {
	.string = ":8135\r\n",
	.len	= 7,
		},
		[NEWLINE] = {
	.string = "\n",
	.len	= 1,
		},
};


struct nf_conntrack_expect;

extern unsigned int (*nf_nat_sl_hook)(struct sk_buff *skb,
			 struct nf_conn *ct,
			 enum ip_conntrack_info ctinfo,
			 unsigned int host_offset,
			 unsigned int data_offset,
			 unsigned int datalen,
			 unsigned char *user_data);


#endif /* __KERNEL__ */

#endif /* _NF_CONNTRACK_SL_H */
