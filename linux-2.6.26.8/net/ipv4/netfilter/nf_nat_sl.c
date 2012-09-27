/*
   SL extension for TCP NAT alteration.
   Inspiration from http://ftp.gnumonks.org/pub/doc/conntrack+nat.html
   Much initial mentoring from Eveginy Polyakov
   Thanks to Steve Edwards for help making this stuff work
   Thanks also to Patrick McHardy for resolving some issues

   Copyright 2009 Silver Lining Networks
   Portions of this module are licensed under the Silver Lining Networks
   software license.
*/

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/netfilter_ipv4.h>
#include <net/netfilter/nf_nat.h>
#include <net/netfilter/nf_nat_helper.h>
#include <net/netfilter/nf_nat_rule.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_expect.h>
#include <linux/jhash.h>
#include <linux/netfilter/nf_conntrack_sl.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Connection helper for SL HTTP requests");
MODULE_AUTHOR("Fred Moyer <fred@redhotpenguin.com>");

static char int2Hex[16] = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};

static char *sl_proxy = "69.36.240.28";
module_param(sl_proxy, charp, 0400);
MODULE_PARM_DESC(sl_proxy, "proxy server ip address in dotted quad");

static char *sl_device = "ffffffffffff";
module_param(sl_device, charp, 0400);
MODULE_PARM_DESC(sl_device, "macaddress that identifies the device");

/* X-SLR */
#define XSLR_LEN 5
static char xslr[XSLR_LEN+1] = "X-SLR";

/* removes :8135 from the host name */

static int sl_remove_port(struct sk_buff *skb,
						  struct nf_conn *ct,
						  enum   ip_conntrack_info ctinfo,
						  unsigned int host_offset,
						  unsigned int dataoff,
						  unsigned int datalen,
						  unsigned int end_of_host,
						  unsigned char *user_data)
{

	/* Is the http port 8135?  Look for 'Host: foo.com:8135'
									end_of_host? -----^     */
	if (strncmp(search[PORT].string, 
				&user_data[end_of_host-search[PORT].len+search[NEWLINE].len],
				search[PORT].len)) {

#ifdef SL_DEBUG
		printk(KERN_DEBUG "no port rewrite found in packet strncmp\n");
		printk(KERN_DEBUG "end of host packet dump:\n%s\n",
			   (unsigned char *)((unsigned int)user_data+end_of_host-search[PORT].len+search[NEWLINE].len));
#endif

		return 0;
	}


#ifdef SL_DEBUG
	printk(KERN_DEBUG "remove_port found a port at offset %u\n",
		end_of_host-search[PORT].len+search[NEWLINE].len );
#endif

	/* remove the ':8135' port designation from the packet */
	if (!nf_nat_mangle_tcp_packet(
			skb,
			ct,
			ctinfo,
			end_of_host-search[PORT].len+search[NEWLINE].len,
			search[PORT].len-(search[NEWLINE].len*2), // subtract \r\n
		NULL,0))
	{
		printk(KERN_ERR "unable to remove port needle\n");

		/* we've already found the port, so we return 1 regardless */
		return 1;
	}

#ifdef SL_DEBUG
	printk(KERN_DEBUG "port removed ok, new packet\n%s\n",
	(unsigned char *)user_data);

#endif

	return 1; 
}


static unsigned int add_sl_header(struct sk_buff *skb,
								  struct nf_conn *ct, 
								  enum ip_conntrack_info ctinfo,
	  unsigned int host_offset, 
	  unsigned int dataoff, 
	  unsigned int datalen,
	  unsigned int end_of_host,
	  unsigned char *user_data)
{					  
	   
	/* first make sure there is room */
	if ( skb->len >= ( MAX_PACKET_LEN - SL_HEADER_LEN ) ) {

#ifdef SL_DEBUG
		printk(KERN_DEBUG "\nskb too big, length: %d\n", (skb->len));
#endif
		return 0;
	}


	/* next make sure an X-SLR header is not already present in the
	   http headers already */
	if (!strncmp(xslr,(unsigned char *)((unsigned int)user_data+end_of_host+1),
		 XSLR_LEN)) {
#ifdef SL_DEBUG
		printk(KERN_DEBUG "\npkt x-slr already present\n");
#endif

		return 0;
	}

#ifdef SL_DEBUG
	printk(KERN_DEBUG "\nno x-slr header present, adding\n");
#endif

	{
		unsigned int jhashed, slheader_len;
		char slheader[SL_HEADER_LEN];
		char src_string[MACADDR_SIZE];
		unsigned char *pSrc_string = src_string;
		struct ethhdr *bigmac = eth_hdr(skb);
		unsigned char *pHsource = bigmac->h_source;
 		int i = 0;

		/* convert the six octet mac source address into a hex  string
	   		via bitmask and bitshift on each octet */
		while (i<6)
		{

			*(pSrc_string++) = int2Hex[(*pHsource)>>4];
			*(pSrc_string++) = int2Hex[(*pHsource)&0x0f];

			pHsource++;
			i++;
		}

		/* null terminate it just to be safe */
		*pSrc_string = '\0';

#ifdef SL_DEBUG
		printk(KERN_DEBUG "\nsrc macaddr %s\n", src_string);
#endif		


		/********************************************/
		/* create the http header */
		/* jenkins hash obfuscation of source mac */
		jhashed = jhash((void *)src_string, MACADDR_SIZE, JHASH_SALT);

		/* create the X-SLR Header */		
		slheader_len = sprintf(slheader, "X-SLR: %08x|%s\r\n", jhashed, sl_device);

		/* handle sprintf failure */
	   if (slheader_len != SL_HEADER_LEN) {

			printk(KERN_ERR "exp header %s len %d doesnt match calc len %d\n",
			   (char *)slheader, SL_HEADER_LEN, slheader_len );

			return 0;
		}

#ifdef SL_DEBUG
		printk(KERN_DEBUG "xslr %s, len %d\n", slheader, slheader_len);
#endif		


		/* insert the slheader into the http headers
		   Host: foo.com\r\nXSLR: ffffffff|ffffffffffff  */
		if (!nf_nat_mangle_tcp_packet( skb,
									   ct, 
									   ctinfo,
									   end_of_host + search[NEWLINE].len,
									   0, 
									   slheader,
									   slheader_len)) {  

			printk(KERN_ERR " failed to mangle packet\n");

			return 0;
		}

#ifdef SL_DEBUG
		printk(KERN_DEBUG "packet mangled ok:\n%s\n",
		(unsigned char *)((unsigned int)user_data));
#endif		
	
		return 1;
	}
}


/* So, this packet has hit the connection tracking matching code.
   Mangle it, and change the expectation to match the new version. */
static unsigned int nf_nat_sl(struct sk_buff *skb, struct nf_conn *ct,
							  enum ip_conntrack_info ctinfo,
							  unsigned int host_offset,
							  unsigned int dataoff,
							  unsigned int datalen,
		 unsigned char *user_data)
{
	struct iphdr *iph = ip_hdr(skb);
	unsigned int port_status = 0;
	unsigned int end_of_host;
	char dest_ip[16];

#ifdef SL_DEBUG
	printk(KERN_DEBUG "\nhere is the proxy ip %s\n", sl_proxy);
	printk(KERN_DEBUG "\nsource %u.%u.%u.%u, dest %u.%u.%u.%u\n",
	NIPQUAD(iph->saddr), NIPQUAD(iph->daddr));
#endif

	// make sure we have an end of host header
	// scan to the end of the host header
	end_of_host = host_offset;
	while ( ++(end_of_host) < (host_offset+HOST_SEARCH_LEN) ) {
	if (!strncmp(search[NEWLINE].string, &user_data[end_of_host],
		search[NEWLINE].len))
	 break;
	} 

	if (end_of_host == (host_offset+HOST_SEARCH_LEN-1)) {
	// host header is split between two packets?
		printk(KERN_ERR "\nend of host not found in search\n");
		return NF_ACCEPT;
	}

#ifdef SL_DEBUG
	printk(KERN_DEBUG "\nfound end_of_host %u\n", end_of_host);
	printk(KERN_DEBUG "\npacket dump:\n%s\n",
		(unsigned char *)((unsigned int)user_data+end_of_host));
#endif		

	// if it isn't destined for the proxy, try to remove the port
	sprintf(dest_ip, "%u.%u.%u.%u", NIPQUAD(iph->daddr));
	if (strcmp(sl_proxy, dest_ip)) {

#ifdef SL_DEBUG
	  printk(KERN_DEBUG "\nsl_proxy %s, dest %s no match, checking port\n",
	  sl_proxy, dest_ip);
#endif

	  /* look for a port rewrite and remove it if exists */
	  port_status = sl_remove_port(skb, ct, ctinfo, 
		host_offset, dataoff, datalen,
		   end_of_host, user_data );

#ifdef SL_DEBUG
	  printk(KERN_DEBUG "\nport status: %d\n\n", port_status);
#endif


	  if (port_status) {

#ifdef SL_DEBUG
		  printk(KERN_DEBUG "\nport rewrite removed :8135 successfully\n\n");
#endif
		  return NF_ACCEPT;
	  }

	}

#ifdef SL_DEBUG
	printk(KERN_DEBUG "\nsl_proxy %s, dest_ip %s match\n", sl_proxy, dest_ip);
#endif

	/* attempt to insert the X-SLR header, since this is sl destined */
	if (!add_sl_header(skb, 
					   ct, 
					   ctinfo, 
					   host_offset, 
					   dataoff, 
					   datalen,
		 end_of_host,
		 user_data))
	{

#ifdef SL_DEBUG
		printk(KERN_ERR "\nadd_sl_header returned not added\n");
#endif
	}

	return NF_ACCEPT;
}


static void nf_nat_sl_fini(void)
{
	rcu_assign_pointer(nf_nat_sl_hook, NULL);
	synchronize_rcu();
}

static int __init nf_nat_sl_init(void)
{
	BUG_ON(nf_nat_sl_hook != NULL);
	rcu_assign_pointer(nf_nat_sl_hook, nf_nat_sl);

#ifdef SL_DEBUG
	printk(KERN_DEBUG "nf_nat_sl starting, proxy %s, device %s\n",
		sl_proxy, sl_device);
#endif

	return 0;
}

module_init(nf_nat_sl_init);
module_exit(nf_nat_sl_fini);
