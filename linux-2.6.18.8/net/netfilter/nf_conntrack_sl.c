/* SLN extension for connection tracking. */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/netfilter.h>
#include <linux/ip.h>
#include <linux/ctype.h>
#include <linux/inet.h>
#include <net/checksum.h>
#include <net/tcp.h>

#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <linux/netfilter/nf_conntrack_sl.h>


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Fred Moyer <fred@redhotpenguin.com");
MODULE_DESCRIPTION("sl connection tracking helper");

// GET
#define GET_LEN 5
static char get[GET_LEN+1] = "GET /";

#define HOST_LEN 6
static char host[HOST_LEN+1] = "Host: ";

unsigned int (*nf_nat_sl_hook)(struct sk_buff **pskb,
                               enum ip_conntrack_info ctinfo,
                               struct nf_conntrack_expect *exp,
                               unsigned int host_offset,
			       unsigned int data_offset,
			       unsigned int datalen,
			       unsigned char *user_data )
                               __read_mostly;
EXPORT_SYMBOL_GPL(nf_nat_sl_hook);


static int sl_help (struct sk_buff **pskb,
                    unsigned int protoff,
                    struct nf_conn *ct,
                    enum   ip_conntrack_info ctinfo)     
{
    struct tcphdr _tcph, *th;
    unsigned int host_offset, dataoff, datalen, start_offset, stop_offset;
    struct nf_conntrack_expect *exp;
    //    struct ts_state ts;
    unsigned char *user_data;
    int ret = NF_ACCEPT;
    //    int i=0;
    int j=0;
    typeof(nf_nat_sl_hook) nf_nat_sl;

    /* only operate on established connections */
    if (ctinfo != IP_CT_ESTABLISHED
         && ctinfo != IP_CT_ESTABLISHED+IP_CT_IS_REPLY)
        return NF_ACCEPT;

    /* only mangle outbound packets */
    if ( ctinfo == IP_CT_IS_REPLY )
        return NF_ACCEPT;

    /* No NAT? */
    if (!(ct->status & IPS_NAT_MASK))
      return NF_ACCEPT;

#ifdef SKB_DEBUG                
    printk(KERN_DEBUG "conntrackinfo = %u\n", ctinfo);
#endif    

    // not a full tcp header
    th = skb_header_pointer(*pskb, protoff, sizeof(_tcph), &_tcph);
    if (th == NULL)
        return NF_ACCEPT;
    
#ifdef SKB_DEBUG

    printk(KERN_DEBUG "tcphdr dst %d, src %d, ack seq %u\n",
           ntohs(th->dest), ntohs(th->source), th->ack_seq);

    /* let SYN, FIN, RST, PSH, ACK, ECE, CWR, URG packets pass */
        printk(KERN_DEBUG "FIN %d, SYN %d, RST %d, PSH %d, ACK %d, ECE %d\n",
         th->fin, th->syn, th->rst, th->psh, th->ack, th->ece);
#endif    

    /* only work on push or ack packets */
    if (!( (th->psh == 1) || (th->ack == 1)) ) {
#ifdef SKB_DEBUG
    	printk(KERN_DEBUG "not psh or ack, return\n\n");
#endif    
        return NF_ACCEPT;
    }

    /* No data? */
    //    dataoff = protoff + sizeof(_tcph);
    dataoff = protoff + th->doff*4;
    if (dataoff >= (*pskb)->len) {

#ifdef SKB_DEBUG
	printk(KERN_DEBUG "dataoff(%u) >= skblen(%u), return\n\n", dataoff,
			 (*pskb)->len);
#endif
        return NF_ACCEPT;
    }

    datalen = (*pskb)->len - dataoff;
    /* if there aren't MIN_PACKET_LEN we aren't interested */
    if (datalen < MIN_PACKET_LEN) {
#ifdef SKB_DEBUG
    	printk(KERN_DEBUG "skb data too small,  %d bytes, return\n", datalen);
#endif    
        return NF_ACCEPT;
    }


#ifdef SL_DEBUG
    printk(KERN_DEBUG "dataoff %u, packet length %d, data length %d\n",
	dataoff, (*pskb)->len, datalen);
#endif    

    /* see if this is a GET request */
    user_data = (void *)th + th->doff*4;

    // look for 'GET /'
    if (strncmp(get, user_data, GET_LEN)) {    

#ifdef SL_DEBUG
        printk(KERN_DEBUG "no get_needle found in packet, return\n\n");
#endif  	      
        return NF_ACCEPT;
    } 

    /* safety break */
    exp = nf_ct_expect_alloc(ct);
    if (exp == NULL)
        return NF_ACCEPT;

    datalen = (*pskb)->len - dataoff;

    start_offset = GET_LEN;
    stop_offset = datalen - HOST_LEN - start_offset;


#ifdef SL_DEBUG
    printk(KERN_DEBUG "packet dump:\n%s\n\n", user_data);

    // see if the packet contains a Host header
    printk(KERN_DEBUG "\ndataoff %u, user_data %u\n",
	    dataoff, (unsigned int)user_data );
    
    printk(KERN_DEBUG "host search:  search_start %u, search_stop %u\n",
        start_offset, stop_offset );

    if (start_offset > stop_offset) {
	printk(KERN_ERR "invalid stop offset, return\n");
	return NF_ACCEPT;
    }
#endif

    /* search for a host header */
    while ( start_offset++ < stop_offset) {

      if ( !memcmp(&user_data[start_offset], &host[j], 1 )) {

#ifdef SL_DEBUG
	printk(KERN_DEBUG "found a match at i %d, j %d\n", start_offset, j);
#endif

	if (j == HOST_LEN-1) {

#ifdef SL_DEBUG
	  printk(KERN_DEBUG "FULL MATCH AT i %d, j %d\n", start_offset+HOST_LEN+GET_LEN+1, j);
	  printk(KERN_DEBUG "match packet dump:\n%s\n", &user_data[start_offset+1]);
#endif

	  break;
	}
	j++;
      } else {
	j = 0;

      }

    }

    if (j != HOST_LEN-1) {
#ifdef SL_DEBUG
      printk("no host header found, j is %d, start_offset is %d, max is %d\n", j, start_offset, datalen-start_offset -HOST_LEN);
#endif
      return NF_ACCEPT;
    }
    host_offset = start_offset;

#ifdef SL_DEBUG

    printk(KERN_DEBUG "packet dump start offset:\n%s\n",
		(unsigned char *)((unsigned int)user_data+ start_offset));

    printk(KERN_DEBUG "packet dump stop offset:\n%s\n",
		(unsigned char *)((unsigned int)user_data+ stop_offset-10));


    printk(KERN_DEBUG "passing packet to nat module, host offset: %u\n", host_offset);
    printk(KERN_DEBUG "packet dump:\n%s\n",
		(unsigned char *)((unsigned int)user_data+host_offset));
#endif
 	
    nf_nat_sl = rcu_dereference(nf_nat_sl_hook);
    ret = nf_nat_sl(pskb, ctinfo, exp,
	host_offset, dataoff, datalen, user_data);
   
    return ret;
}

static struct nf_conntrack_helper sl_helper __read_mostly = {
		.name                     = "sl",
		.max_expected             = 0,
		.timeout                  = 60,
		.tuple.src.l3num          = AF_INET,
		.tuple.dst.protonum       = IPPROTO_TCP,
		.tuple.src.u.tcp.port     = __constant_htons(SL_PORT),
		.me                       = THIS_MODULE,
		.help                     = sl_help,
};
  

/* don't make this __exit, since it's called from __init ! */
static void nf_conntrack_sl_fini(void)
{

#ifdef SL_DEBUG
	    printk(KERN_DEBUG " unregistering for port %d\n", SL_PORT);
#endif

        nf_conntrack_helper_unregister(&sl_helper); 
}

static int __init nf_conntrack_sl_init(void)
{
 
        int ret = 0;


#ifdef SL_DEBUG
        printk(KERN_DEBUG "Registering nf_conntrack_sl, port %d\n", SL_PORT);
#endif

        ret = nf_conntrack_helper_register(&sl_helper);
	if (ret < 0) {

	  printk(KERN_ERR "error registering module: %d\n\n", ret);
	  return ret;
	}

	return ret;
}

module_init(nf_conntrack_sl_init);
module_exit(nf_conntrack_sl_fini);
