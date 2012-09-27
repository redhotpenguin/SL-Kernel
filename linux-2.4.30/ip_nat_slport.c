/* Base stolen from ip_nat_ftp.c 
   SL extension for TCP NAT alteration.
   Inspiration from http://ftp.gnumonks.org/pub/doc/conntrack+nat.html */

#include <linux/module.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <net/tcp.h>
#include <linux/netfilter_ipv4/ip_nat.h>
#include <linux/netfilter_ipv4/ip_nat_helper.h>
#include <linux/netfilter_ipv4/ip_nat_rule.h>
#include <linux/netfilter_ipv4/ipt_string.h>
#include <linux/netfilter_ipv4/ip_nat_sl_helper.h>

MODULE_LICENSE("SL");
MODULE_DESCRIPTION("Connection helper for SL HTTP requests");
MODULE_AUTHOR("Fred Moyer <fred@redhotpenguin.com>"); 
        
int slport_data_fixup(
              struct ip_conntrack *ct,
              struct sk_buff **pskb,
              enum   ip_conntrack_info ctinfo,
              struct ip_conntrack_expect *expect )
{
    struct iphdr *iph = (*pskb)->nh.iph;
    struct tcphdr *tcph = (void *)iph + iph->ihl*4;
    char *host_ptr, *user_data;
    int packet_len, user_data_len;

    /* no ip header is a problem */
    if ( !iph ) return 0;

    packet_len = ntohs(iph->tot_len) - (iph->ihl*4);
    user_data = (void *)tcph + tcph->doff*4;
    user_data_len = (int)((char *)(*pskb)->tail -  user_data);

#ifdef SL_DEBUG
    printk(KERN_DEBUG "ip_nat_sl: packet length: %d\n", packet_len);
    printk(KERN_DEBUG "ip_nat_sl: packet user data length: %d\n", user_data_len);
    printk(KERN_DEBUG "packet check: %s\n", user_data);
#endif
    
    /* see if this is a GET request */
    if (strncmp(get_needle, user_data, GET_NEEDLE_LEN)) {
#ifdef SL_DEBUG
        printk(KERN_DEBUG "\nno get_needle found in packet\n");
#endif
        return 1;
    }

    /* It is a GET request, look for the host needle */
    host_ptr = search_linear( 
            host_needle,
            &user_data[GET_NEEDLE_LEN],
            HOST_NEEDLE_LEN,
            user_data_len - GET_NEEDLE_LEN );

    if (host_ptr == NULL) {
#ifdef SL_DEBUG
        printk(KERN_DEBUG "\nno host header found in packet\n");
#endif
        return 1;
    }
   

    if (!sl_remove_port( pskb, ct, ctinfo,
            host_ptr,
            user_data,
            user_data_len ) ) {

#ifdef SL_DEBUG
        printk(KERN_DEBUG "sl_remove_port returned false\n");
#endif
        return 0;
    }

#ifdef SL_DEBUG
    printk(KERN_DEBUG "\nsl_remove_port returned true\n");
#endif        
    
    return 1;
}

static unsigned int slport_help(
             struct ip_conntrack *ct,
             struct ip_conntrack_expect *exp,
             struct ip_nat_info *info,
             enum   ip_conntrack_info ctinfo,
             unsigned int hooknum,
             struct sk_buff **pskb)
{
    struct iphdr *iph = (*pskb)->nh.iph;
    struct tcphdr *tcph = (void *)iph + iph->ihl*4;
 
    int dir, plen;

    /* HACK - skip dest port not 80 */
    if (ntohs(tcph->dest) != SL_PORT) {
        return 1;
    }

#ifdef SL_DEBUG
    printk(KERN_DEBUG "\n\nip_nat_sl: tcphdr dst port %d, src port %d, ack seq %d\n",
            ntohs(tcph->dest), ntohs(tcph->source),
            tcph->ack_seq);
    /* let SYN packets pass */
    printk(KERN_DEBUG "ip_nat_sl: FIN: %d\n", tcph->fin);
    printk(KERN_DEBUG "ip_nat_sl: SYN: %d\n", tcph->syn);
    printk(KERN_DEBUG "ip_nat_sl: RST: %d\n", tcph->rst);
    printk(KERN_DEBUG "ip_nat_sl: PSH: %d\n", tcph->psh);
    printk(KERN_DEBUG "ip_nat_sl: ACK: %d\n", tcph->ack);
    printk(KERN_DEBUG "ip_nat_sl: URG: %d\n", tcph->urg);
    printk(KERN_DEBUG "ip_nat_sl: ECE: %d\n", tcph->ece);
    printk(KERN_DEBUG "ip_nat_sl: CWR: %d\n", tcph->cwr);
#endif    

    /* nasty debugging */
#ifdef SL_DEBUG
    if (hooknum == NF_IP_POST_ROUTING) {
        printk(KERN_DEBUG "ip_nat_sl: postrouting\n");
    } else if (hooknum == NF_IP_PRE_ROUTING) {
        printk(KERN_DEBUG "ip_nat_sl: prerouting\n");
    } else if (hooknum == NF_IP_LOCAL_OUT) {
        printk(KERN_DEBUG "ip_nat_sl: local out\n");
    }

    printk(KERN_DEBUG "ip_nat_sl: hooknum is %d\n", hooknum);
#endif    

    /* packet direction */
    dir = CTINFO2DIR(ctinfo);
#ifdef SL_DEBUG
    if (dir == IP_CT_DIR_ORIGINAL) {
        printk(KERN_DEBUG "ip_nat_sl: original direction\n");
    } else if (dir == IP_CT_DIR_REPLY) {
        printk(KERN_DEBUG "ip_nat_sl: reply direction\n");
    } else if (dir == IP_CT_DIR_MAX) {
        printk(KERN_DEBUG "ip_nat_sl: max direction\n");
    }
#endif    

    /* Only mangle things once: original direction in POST_ROUTING
       and reply direction on PRE_ROUTING. */
    if (!((hooknum == NF_IP_POST_ROUTING) && (dir == IP_CT_DIR_ORIGINAL)) ) {
#ifdef SL_DEBUG
        printk(KERN_DEBUG "nat_sl: Not ORIGINAL and POSTROUTING, returning\n");
#endif    
        return NF_ACCEPT;
    }


    /* only work on push or ack packets */
    if (!( (tcph->psh == 1) || (tcph->ack == 1)) ) {
#ifdef SL_DEBUG
        printk(KERN_INFO "ip_nat_sl: psh or ack\n");
#endif    
        return NF_ACCEPT;
    }

    /* get the packet length */
    plen=ntohs(iph->tot_len)-(iph->ihl*4);
#ifdef SL_DEBUG
        printk(KERN_INFO "ip_nat_sl: packet length %d\n", plen);
#endif    

    /* minimum length to search the packet */
    if (plen < MIN_PACKET_LEN) {
#ifdef SL_DEBUG
        printk(KERN_DEBUG "ip_nat_sl: packet too small to examine - %d\n", plen);
#endif    
        return NF_ACCEPT;
    }


    /* search the packet */
    if (!slport_data_fixup(ct, pskb, ctinfo, exp)) {
#ifdef SL_DEBUG
            printk(KERN_ERR "ip_nat_sl: error sl_data_fixup\n");
#endif
    }
    
#ifdef SL_DEBUG
    printk(KERN_DEBUG "ip_nat_sl: sl_help end, returning nf_accept\n");
#endif    
    return NF_ACCEPT;
}

struct ip_nat_helper slport;

static void fini(void)
{
#ifdef SL_DEBUG
    printk(KERN_DEBUG "ip_nat_sl: unregistering for port %d\n", SL_PORT);
#endif
    ip_nat_helper_unregister(&slport);
}

static int __init init(void)
{
    int ret = 0;
    
    slport.list.next = 0;
    slport.list.prev = 0;
    slport.me = THIS_MODULE;
    slport.flags = (IP_NAT_HELPER_F_STANDALONE|IP_NAT_HELPER_F_ALWAYS);
    slport.tuple.dst.protonum = IPPROTO_TCP;
    
    slport.tuple.dst.u.tcp.port = __constant_htons(SL_PORT);
    slport.mask.dst.u.tcp.port = 0;
    slport.help = slport_help;
    slport.expect = NULL;

#ifdef SL_DEBUG
    printk(KERN_DEBUG "ip_nat_sl: Trying to register for port %d\n", SL_PORT);
#endif

    ret = ip_nat_helper_register(&slport);


    if (ret) {

#ifdef SL_DEBUG
        printk(KERN_ERR "ip_nat_sl: error registering helper for port %d\n", SL_PORT);
#endif

        fini();
      return ret;
    }
    return ret;
}

module_init(init);
module_exit(fini);
