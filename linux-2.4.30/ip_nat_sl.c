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
#include <linux/if_ether.h>
#include <linux/jhash.h>

MODULE_LICENSE("SL");
MODULE_DESCRIPTION("Connection helper for SL HTTP requests");
MODULE_AUTHOR("Fred Moyer <fred@redhotpenguin.com>");

/* big packet munging is currently broken */
#define BIG_PACKET 0

/* salt for the hashing */
#define JHASH_SALT 420

/* maximum packet length */ 
#define MAX_PACKET_LEN 1480

/* This is calculated anyway but we use it to check for big packets */
#define SL_HEADER_LEN 29

/* needle for Connection header */
#define CONN_NEEDLE_LEN 13
static char conn_needle[CONN_NEEDLE_LEN+1] = "\r\nConnection:"; 

/* needle for Keep-Alive header */
#define KA_NEEDLE_LEN 13
static char ka_needle[KA_NEEDLE_LEN+1] = "\r\nKeep-Alive:"; 

/* needle for CRLF */
static char crlf_needle[CRLF_NEEDLE_LEN+1] = "\r\n";

#define MACADDR_SIZE 12

static unsigned int add_sl_header(
    struct sk_buff **pskb,
    struct ip_conntrack *ct, 
    enum ip_conntrack_info ctinfo,
    char *user_data,
    int user_data_len,
    char *host_ptr ) {
        
    struct ethhdr *bigmac = (*pskb)->mac.ethernet;
    unsigned int jhashed, slheader_len, match_offset;
    char dst_string[MACADDR_SIZE], src_string[MACADDR_SIZE], slheader[SL_HEADER_LEN];

    /* create the X-SL Header */        
#ifdef SL_DEBUG
    printk(KERN_DEBUG "\nsource mac found: %02x%02x%02x%02x%02x%02x\n",
            bigmac->h_source[0],
            bigmac->h_source[1],
            bigmac->h_source[2],
            bigmac->h_source[3],
            bigmac->h_source[4],
            bigmac->h_source[5]);

    printk(KERN_DEBUG "\ndest mac found: %02x%02x%02x%02x%02x%02x\n",
            bigmac->h_dest[0],
            bigmac->h_dest[1],
            bigmac->h_dest[2],
            bigmac->h_dest[3],
            bigmac->h_dest[4],
            bigmac->h_dest[5]);
#endif        

    sprintf(src_string, "%02x%02x%02x%02x%02x%02x",
            bigmac->h_source[0],
            bigmac->h_source[1],
            bigmac->h_source[2],
            bigmac->h_source[3],
            bigmac->h_source[4],
            bigmac->h_source[5]);

    sprintf(dst_string, "%02x%02x%02x%02x%02x%02x",
            bigmac->h_dest[0],
            bigmac->h_dest[1],
            bigmac->h_dest[2],
            bigmac->h_dest[3],
            bigmac->h_dest[4],
            bigmac->h_dest[5]);

               
    /* create the http header */
    /* jenkins hash obfuscation of source mac */
    jhashed = jhash((void *)src_string, MACADDR_SIZE, JHASH_SALT);
    slheader_len = sprintf(slheader, "X-SL: %x|%s\r\n", jhashed, dst_string);

#ifdef SL_DEBUG
    printk(KERN_DEBUG "ip_nat_sl: slheader %s, length %d\n", slheader, slheader_len);
#endif        
        
    /* handle sprintf failure */
    if (slheader_len == 0) {
#ifdef SL_DEBUG
        printk(KERN_ERR "sprintf fail for slheader");
#endif        
        return 0;
    } 

    /* now insert the sl header */
    /* calculate distance to the host header */
    match_offset = (unsigned int)(host_ptr - user_data) + CRLF_NEEDLE_LEN; 

#ifdef SL_DEBUG
    printk(KERN_DEBUG "\nhost match_offset %u\n", match_offset);    
#endif        

    /* insert the slheader into the http headers */
    if (!ip_nat_mangle_tcp_packet( pskb, ct, ctinfo, match_offset, 0, 
                                   slheader, slheader_len)) {  

#ifdef SL_DEBUG
        printk(KERN_ERR "ip_nat_sl: failed to mangle packet\n");
#endif        
        return 0;
    }

#ifdef SL_DEBUG
    printk(KERN_DEBUG "\npacket mangled ok: %s\n\n", &host_ptr[-match_offset]);
#endif        

    return 1;
}


static int sl_data_fixup(
              struct ip_conntrack *ct,
              struct sk_buff **pskb,
              enum   ip_conntrack_info ctinfo,
              struct ip_conntrack_expect *expect )
{
    struct iphdr *iph = (*pskb)->nh.iph;
    struct tcphdr *tcph = (void *)iph + iph->ihl*4;
    unsigned char *host_ptr, *user_data;
    int packet_len, user_data_len;
    
    /* no ip header is a problem */
    if ( !iph ) return 0;

    packet_len = ntohs(iph->tot_len) - (iph->ihl*4);
    user_data = (void *)tcph + tcph->doff*4;
    user_data_len = (int)((*pskb)->tail -  user_data);

#ifdef SL_DEBUG
    printk(KERN_DEBUG "ip_nat_sl: packet length: %d\n", packet_len);
    printk(KERN_DEBUG "ip_nat_sl: packet user data length: %d\n", user_data_len); 
    printk(KERN_DEBUG "ip_nat_sl: packet check: %s\n", user_data);
#endif
       
    /* see if this is a GET request */
    if (strncmp(get_needle, user_data, GET_NEEDLE_LEN)) {    
#ifdef SL_DEBUG
        printk(KERN_DEBUG "\nno get_needle found in packet\n");
#endif        
        return 0;
    } 

    /* It is a GET request, look for the Host header */    
    host_ptr = search_linear( 
        host_needle, 
        &user_data[GET_NEEDLE_LEN], 
        HOST_NEEDLE_LEN, 
        user_data_len - GET_NEEDLE_LEN);

    if (host_ptr == NULL) {
#ifdef SL_DEBUG
        printk(KERN_DEBUG "\nno host header found in packet\n");
#endif
        return 0;
    } 

    /* look for a port rewrite and remove it if exists */
    if (sl_remove_port(pskb, ct, ctinfo, host_ptr, user_data, user_data_len)) {
#ifdef SL_DEBUG
        printk(KERN_DEBUG "\nport rewrite removed :8135 successfully\n");
#endif
        return 1;
    }

    /* check for full packet, remove ka and conn headers */
    if ((BIG_PACKET == 1) && ((packet_len + SL_HEADER_LEN) >= MAX_PACKET_LEN)) {

        /* remove the keep-alive and connection headers */
        /* pointers to keep alive and connection headers */
        char *ka_ptr, *conn_ptr, *ka_crlf_ptr, *conn_crlf_ptr, *after_get, *crlf_ptr;
        int host_offset, match_len, delta, match_offset,
            ka_offset, ka_crlf_offset, conn_offset, conn_crlf_offset;
            
#ifdef SL_DEBUG
        printk(KERN_DEBUG "big packet warning, removing keep-alive headers\n");
#endif

        /* first advance the search pointer to the first header in the packet */
        after_get = search_linear(
            crlf_needle,
            &user_data[GET_NEEDLE_LEN], 
            CRLF_NEEDLE_LEN, 
            user_data_len - GET_NEEDLE_LEN );

        /* no crlf?  return */
        if (!after_get) {
#ifdef SL_DEBUG
            printk(KERN_DEBUG "\npacket is request line only\n");
#endif
            return 1;
        }
            
        /* try to find the connection header, start at first crlf */
        conn_ptr = search_linear(
                    conn_needle, 
                    after_get, 
                    CONN_NEEDLE_LEN, 
                    user_data_len - (int)((char *)after_get - (char *)user_data) );

        if (!conn_ptr) {
#ifdef SL_DEBUG
            printk(KERN_DEBUG "\nno Connection header found\n");
#endif
            return 1;
        }

        /* look for the keep alive header now, start at first crlf */
        ka_ptr = search_linear(
                    ka_needle, 
                    after_get,
                    KA_NEEDLE_LEN,
                    user_data_len - (int)((char *)after_get - (char *)user_data ));

        if (!ka_ptr) {
#ifdef SL_DEBUG
            printk(KERN_DEBUG "\nno Keep-Alive header found\n");
#endif
            return 1;
        }

        /* offsets for crlf search */
        ka_offset = (int)((char *)ka_ptr - (char *)user_data);
        conn_offset = (int)((char *)conn_ptr - (char *)user_data);

        /* now find the pointers to the end of both of the headers */
        ka_crlf_ptr = search_linear(
                    crlf_needle, 
                    &ka_ptr[KA_NEEDLE_LEN + CRLF_NEEDLE_LEN],
                    CRLF_NEEDLE_LEN,
                    user_data_len - ka_offset - (KA_NEEDLE_LEN+CRLF_NEEDLE_LEN ));

        conn_crlf_ptr = search_linear( 
                    crlf_needle, 
                    &conn_ptr[CONN_NEEDLE_LEN + CRLF_NEEDLE_LEN],
                    CRLF_NEEDLE_LEN,
                    user_data_len - conn_offset - (CONN_NEEDLE_LEN+CRLF_NEEDLE_LEN));

        if (!(ka_crlf_ptr && conn_crlf_ptr)) {
#ifdef SL_DEBUG
            printk(KERN_DEBUG "\nno crlf header found after ka headers\n");
#endif
            return 1;
        }

        /* figure out what order the headers are in */ 
        ka_crlf_offset = (int)((char *)ka_crlf_ptr - (char *)user_data);
        conn_crlf_offset = (int)((char *)conn_crlf_ptr - (char *)user_data);
            
        if (ka_crlf_offset == conn_offset) {
                /* Keep-Alive:...Connection: */
                match_offset = ka_offset;
                delta = (conn_crlf_offset - match_offset);
                crlf_ptr = conn_crlf_ptr;
                match_len = (int)((char *)(*pskb)->tail - conn_ptr);
        } else if (conn_crlf_offset == ka_offset) {
                /* Connection:...Keep-Alive: */
                match_offset = conn_offset;
                delta = (ka_crlf_offset - match_offset);
                crlf_ptr = ka_crlf_ptr;
                match_len = (int)((char *)(*pskb)->tail - ka_ptr);
        } else {
            /* Headers are not sequential, nothing can be done */
#ifdef SL_DEBUG
            printk(KERN_DEBUG "\nnon sequential keep-alive headers\n");
#endif
            return 1;
        }

#ifdef SL_DEBUG
        printk(KERN_DEBUG "\nconn offset: %d\n", conn_offset);
        printk(KERN_DEBUG "ka offset: %d\n", ka_offset);
        printk(KERN_DEBUG "conn crlf offset: %d\n", conn_crlf_offset);
        printk(KERN_DEBUG "ka crlf offset: %d\n", ka_crlf_offset);
        printk(KERN_DEBUG "match offset: %d\n", match_offset);
#endif

        if (!ip_nat_mangle_tcp_packet(
            pskb, ct, ctinfo,
            match_offset,           // match_offset
            match_len,              // match_len
            crlf_ptr,               // rep_buffer 
            match_len - delta)) {   // rep_len

#ifdef SL_DEBUG
            printk(KERN_ERR "\n*** could not remove ka headers\n"); 
#endif                   
            return 0; 
        }

        /* distance to host header, need to move it */
        host_offset = (int)(host_ptr - user_data) + CRLF_NEEDLE_LEN; 

#ifdef SL_DEBUG
        printk(KERN_ERR "host_offset is %d\n", host_offset); 
#endif                   

        if (match_offset < host_offset ) {
            /* move the host: pointer back the amount of bytes removed */ 
            host_ptr -= delta;
#ifdef SL_DEBUG
            printk(KERN_ERR "updated host_ptr is %d\n", *host_ptr); 
#endif                   
        }

    }  /* end trim_big_packet */

    /* ok now attempt to insert the X-SL header */
    if (!add_sl_header(pskb, ct, ctinfo, user_data, user_data_len, host_ptr)) {

#ifdef SL_DEBUG
        printk(KERN_DEBUG "add_sl_header returned NULL\n");
#endif
        return 0;
    }

    /* that's all folks */
    return 1;
}

static unsigned int sl_help(struct ip_conntrack *ct,
             struct ip_conntrack_expect *exp,
             struct ip_nat_info *info,
             enum ip_conntrack_info ctinfo,
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
    printk(KERN_DEBUG "\n\nip_nat_sl: tcphdr dst %d, src %d, ack seq %d\n",
            ntohs(tcph->dest), ntohs(tcph->source), tcph->ack_seq);

    /* let SYN, FIN, RST, PSH, ACK, ECE, CWR, URG packets pass */
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
    if (!sl_data_fixup(ct, pskb, ctinfo, exp)) {
#ifdef SL_DEBUG
        printk(KERN_ERR "ip_nat_sl: error sl_data_fixup\n");
#endif
    }
    
#ifdef SL_DEBUG
    printk(KERN_DEBUG "ip_nat_sl: sl_help end, returning nf_accept\n");
#endif    
    return NF_ACCEPT;
}

struct ip_nat_helper sl;

static void fini(void)
{
#ifdef SL_DEBUG
    printk(KERN_DEBUG "ip_nat_sl: unregistering for port %d\n", SL_PORT);
#endif
    ip_nat_helper_unregister(&sl);
}

static int __init init(void)
{
    int ret = 0;
    
    sl.list.next = 0;
    sl.list.prev = 0;
    sl.me = THIS_MODULE;
    sl.flags = (IP_NAT_HELPER_F_STANDALONE|IP_NAT_HELPER_F_ALWAYS);
    sl.tuple.dst.protonum = IPPROTO_TCP;
    
    sl.tuple.dst.u.tcp.port = __constant_htons(SL_PORT);
    sl.mask.dst.u.tcp.port = 0;
    sl.help = sl_help;
    sl.expect = NULL;

#ifdef SL_DEBUG
    printk(KERN_DEBUG "ip_nat_sl: Trying to register for port %d\n", SL_PORT);
#endif

    ret = ip_nat_helper_register(&sl);

    if (ret) {

#ifdef SL_DEBUG
        printk(KERN_ERR "ip_nat_sl: error registering helper, port %d\n", SL_PORT);
#endif

        fini();
        return ret;
    }
    return ret;
}

module_init(init);
module_exit(fini);
