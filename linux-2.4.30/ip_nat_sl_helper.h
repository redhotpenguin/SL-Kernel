#ifndef _IP_NAT_SL_HELPER_H
#define _IP_NAT_SL_HELPER_H

#define xSL_DEBUG

/* packets must be on port 80 to have fun */
#define SL_PORT 80

/* packets must have this much data to go on the ride */
#define MIN_PACKET_LEN 216

/* needle for GET */
#define GET_NEEDLE_LEN 5
static char get_needle[GET_NEEDLE_LEN+1] = "GET /";

/* needle for host header */
#define HOST_NEEDLE_LEN 7
static char host_needle[HOST_NEEDLE_LEN+1] = "\r\nHost:";

/* the removal string for the port */
#define PORT_NEEDLE_LEN 5
static char port_needle[PORT_NEEDLE_LEN+1] = ":8135";

#define CRLF_NEEDLE_LEN 2

static int sl_remove_port(
                struct sk_buff **pskb,
                struct ip_conntrack *ct,
                enum   ip_conntrack_info ctinfo,
                char   *host_ptr,
                char   *user_data,
                int    user_data_len ) {

    char *port_ptr;
    unsigned int match_offset, match_len;

   /* Temporarily use match_len for the data length to be searched*/
    match_len =  (unsigned int)(user_data_len
                       - (int)(host_ptr - user_data)
                       - (HOST_NEEDLE_LEN + CRLF_NEEDLE_LEN));

    port_ptr = search_linear(
                    port_needle,
                    &host_ptr[HOST_NEEDLE_LEN + CRLF_NEEDLE_LEN],
                    PORT_NEEDLE_LEN, 
                    (int)match_len);

    if (port_ptr == NULL) {
#ifdef SL_DEBUG
        printk(KERN_DEBUG "\nno port rewrite found in packet\n");
#endif
        return 0;
    }

    match_offset = (unsigned int)(port_ptr - user_data);
    match_len    = (unsigned int)((char *)(*pskb)->tail - port_ptr);

#ifdef SL_DEBUG
    printk(KERN_DEBUG "\nmatch_len: %d\n", match_len);
    printk(KERN_DEBUG "match_offset: %d\n", match_offset);
#endif

    /* remove the port */
    if (!ip_nat_mangle_tcp_packet( 
                pskb, ct, ctinfo,
                match_offset,
                match_len,
                &port_ptr[PORT_NEEDLE_LEN],
                match_len - PORT_NEEDLE_LEN ) )  {
#ifdef SL_DEBUG
        printk(KERN_ERR "unable to remove port needle\n");
#endif
        return 0;
    }

#ifdef SL_DEBUG
    printk(KERN_DEBUG "\nport needle removed ok\n");
#endif

   return 1; 
}

#endif
