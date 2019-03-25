/*
 * Adaptation of fragments for OX
 * by Fernando López 2019
 * Port to lwIP from uIP
 * by Jim Pettinato April 2007
 *
 * security fixes and more by Simon Goldschmidt
 *
 * uIP version Copyright (c) 2002-2003, Adam Dunkels.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*-----------------------------------------------------------------------------
 * RFC 1035 - Domain names - implementation and specification
 * RFC 2181 - Clarifications to the DNS Specification
 *----------------------------------------------------------------------------*/

/** Callback which is invoked when a hostname is found.
 * A function of this type must be implemented by the application using the DNS resolver.
 * @param name pointer to the name that was looked up.
 * @param ipaddr pointer to an ip_addr_t containing the IP address of the hostname,
 *        or NULL if the name could not be found (or on any other error).
 * @param callback_arg a user-specified callback argument passed to dns_gethostbyname
*/



typedef void (*dns_answer_callback)(const char *name, void *callback_arg);

void             dns_init(void);
void             dns_tmr(void);
void             dns_setserver(u8_t numdns, const ip_addr_t *dnsserver);
const ip_addr_t* dns_getserver(u8_t numdns);
err_t            dns_gethostbyname(const char *hostname, ip_addr_t *addr,
                                   dns_found_callback found, void *callback_arg);
err_t            dns_gethostbyname_addrtype(const char *hostname, ip_addr_t *addr,
                                   dns_found_callback found, void *callback_arg,
                                   u8_t dns_addrtype);

typedef struct {
    err_t (*connect)();
    err_t (*disconnect)();
    err_t (*send)(uint8_t *buff, size_t len);
    err_t (*recv)(uint8_t *buff, size_t *len);
} transport_t;

typedef struct {
    void seed();
    uint16_t random();
    void *malloc(size_t);
} platform_t;

transport_t *transport;
platform_t *platform;

void dns_init(
        transport_t *transport_handler,
        platform_t *platform_handler)
{
    transport = transport_handler;
    platform = platform_handler;
    platform->seed();
}

err_t dns_query(
        const char *name,
        uint8_t qtype,
        dns_answer_callback answer_cb,
        void *callback_arg)
{
    struct dns_hdr hdr;
    struct dns_footer footer;
    size_t name_len = strlen(name);
    size_t query_len = sizeof(dns_hdr) + sizeof(dns_footer) +\
                       strlen(name) + 2;

    if (query_len < name_len || query_len < sizeof(dns_hdr) ||\
            query_len < sizeof(dns_footer)){
        return ERROR_NAME_TOO_LONG;
    }

    uint8_t *buff = malloc(query_len);
    uint8_t *name_copy = malloc(name_len + 1);
    if (buff == NULL || name_copy == NULL){
        return ERROR_NOT_ENOUGHT_MEMORY;
    }

    memset(&hdr, 0, sizeof(struct dns_hdr));
    hdr.id = htons(platform->random());
    hdr.flags1 = DNS_FLAG1_RD;
    hdr.numquestions = htons(1);
    footer.qtype = qtype
    footer.qclass = DNS_RRCLASS_IN;
    memcpy(buff, &hdr);
    memcpy(buff + sizeof(dns_hdr) + name_len + 2, &footer);

    name = entry->name;
    --name;

    /* convert name into suitable query format. */
    size_t offset = sizeof(struct dns_hdr);
    do {
        size_t copy_len;
        ++name;
        name_part = name;
        for (copy_len = 0; *name != '.' && *name != 0; name++, copy_len++);
        if (copy_len > 64) {
            return ERROR_NAME_LABEL_TOO_LONG;
        }
        buff[offset++] = (uint8_t) copy_len;
        memcpy(buff + offset, name_part, copy_len);
        offset = offset + copy_len + 1;
    } while (*name != 0);
    buff[offset++] = 0;
}


struct dns_hdr {
  PACK_STRUCT_FIELD(u16_t id);
  PACK_STRUCT_FLD_8(u8_t flags1);
  PACK_STRUCT_FLD_8(u8_t flags2);
  PACK_STRUCT_FIELD(u16_t numquestions);
  PACK_STRUCT_FIELD(u16_t numanswers);
  PACK_STRUCT_FIELD(u16_t numauthrr);
  PACK_STRUCT_FIELD(u16_t numextrarr);
} PACK_STRUCT_STRUCT;
PACK_STRUCT_END
}




#if DNS_LOCAL_HOSTLIST
size_t         dns_local_iterate(dns_found_callback iterator_fn, void *iterator_arg);
err_t          dns_local_lookup(const char *hostname, ip_addr_t *addr, u8_t dns_addrtype);
#if DNS_LOCAL_HOSTLIST_IS_DYNAMIC
int            dns_local_removehost(const char *hostname, const ip_addr_t *addr);
err_t          dns_local_addhost(const char *hostname, const ip_addr_t *addr);
#endif /* DNS_LOCAL_HOSTLIST_IS_DYNAMIC */
#endif /* DNS_LOCAL_HOSTLIST */




#endif
