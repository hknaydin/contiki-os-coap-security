Aşağıdaki eklemeleri yaptıktan sonra initialize fonksyonunu
örneğin başında çağırmanız yeterlidir. [ secure_join_init() ]

Example Makefile'ına Eklenmesi Gerekenler
=========================================

ifeq ($(WITH_SECURE_JOIN),1)
CFLAGS+=-DSECURE_JOIN_ENABLED=1

# REST Engine shall use Erbium CoAP implementation
APPS += er-oscoap
APPS += rest-engine
APPS += secure-join

# minimal-net target is currently broken in Contiki
ifeq ($(TARGET), minimal-net)

CFLAGS += -DHARD_CODED_ADDRESS=\"fdfd::10\"
${info INFO: er-example compiling with large buffers}
CFLAGS += -DUIP_CONF_BUFFER_SIZE=1300
CFLAGS += -DREST_MAX_CHUNK_SIZE=1024
CFLAGS += -DCOAP_MAX_HEADER_SIZE=176
CONTIKI_WITH_RPL=0
endif

# optional rules to get assembly
#$(OBJECTDIR)/%.o: asmdir/%.S


Example project-conf.h Eklenmesi Gerekenler
===========================================

#if SECURE_JOIN_ENABLED
#define UIP_CONF_ND6_SEND_NS 1
#define UIP_CONF_ND6_SEND_NA 1

#undef RPL_CONF_MAX_DAG_PER_INSTANCE
#define RPL_CONF_MAX_DAG_PER_INSTANCE     1

/* Disabling TCP on CoAP nodes. */
#undef UIP_CONF_TCP
#define UIP_CONF_TCP                   0

/* Increase rpl-border-router IP-buffer when using more than 64. */
#undef REST_MAX_CHUNK_SIZE
#define REST_MAX_CHUNK_SIZE            48

/* Estimate your header size, especially when using Proxy-Uri. */
/*
   #undef COAP_MAX_HEADER_SIZE
   #define COAP_MAX_HEADER_SIZE           70
*/

/* Multiplies with chunk size, be aware of memory constraints. */
#undef COAP_MAX_OPEN_TRANSACTIONS
#define COAP_MAX_OPEN_TRANSACTIONS     1

/* Must be <= open transactions, default is COAP_MAX_OPEN_TRANSACTIONS-1. */
#undef COAP_MAX_OBSERVERS
#define COAP_MAX_OBSERVERS             2

/* Filtering .well-known/core per query can be disabled to save space. */
#undef COAP_LINK_FORMAT_FILTERING
#define COAP_LINK_FORMAT_FILTERING     0

/* Turn off DAO ACK to make code smaller */
#undef RPL_CONF_WITH_DAO_ACK
#define RPL_CONF_WITH_DAO_ACK          0

/* Enable client-side support for COAP observe */
#define COAP_OBSERVE_CLIENT 1
#endif /* SECURE_JOIN_ENABLED */# contiki-os-coap-security
