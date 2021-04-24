/*
 * Copyright (c) 2017, Mavi Alp Research Limited.
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
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 *
 */

/**
 * \file
 *      draft-ietf-6tisch-minimal-security-03
 *      Secure Join Application
 * \author
 *      Kadir Yanık <eleqiac2@gmail.com>
 */

#include "contiki.h"
#include "net/ip/uip.h"
#include "net/ip/uip-udp-packet.h"
#include "sys/ctimer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if TSCH_TIME_SYNCH
#include "net/rpl/rpl-private.h"
#include "net/mac/4emac/4emac-private.h"
#endif /* TSCH_TIME_SYNCH */

#define DEBUG DEBUG_PRINT
#include "net/ip/uip-debug.h"

//To enable authentation using oscoap
#include "rest-engine.h"
#include "er-oscoap.h"
#include "er-coap-engine.h"
#include "cose-keyset-decoder.h"
#include "er-coap-constants.h"

#include "secure-join.h"

static uip_ipaddr_t local_prefix;         // Local Prefix holder
static uip_ipaddr_t time_master_ipaddr;   // Will set sending JoinReq, holding time master ipaddr

#define PRINT_KEY(key) PRINTF("0x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x\n", key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7], \
                                                                      key[8], key[9], key[10], key[11], key[12], key[13], key[14], key[15])

#define LOCAL_PORT      UIP_HTONS(COAP_DEFAULT_PORT + 1)
#define REMOTE_PORT     UIP_HTONS(COAP_DEFAULT_PORT)

#define NUMBER_OF_URLS 1

////////////////////////////////////////
#define TIMER_NEIGHBOR_MAX_INTERVAL (1 * 30 * CLOCK_SECOND)
#define TIMER_ROUTING_INTERVAL (2 * 30 * CLOCK_SECOND)

#define JOIN_PORT 5683
PROCESS(secure_join_send_neigbour_table_process, "secure_join_send_neigbour_table_process");
//////////////////////////////////////////
const char *service_urls[NUMBER_OF_URLS] = { "/j" };

#define NBR_PROBING_INTERVAL (30 * CLOCK_SECOND)
static struct ctimer nbr_timer;

uint8_t master_secret[OSCOAP_MASTER_SECRET_LEN] = MASTER_SECRET;
/*---------------------------------------------------------------------------*/
PROCESS(secure_join_process, "Secure Join process");
AUTOSTART_PROCESSES(&secure_join_process);
/*---------------------------------------------------------------------------*/
void
client_chunk_handler(void *response)
{
  const uint8_t *chunk;
  int len = coap_get_payload(response, &chunk);
  int i;

  PRINTF("Secure-Join: Response Arrived[%d]: ", len);
  for(i = 0; i < len; i++){
    PRINTF("%x ", chunk[i]);
  }
  PRINTF("\n");

  /* COSE_KeySets */
  keyset_t keysets[2];
  if(!cbor_parse((unsigned char *)chunk, len, keysets)){
    print_keyset(keysets);
  }
  if(keysets[0].key_len == AES_CCM_16_64_128_KEY_LEN){
    PRINTF("Secure-Join: Key: ");
    PRINT_KEY(keysets[0].key);
#if LLSEC802154_ENABLED
    //foure_security_set_key(keysets[0].key, 0); //K1 changed
    foure_security_set_key(keysets[0].key, 1); //K2 changed
#endif
    ctimer_stop(&nbr_timer);

    foure_control.secured = 1;
    foure_control.authenticated = 1;
  } else{
    PRINTF("Secure-Join: Error: key_len != %d\n", AES_CCM_16_64_128_KEY_LEN);
  }
}
/*------------------------------------------------------------------------------*/
static void
handle_nbr_timer(void *ptr)
{
  PRINTF("Send DIS to %u\n", time_master_ipaddr.u8[15]);
  dis_output(&time_master_ipaddr);

  ctimer_stop(&nbr_timer);
  ctimer_set(&nbr_timer, NBR_PROBING_INTERVAL, handle_nbr_timer, ptr);
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(secure_join_process, ev, data)
{
  static struct etimer et;
  static coap_packet_t request[1];      /* This way the packet can be treated as pointer as usual. */
  static uint8_t token[] = { 0x05, 0x05 };
  static uint8_t sender_id[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0x00 };
  static uint8_t receiver_id[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0x01 };

  PROCESS_BEGIN();

  PRINTF("Secure Join Process Started\n");

  oscoap_ctx_store_init();
  init_token_seq_store();

  /* Sets pledge EUI-64 addr */
  memcpy(sender_id, uip_lladdr.addr, 8);
  memcpy(receiver_id, uip_lladdr.addr, 8);

  if(!oscoap_new_ctx(master_secret, sizeof(master_secret), sender_id, ID_LEN, receiver_id, ID_LEN, REPLAY_WINDOW_LEN)){
    PRINTF("Secure-Join: Error: Couldn't create new context!\n");
  }

  PROCESS_PAUSE();

  etimer_set(&et, CLOCK_SECOND);
  while(!foure_control.synched){
    PROCESS_WAIT_UNTIL(etimer_expired(&et));
    etimer_reset(&et);
  }

  uip_create_linklocal_prefix(&local_prefix);
  memset(&time_master_ipaddr, 0, sizeof(uip_ipaddr_t));
  memcpy(&time_master_ipaddr, &local_prefix, 64 >> 3);
  uip_ds6_set_addr_iid(&time_master_ipaddr, (uip_lladdr_t *)&time_master_linkaddr);

  if(uip_ds6_nbr_add(&time_master_ipaddr, (const uip_lladdr_t *)&time_master_linkaddr, 0, NBR_REACHABLE, NBR_TABLE_REASON_UNDEFINED, NULL) == NULL) {
    PRINTF("Secure-Join: Neighbor add failed!\n");
    PROCESS_EXIT();
  }

  DESTINATION_ADD_CALLBACK(&time_master_linkaddr, NBR_TABLE_REASON_UNDEFINED, NULL);

  ctimer_stop(&nbr_timer);
  ctimer_set(&nbr_timer, 2 * (random_rand() % CLOCK_SECOND), handle_nbr_timer, NULL);

  etimer_set(&et, 5 * (random_rand() % CLOCK_SECOND) + CLOCK_SECOND);

  while(1) {
    PROCESS_YIELD();

    if(etimer_expired(&et) && !foure_control.authenticated) {
      coap_init_message(request, COAP_TYPE_CON, COAP_GET, 0);

      //coap_set_header_proxy_uri(request, "coap://6tisch.arpa/j?q=1");

      coap_set_header_proxy_scheme(request, "coap");
      coap_set_header_uri_host(request, "6tisch.arpa");
      coap_set_header_uri_path(request, service_urls[0]);

      coap_set_header_object_security(request);
      coap_set_token(request, token, 2);

      // Set context with Receiver ID
      request->context = oscoap_find_ctx_by_rid(receiver_id, ID_LEN);

      PRINTF("Secure-Join: Sending JoinRequest via Uri-Path: [%s]\n", service_urls[0]);
      
      PRINT6ADDR(&time_master_ipaddr);

      PRINTF(" : %u\n", UIP_HTONS(REMOTE_PORT));

      COAP_BLOCKING_REQUEST(&time_master_ipaddr, REMOTE_PORT, request,
                            client_chunk_handler);
      token[1]++;
      PRINTF("\nSecure-Join: Block request done!\n");

      etimer_set(&et, random_rand() % CLOCK_SECOND);
    }
  }

  PROCESS_END();
}

/*---------------------------------------------------------------------------*/

PROCESS_THREAD(secure_join_send_neigbour_table_process, ev, data)
{
  static struct etimer neighbor_duration_timer;
  static struct etimer routing_duration_timer;

///////////////////////////////////////////////////////////////////
  static struct uip_udp_conn *client_conn = NULL;
  uint8_t MAX_NEIGHBOUR = 70;
  uint8_t buf[MAX_NEIGHBOUR]; // 100 byte channel parametres request
  uint8_t total_route = 0;
  uint8_t total_neighbor = 0;
  uip_ds6_nbr_t *nbr;
  linkaddr_t *to_linkaddr;
  uip_ds6_route_t *r;
  uint8_t index = 0;
///////////////////////////////////////////////////////////////////  
uint8_t jrc_addr[16];
uip_ipaddr_t jrc_ip_addr;      

//////////////////////////////////////////////////////////////////
  PROCESS_BEGIN();

  PROCESS_PAUSE();

  etimer_set(&neighbor_duration_timer, TIMER_NEIGHBOR_MAX_INTERVAL);
  etimer_set(&routing_duration_timer, TIMER_ROUTING_INTERVAL);

  /* new connection with remote host */
  client_conn = udp_new(NULL, UIP_HTONS(5678), NULL); 
  if(client_conn == NULL) {
    PRINTF("No UDP connection available, exiting the process!\n");
    PROCESS_EXIT();
  }
  udp_bind(client_conn, JOIN_PORT); 




  while(1){
    PROCESS_YIELD();
    
    total_neighbor = 0;
    total_route = 0;
    index = 0;



    if(ev == tcpip_event){
    }

    #if 0
    if(data = &routing_duration_timer && foure_control.authenticated && foure_control.secured){
      //printf("3 dakika\n");
      
      //TODO: JRC adresi nasıl alınabilir?
      uint8_t jrc_addr[16] = JRC_IP_ADDR;
      // jrc adresini uip_ipaddr_t structına kopyala
      memcpy(jrc_ip_addr.u8, jrc_addr, 16); 

      etimer_set(&routing_duration_timer, TIMER_ROUTING_INTERVAL);
    }

    if(data = &neighbor_duration_timer && foure_control.authenticated && foure_control.secured){
      //printf("2 dakika\n");
      //TODO: JRC adresi nasıl alınabilir?
      uint8_t jrc_addr[16] = JRC_IP_ADDR;
      // jrc adresini uip_ipaddr_t structına kopyala
      memcpy(jrc_ip_addr.u8, jrc_addr, 16);      
    
      // node type
      buf[0] = 'r';
      buf[1] = 'o';
      buf[2] = 'u';
      buf[3] = 0;

      total_route = 0;

      for(r = uip_ds6_route_head();
          r != NULL;
          r = uip_ds6_route_next(r)) {

        buf[3] += 1;
        total_route++;

        buf[3 + total_route] = r->ipaddr.u8[15];
      }
      printf("total_route %d\n", buf[3]);


      if(buf[3] != 0){
        uip_udp_packet_sendto(client_conn, buf, 4 + buf[3], &jrc_ip_addr, UIP_HTONS(JOIN_PORT));
      }

      // node type
      buf[0] = 'n';
      buf[1] = 'e';
      buf[2] = 'g';
      buf[3] = 0;
    
      for(nbr = nbr_table_head(ds6_neighbors); nbr != NULL; nbr = nbr_table_next(ds6_neighbors, nbr)){
        to_linkaddr = nbr_table_get_lladdr(ds6_neighbors, nbr);
        PRINTF("%x ", to_linkaddr->u8[7]);
        buf[3] += 1;
        index++;

        buf[3 + index] = to_linkaddr->u8[7];
      }
      PRINTF("---\n");
      printf("total_neighbor %d\n", buf[3]);

    /* configure connection to reply to client */
      if(buf[3] != 0){
        printf("CoAP: Send to %u\n", jrc_ip_addr.u8[15]);
        uip_udp_packet_sendto(client_conn, buf, 4 + buf[3], &jrc_ip_addr, UIP_HTONS(JOIN_PORT));
      }

      etimer_set(&neighbor_duration_timer, TIMER_NEIGHBOR_MAX_INTERVAL);

    }
    #endif

    if(etimer_expired(&neighbor_duration_timer) && foure_control.authenticated && foure_control.secured){
      //etimer_reset(&neighbor_duration_timer); 
      PRINTF("2 dakika\n");
            //TODO: JRC adresi nasıl alınabilir?
      uint8_t jrc_addr[16] = JRC_IP_ADDR;
      // jrc adresini uip_ipaddr_t structına kopyala
      memcpy(jrc_ip_addr.u8, jrc_addr, 16);  

      // node type
      buf[0] = 'n';
      buf[1] = 'e';
      buf[2] = 'g';
      buf[3] = 0;
    
      for(nbr = nbr_table_head(ds6_neighbors); nbr != NULL; nbr = nbr_table_next(ds6_neighbors, nbr)){
        to_linkaddr = nbr_table_get_lladdr(ds6_neighbors, nbr);
        PRINTF("%x ", to_linkaddr->u8[7]);
        buf[3] += 1;
        index++;

        buf[3 + index] = to_linkaddr->u8[7];
      }
      PRINTF("---\n");
      PRINTF("total_neighbor %d\n", buf[3]);

    /* configure connection to reply to client */
      if(buf[3] != 0){
        PRINTF("CoAP: Send to %u\n", jrc_ip_addr.u8[15]);
        uip_udp_packet_sendto(client_conn, buf, 4 + buf[3], &jrc_ip_addr, UIP_HTONS(JOIN_PORT));
      }


      //etimer_set(&neighbor_duration_timer, TIMER_NEIGHBOR_MAX_INTERVAL);
    }

    if(etimer_expired(&routing_duration_timer) && foure_control.authenticated && foure_control.secured){
      etimer_reset(&routing_duration_timer);
      PRINTF("3 dakika\n");

      //TODO: JRC adresi nasıl alınabilir?
      uint8_t jrc_addr[16] = JRC_IP_ADDR;
      // jrc adresini uip_ipaddr_t structına kopyala
      memcpy(jrc_ip_addr.u8, jrc_addr, 16);      
    
      // node type
      buf[0] = 'r';
      buf[1] = 'o';
      buf[2] = 'u';
      buf[3] = 0;

      total_route = 0;

      for(r = uip_ds6_route_head();
          r != NULL;
          r = uip_ds6_route_next(r)) {

        buf[3] += 1;
        total_route++;

        buf[3 + total_route] = r->ipaddr.u8[15];
      }
      PRINTF("total_route %d\n", buf[3]);


      if(buf[3] != 0){
        uip_udp_packet_sendto(client_conn, buf, 4 + buf[3], &jrc_ip_addr, UIP_HTONS(JOIN_PORT));
      }

      etimer_set(&routing_duration_timer, TIMER_ROUTING_INTERVAL);

    }
  }
  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
void
secure_join_init(int joined)
{
  /* receives all CoAP messages */
  coap_init_engine();

  if(!joined){
    process_exit(&secure_join_process);
    process_start(&secure_join_process, NULL);
  }

    process_exit(&secure_join_send_neigbour_table_process);
    process_start(&secure_join_send_neigbour_table_process, NULL);

}
/*---------------------------------------------------------------------------*/