/*
 *
 * Copyright (c) 2001
 *	Politecnico di Torino.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * For bug report and other information please visit Tstat site:
 * http://tstat.polito.it
 *
 * Tstat is deeply based on TCPTRACE. The authors would like to thank
 * Shawn Ostermann for the development of TCPTRACE.
 *
*/

#ifdef HAVE_OPENSSL
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <regex.h>
#endif

#include "tstat.h"
#include "tcpL7.h"
#include "dns_cache.h"
#include "rfc6234/sha.h"


#ifdef DNS_CACHE_PROCESSOR
extern Bool dns_enabled;
#endif

#define get_u8(X,O)   (*(tt_uint8  *)(X + O))
#define get_u16(X,O)  (*(tt_uint16 *)(X + O))
#define get_u32(X,O)  (*(tt_uint32 *)(X + O))

#if __BIG_ENDIAN__
#define htonll(x) (x)
#define ntohll(x) (x)
#else
#define htonll(x) ((uint64_t)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32)
#define ntohll(x) ((uint64_t)ntohl((x) & 0xFFFFFFFF) << 32) | ntohl((x) >> 32)
#endif

extern struct L3_bitrates L3_bitrate;
extern struct L4_bitrates L4_bitrate;

/* locally global variables */
static int packet_count = 0;
static int search_count = 0;

#ifdef HAVE_OPENSSL
extern regex_t re_ssl_subject,re_ssl_clean;
#endif

/* provided globals  */
int num_udp_pairs = -1;		/* how many pairs we've allocated */
u_long udp_trace_count = 0;
udp_pair **utp = NULL;		/* array of pointers to allocated pairs */


/* local routine definitions */
static udp_pair *NewUTP (struct ip *, struct udphdr *);
static udp_pair *FindUTP (struct ip *, struct udphdr *, int *);
void print_udp_periodic_log(udp_pair *);

char *url_encode(char *str);

extern unsigned long int fcount;
extern Bool warn_MAX_;
extern unsigned long int f_UDP_count;
extern FILE *fp_periodic_udp_logc;

#ifdef CHECK_UDP_DUP
Bool
dup_udp_check (struct ip *pip, struct udphdr *pudp, ucb * thisdir)
{
//  static int tot;
  double delta_t = elapsed (thisdir->last_pkt_time, current_time);
  
  if (!PIP_ISV4(pip)) return FALSE;
  
  if (thisdir->last_ip_id == pip->ip_id &&
      thisdir->last_checksum == ntohs(pudp->uh_sum) && 
      delta_t < GLOBALS.Min_Delta_T_UDP_Dup_Pkt && thisdir->last_len == pip->ip_len)
    {
//       fprintf (fp_stdout, "dup udp %d , id = %u ",tot++, pip->ip_id);
//       fprintf (fp_stdout, "TTL: %d ID: %d Checksum: %d Delta_t: %g\n", 
//          pip->ip_ttl,pip->ip_id,ntohs(pudp->uh_sum),delta_t);
      thisdir->last_ip_id = pip->ip_id;
      thisdir->last_len = pip->ip_len;
      thisdir->last_checksum = ntohs(pudp->uh_sum); 
      return TRUE;
    }
//    fprintf (fp_stdout, "NOT dup udp %d\n",tot);
  thisdir->last_ip_id = pip->ip_id;
  thisdir->last_len = pip->ip_len;
  thisdir->last_checksum = ntohs(pudp->uh_sum); 
  return FALSE;
}
#endif

static udp_pair *
NewUTP (struct ip *pip, struct udphdr *pudp)
{
  udp_pair *pup;
  int old_new_udp_pairs = num_udp_pairs;
  int steps = 0;

  /* look for the next eventually available free block */
  num_udp_pairs++;
  num_udp_pairs = num_udp_pairs % GLOBALS.Max_UDP_Pairs;
  /* make a new one, if possible */
  while ((num_udp_pairs != old_new_udp_pairs) && (utp[num_udp_pairs] != NULL)
	 && (steps < GLOBALS.List_Search_Dept))
    {
      steps++;
      /* look for the next one */
//         fprintf (fp_stdout, "%d %d\n", num_udp_pairs, old_new_udp_pairs);
      num_udp_pairs++;
      num_udp_pairs = num_udp_pairs % GLOBALS.Max_UDP_Pairs;
    }
  if (utp[num_udp_pairs] != NULL)
    {
      if (warn_MAX_)
	{
	  fprintf (fp_stderr, 
        "\nooopsss: number of simultaneous connection opened is greater then the maximum supported number!\n"
	    "you have to rebuild the source with a larger LIST_SEARCH_DEPT defined!\n"
	    "or possibly with a larger 'MAX_UDP_PAIRS' defined!\n");
	}
      warn_MAX_ = FALSE;
      return (NULL);
    }

  /* create a new UDP pair record and remember where you put it */
  pup = utp[num_udp_pairs] = utp_alloc ();

  /* grab the address from this packet */
  CopyAddr (&pup->addr_pair,
	    pip, ntohs (pudp->uh_sport), ntohs (pudp->uh_dport));

  pup->c2s.first_pkt_time.tv_sec = 0;
  pup->s2c.first_pkt_time.tv_sec = 0;

  pup->c2s.last_pkt_time.tv_sec = -1;
  pup->s2c.last_pkt_time.tv_sec = -1;

  pup->c2s.pup = pup;
  pup->s2c.pup = pup;

  pup->internal_src = internal_src;
  pup->internal_dst = internal_dst;

  pup->cloud_src = cloud_src;
  pup->cloud_dst = cloud_dst;

  if (crypto_src)
   {
#ifdef SUPPORT_IPV6   
     if (ADDR_ISV6(&(pup->addr_pair.a_address)))
       store_crypto_ipv6(&(pup->addr_pair.a_address.un.ip6));
     else
#endif
       store_crypto_ip(&(pup->addr_pair.a_address.un.ip4));
   }

  if (crypto_dst)
   {
#ifdef SUPPORT_IPV6   
     if (ADDR_ISV6(&(pup->addr_pair.a_address)))
       store_crypto_ipv6(&(pup->addr_pair.b_address.un.ip6));
     else
#endif
       store_crypto_ip(&(pup->addr_pair.b_address.un.ip4));
   }

  pup->crypto_src = crypto_src;
  pup->crypto_dst = crypto_dst;

  pup->c2s.type = UDP_UNKNOWN;
  pup->s2c.type = UDP_UNKNOWN;
  
  pup->c2s.kad_state = OUDP_UNKNOWN;
  pup->s2c.kad_state = OUDP_UNKNOWN;

  pup->c2s.uTP_state = UTP_UNKNOWN;
  pup->s2c.uTP_state = UTP_UNKNOWN;

  pup->c2s.QUIC_state = QUIC_UNKNOWN;
  pup->s2c.QUIC_state = QUIC_UNKNOWN;
  
#ifdef DNS_CACHE_PROCESSOR
 if (dns_enabled)
  {
#ifdef SUPPORT_IPV6
    if (PIP_ISV6(pip))
     { 
    struct DNS_data_IPv6* dns_data =  get_dns_entry_ipv6(&(PIP_V6(pip)->ip6_saddr), &(PIP_V6(pip)->ip6_daddr));
    if(dns_data!=NULL){
	 pup->dns_name = dns_data->hostname;
	 pup->dns_server.addr_vers = 6;
	 memcpy((&pup->dns_server.un.ip6),&(dns_data->dns_server),sizeof(struct in6_addr));
	 pup->request_time = dns_data->request_time;
	 pup->response_time = dns_data->response_time;
	 pup->crypto_dns = crypto_ipv6(pup->dns_server.un.ip6);
     }
#ifdef SUPPORT_MIXED_DNS
    else {
      // Look for a DNS6 query from an equivalent IPv4 addresses
      struct DNS_data_IPv6* dns_data =  get_dns_entry_ipv6_dns4(&(PIP_V6(pip)->ip6_saddr), &(PIP_V6(pip)->ip6_daddr));
      if(dns_data!=NULL){
	 pup->dns_name = dns_data->hostname;
	 // The DNS Server was IPv4, stored in the DNSCache IP4->6 format
	 pup->dns_server.addr_vers = 4;
	 pup->dns_server.un.ip4.s_addr = map_6to4(&(dns_data->dns_server));
	 pup->request_time = dns_data->request_time;
	 pup->response_time = dns_data->response_time;
	 pup->crypto_dns = crypto_ip(pup->dns_server.un.ip4);
       }
    }
#endif /* SUPPORT_MIXED_DNS */
     }
    else
#endif /* SUPPORT_IPV6 */
    {
    /* Do reverse lookup */
    struct DNS_data* dns_data = get_dns_entry(pip->ip_src.s_addr, pip->ip_dst.s_addr);
    if(dns_data!=NULL){
	  pup->dns_name = dns_data->hostname;
	  pup->dns_server.addr_vers = 4;
	  memcpy((&pup->dns_server.un.ip4),&(dns_data->dns_server),sizeof(struct in_addr));
	  pup->request_time = dns_data->request_time;
	  pup->response_time = dns_data->response_time;
	  pup->crypto_dns = crypto_ip(pup->dns_server.un.ip4);
     }
#if defined(SUPPORT_IPV6) && defined(SUPPORT_MIXED_DNS)
    else {
      // Look for a DNS4 query from an equivalent IPv6 addresses
      struct DNS_data_IPv6* dns_data =  get_dns_entry_ipv4_dns6(pip->ip_src.s_addr, pip->ip_dst.s_addr);
      if(dns_data!=NULL){
	 pup->dns_name = dns_data->hostname;
	 // The DNS Server was IPv6
	 pup->dns_server.addr_vers = 6;
	 memcpy((&pup->dns_server.un.ip6),&(dns_data->dns_server),sizeof(struct in6_addr));
	 pup->request_time = dns_data->request_time;
	 pup->response_time = dns_data->response_time;
	 pup->crypto_dns = crypto_ipv6(pup->dns_server.un.ip6);
       }
    }
#endif /* SUPPORT_IPV6 && SUPPORT_MIXED_DNS */
    }
  }
 else
  pup->dns_name = NULL;
//  pup->dns_name = reverse_lookup(ntohl(pip->ip_src.s_addr), ntohl(pip->ip_dst.s_addr));
#else
  pup->dns_name = NULL;
/*
  pup->dns_server = NULL;
  pup->request_time = NULL;
  pup->response_time = NULL;
*/  
#endif

  pup->quic_sni_name = NULL;
  pup->quic_ua_string = NULL;
  memset(pup->quic_c_vers, 0, 4);
  memset(pup->quic_s_vers, 0, 4);
  pup->quic_zero_rtt = 0;
  pup->is_stun_initiated = 0;

#ifdef LOG_PERIODIC
  // LOG_PERIODIC
  pup->last_print_time = current_time;
#endif //LOG_PERIODIC
  
  
  return (utp[num_udp_pairs]);
}


udp_pair **pup_hashtable;


/* connection records are stored in a hash table.  Buckets are linked	*/
/* lists sorted by most recent access.					*/
// static 
udp_pair *
FindUTP (struct ip * pip, struct udphdr * pudp, int *pdir)
{
  udp_pair **ppup_head = NULL;
  udp_pair *pup;
  udp_pair *pup_last;
  udp_pair tp_in;

  int prof_curr_clk;
  struct timeval prof_tm;
  double prof_curr_tm;
  struct tms prof_curr_tms;
  double cpu_sys,cpu_usr;


  int dir;
  hash hval;

  /* grab the address from this packet */
  CopyAddr (&tp_in.addr_pair, pip,
	    ntohs (pudp->uh_sport), ntohs (pudp->uh_dport));

  /* grab the hash value (already computed by CopyAddr) */
  hval = tp_in.addr_pair.hash % GLOBALS.Hash_Table_Size;


  pup_last = NULL;
  ppup_head = &pup_hashtable[hval];
  for (pup = *ppup_head; pup; pup = pup->next)
    {
      ++search_count;
      if (SameConn (&tp_in.addr_pair, &pup->addr_pair, &dir))
	{
	  /* move to head of access list (unless already there) */
	  if (pup != *ppup_head)
	    {
	      pup_last->next = pup->next;	/* unlink */
	      pup->next = *ppup_head;	/* move to head */
	      *ppup_head = pup;
	    }
	  *pdir = dir;

/*
#ifdef RUNTIME_SKYPE_RESET
	  if (elapsed (pup->first_time, current_time) >
	      SKYPE_UPDATE_DELTA_TIME)
	    {
//            close_udp_flow (pup, -1, dir)
	      memset (&(pup->c2s.skype), 0, sizeof ((pup->c2s.skype)));
	      memset (&(pup->s2c.skype), 0, sizeof ((pup->s2c.skype)));
	      bayes_reset ((pup->c2s.bc_pktsize), BAYES_RESET_ZERO);
	      bayes_reset ((pup->c2s.bc_avgipg), BAYES_RESET_ZERO);

	    }
	  else
#endif
*/
	    return (pup);
	}
      pup_last = pup;
    }

    /* profile CPU */
    if (profile_cpu -> flag == HISTO_ON) {
        prof_curr_clk = (int)clock();
        gettimeofday(&prof_tm, NULL);
        prof_curr_tm = time2double(prof_tm)/1e6;
        times(&prof_curr_tms);
        
        
        if (prof_curr_tm - prof_last_tm > PROFILE_IDLE) {
            /* system cpu */
            cpu_sys = 1.0 * (prof_curr_tms.tms_stime - prof_last_tms.tms_stime) / prof_cps /
                  (prof_curr_tm - prof_last_tm) * 100;
            AVE_new_step(prof_tm, &ave_win_sys_cpu, cpu_sys);
            // system + user cpu
            //usr_cpu = 1.0 * (prof_curr_clk - prof_last_clk) / CLOCKS_PER_SEC / 
            //      (prof_curr_tm - prof_last_tm) * 100;
            /* user cpu */
            cpu_usr = 1.0 * (prof_curr_tms.tms_utime - prof_last_tms.tms_utime) / prof_cps /
                  (prof_curr_tm - prof_last_tm) * 100;
            AVE_new_step(prof_tm, &ave_win_usr_cpu, cpu_usr);
        
            prof_last_tm = prof_curr_tm;
            prof_last_clk = prof_curr_clk; 
            prof_last_tms = prof_curr_tms;
            max_cpu = (max_cpu < (cpu_usr+cpu_sys)) ? cpu_usr+cpu_sys : max_cpu;
            //printf("cpu:%.2f max:%.2f\n", cpu, max_cpu);
        }
    }

/* if is elapsed an IDLE_TIME from the last cleaning flow operation I will start
a new one */

  // we fire it at DOUBLE rate, but actually clean only those > UDP_IDLE_TIME
  if (elapsed (last_cleaned, current_time) > GLOBALS.GC_Fire_Time)
    {
      int i;
      for (i=0; i< elapsed (last_cleaned, current_time) / GLOBALS.GC_Fire_Time; i++ )
         trace_done_periodic ();
      last_cleaned = current_time;
    }

  fcount++;
  f_UDP_count++;
  add_histo (L4_flow_number, L4_FLOW_UDP);

  pup = NewUTP (pip, pudp);

  /* put at the head of the access list */
  if (pup)
    {
      if (profile_flows->flag == HISTO_ON)
        AVE_arrival(current_time, &active_flows_win_UDP);
      tot_conn_UDP++;
      pup->next = *ppup_head;
      *ppup_head = pup;
    }
  /* profile number of missed udp session */
  else if (profile_flows->flag == HISTO_ON)
        AVE_arrival(current_time, &missed_flows_win_UDP);

  *pdir = C2S;

  /*Return the new utp */

  return (pup);
}


void check_udp_obfuscate(ucb *thisdir, ucb *otherdir, u_short uh_ulen)
{
  if (thisdir->obfuscate_state==0 && otherdir->obfuscate_state==0)
   {
     switch(uh_ulen)
      {
	case 43:
	  thisdir->kad_state=OUDP_REQ43;
          break;
	case 59:
	  thisdir->kad_state=OUDP_REQ59;
          break;
        case 22:
          if (otherdir->obfuscate_last_len>=36 &&
              otherdir->obfuscate_last_len<=70)
            {
	      otherdir->kad_state=OUDP_SIZEX_22;
	      otherdir->obfuscate_state=1;
	      thisdir->pup->kad_state = OUDP_SIZEX_22;
            } 
          break;
	default:
	  if ( uh_ulen>=52 && (uh_ulen-52)%25 == 0)
	   {
	     if (otherdir->kad_state==OUDP_REQ43)
              {
		otherdir->kad_state=OUDP_RES52_K25;
		otherdir->obfuscate_state=1;
		thisdir->pup->kad_state=OUDP_RES52_K25;
	      }
             else if (uh_ulen==52 && 
        	      otherdir->obfuscate_last_len>=46 &&
        	      otherdir->obfuscate_last_len<=57)
              {
		otherdir->kad_state=OUDP_SIZEX_52;
		otherdir->obfuscate_state=1;
	        thisdir->pup->kad_state = OUDP_SIZEX_52;
              } 
             else
		otherdir->kad_state=OUDP_UNKNOWN;
             break;
           }
	  else if ( uh_ulen>=68 && (uh_ulen-68)%25 == 0)
	   {
	     if (otherdir->kad_state==OUDP_REQ59)
              {
		otherdir->kad_state=OUDP_RES68_K25;
		otherdir->obfuscate_state=1;
		thisdir->pup->kad_state=OUDP_RES68_K25;
	      }
             else
		otherdir->kad_state=OUDP_UNKNOWN;
             break;
           }
	  else if ( uh_ulen>=46 && uh_ulen<=57 &&
		    otherdir->obfuscate_last_len >=46 &&
        	    otherdir->obfuscate_last_len <=57)
           {
	     otherdir->kad_state=OUDP_SIZE_IN_46_57;
	     otherdir->obfuscate_state=1;
	     thisdir->pup->kad_state=OUDP_SIZE_IN_46_57;
	   }
          else
           {
	     thisdir->kad_state=OUDP_UNKNOWN;
	     otherdir->kad_state=OUDP_UNKNOWN;
           }
	  break;
      }

     thisdir->obfuscate_last_len = uh_ulen;

   }

  return;
}

void check_uTP(struct ip * pip, struct udphdr * pudp, void *plast,
                ucb *thisdir, ucb *otherdir)
{
  int payload_len;
  int data_len;
  unsigned char *base;
  tt_uint16 connection_id,seq_nr;

  if (thisdir->is_uTP==1 && otherdir->is_uTP==1)
    return;  /* Flow already classified */

  payload_len = ntohs (pudp->uh_ulen);
  /* This is the UDP complete length, included the header size */

  base = (unsigned char *) pudp;
  data_len = (unsigned char *) plast - (unsigned char *) base + 1;

  if (data_len < 28 || payload_len == 0)
    return;  /* Minimum uTP size is 8+20 bytes */
  
  if ( !( 
  	  ((base[8] & 0x31) || (base[8]==0x41) ) &&
     	  ( base[9]==0 || base[9]==1 || base[9]==2 )
     	)
     )  
    return; /* Minimal protocol matching failed*/

  switch(thisdir->uTP_state)
   {
/*
  Unknown --0x41-> SYN_SEEN --0x21-> completed open
  Unknown --0x41-> SYN_SEEN --0x11-> completed fin
  Unknown --0x41-> SYN_SEEN --0x31-> completed reset
  Unknown --0x01-> DATA_SEEN --0x21-> completed data_ack
  Unknown --0x01-> DATA_SEEN --0x01-> completed data_data
  Unknown --0x01-> DATA_SEEN --0x11-> completed data_fin
  Unknown --0x01-> DATA_SEEN --0x31-> completed data_reset
  Unknown --0x21-> ACK_SEEN --0x01-> completed ack_data
  Unknown --0x21-> ACK_SEEN --0x11-> completed ack_fin
  Unknown --0x21-> ACK_SEEN --0x31-> completed ack_reset
*/
     case UTP_UNKNOWN:
     case UTP_DATA_SENT:
     case UTP_SYN_SENT:
     case UTP_ACK_SENT:
       switch (base[8])
        {
	  case 0x01:
	    thisdir->uTP_conn_id=ntohs(*(tt_uint16 *)(base+10));
	    thisdir->uTP_state=UTP_DATA_SENT;
	    otherdir->uTP_state=UTP_DATA_SEEN;
	    break;
	  case 0x21:
	    thisdir->uTP_conn_id=ntohs(*(tt_uint16 *)(base+10));
	    thisdir->uTP_state=UTP_ACK_SENT;
	    otherdir->uTP_state=UTP_ACK_SEEN;
	    break;
	  case 0x41:
	    thisdir->uTP_conn_id=ntohs(*(tt_uint16 *)(base+10));
	    thisdir->uTP_syn_seq_nr=ntohs(*(tt_uint16 *)(base+24));
	    thisdir->uTP_state=UTP_SYN_SENT;
	    otherdir->uTP_state=UTP_SYN_SEEN;
	    break;
	  default:
	    break;
	}
       break;
     case UTP_SYN_SEEN:
       switch (base[8])
        {
	  case 0x11: /* SYN->FIN  check only the ID */ 
	    connection_id=ntohs(*(tt_uint16 *)(base+10));
	    if (connection_id==otherdir->uTP_conn_id)
	     {
	       thisdir->uTP_conn_id=connection_id;
	       otherdir->is_uTP=1;
	       thisdir->is_uTP=1;
	     }
	    break;
	  case 0x21:
	    seq_nr=ntohs(*(tt_uint16 *)(base+26));
	    connection_id=ntohs(*(tt_uint16 *)(base+10));
	    if ( seq_nr==otherdir->uTP_syn_seq_nr &&
	         connection_id==otherdir->uTP_conn_id)
	     {
	       thisdir->uTP_conn_id=connection_id;
	       otherdir->is_uTP=1;
	       thisdir->is_uTP=1;
	     }
	    break;
	  case 0x31: /* SYN->RESET  check only the ID */ 
	    connection_id=ntohs(*(tt_uint16 *)(base+10));
	    if (connection_id==otherdir->uTP_conn_id)
	     {
	       thisdir->uTP_conn_id=connection_id;
	       otherdir->is_uTP=1;
	       thisdir->is_uTP=1;
	     }
	    break;
	  case 0x41:
	    thisdir->uTP_conn_id=ntohs(*(tt_uint16 *)(base+10));
	    thisdir->uTP_syn_seq_nr=ntohs(*(tt_uint16 *)(base+24));
	    thisdir->uTP_state=UTP_SYN_SENT;
	    otherdir->uTP_state=UTP_SYN_SEEN;
	    break;
	  default:
	    break;
	}
       break;
     case UTP_DATA_SEEN:
       switch (base[8])
        {
	  case 0x01: /* DATA->DATA */
	  case 0x11: /* DATA->FIN */
	  case 0x21: /* DATA->ACK */
	    connection_id=ntohs(*(tt_uint16 *)(base+10));
	    if (connection_id==otherdir->uTP_conn_id+1 || 
	        connection_id==otherdir->uTP_conn_id-1)
	     {
	       thisdir->uTP_conn_id=connection_id;
	       otherdir->is_uTP=1;
	       thisdir->is_uTP=1;
	     }
	    break;
	  case 0x31: /* DATA->RESET */
	    connection_id=ntohs(*(tt_uint16 *)(base+10));
	    if (connection_id==otherdir->uTP_conn_id)
	     {
	       thisdir->uTP_conn_id=connection_id;
	       otherdir->is_uTP=1;
	       thisdir->is_uTP=1;
	     }
	    break;
	  default:
	    break;
	}
       break;
     case UTP_ACK_SEEN:
       switch (base[8])
        {
	  case 0x01: /* ACK->DATA */
	  case 0x11: /* ACK->FIN */
	  case 0x21: /* ACK->ACK */
	    connection_id=ntohs(*(tt_uint16 *)(base+10));
	    if (connection_id==otherdir->uTP_conn_id+1 || 
	        connection_id==otherdir->uTP_conn_id-1)
	     {
	       thisdir->uTP_conn_id=connection_id;
	       otherdir->is_uTP=1;
	       thisdir->is_uTP=1;
	     }
	    break;
	  case 0x31: /* ACK->RESET */
	    connection_id=ntohs(*(tt_uint16 *)(base+10));
	    if (connection_id==otherdir->uTP_conn_id)
	     {
	       thisdir->uTP_conn_id=connection_id;
	       otherdir->is_uTP=1;
	       thisdir->is_uTP=1;
	     }
	    break;
	  default:
	    break;
	}
       break;
     default:
       break;
   }

  if (thisdir->is_uTP==1 && otherdir->is_uTP==1)
   {
     if (thisdir->type==UDP_UNKNOWN ||
    	 thisdir->type==FIRST_RTP_PLUS || 
    	 thisdir->type==FIRST_RTP || 
    	 thisdir->type==FIRST_RTCP)
      { thisdir->type=P2P_UTP; }
     else if (thisdir->type==P2P_BT)
      { thisdir->type=P2P_UTPBT; }
     else
      { 
        // fprintf(fp_stderr, "uTP type overriding %d\n",thisdir->type);
    	thisdir->type=P2P_UTP; 
      }

     if (otherdir->type==UDP_UNKNOWN ||
    	 otherdir->type==FIRST_RTP_PLUS || 
    	 otherdir->type==FIRST_RTP || 
    	 otherdir->type==FIRST_RTCP)
      { otherdir->type=P2P_UTP; }
     else if (otherdir->type==P2P_BT)
      { otherdir->type=P2P_UTPBT; }
     else
      { 
        // fprintf(fp_stderr, "uTP type overriding %d\n",otherdir->type);
    	otherdir->type=P2P_UTP; 
      }
   }
  return;
}



typedef struct {
  uint8_t header_form   : 1;
  uint8_t fixed_bit     : 1;
  uint8_t spin_bit      : 1;
  uint8_t packet_type   : 2;
  uint8_t reserved      : 2;
  uint8_t packet_nb_len : 2;
  uint8_t version[4]       ;
  uint8_t dcid_len         ;
  uint8_t dcid[20]         ;
  uint8_t scid_len         ;
  uint8_t scid[20]         ;
  uint8_t token_len        ;
  uint64_t pkt_len         ;
} quic_hdr;


/* Read Variable Length Integers
   As Defined in: https://datatracker.ietf.org/doc/html/rfc9000#section-16
   Input: start
   Output: result, offset (in Bytes)
*/
uint64_t read_var_len_int(uint8_t * start, uint8_t * offset){

    uint8_t type =  *(start) >> 6;
    uint64_t result;
    if (type==0x00){
        result = *( (uint8_t*)(start) )& 0x3F;
        *offset = 1;
    }
    else if (type==0x01){
        result = ntohs(*( (uint16_t*)(start) )) & 0x3FFF;
        *offset = 2;
    }
    else if (type==0x02){
        result = ntohl(*( (uint32_t*)(start) )) & 0x3FFFFFFF;
        *offset = 4;
    }
    else if (type==0x03){
        result = ntohll(*( (uint64_t*)(start) )) & 0x3FFFFFFFFFFFFFFF;
        *offset = 16;
    }

    return result;

}

#ifdef HAVE_OPENSSL


void search_QUIC_SNI(ucb * thisdir, unsigned char * data, int data_len, int payload_offset, quic_hdr hdr  ){

    int err;
    EVP_CIPHER_CTX *ctx;
    int plaintext_len;
    int ret;
    unsigned char plaintext [1500];
    unsigned char client_hello [1500];
    int conn_id_len = hdr.dcid_len;
    // Check UDP packet long enough
    if (data_len<payload_offset || payload_offset<19)
        return;
        
    // Must be updated in future versions
    static const char handshake_salt_v1[20] = {
        0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
        0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a
    };
    
    // Get initial secret, test on Appendix from https://datatracker.ietf.org/doc/html/rfc9001 with
    static const char connid_sample[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}; 

    unsigned char initial_secret[SHA256HashSize];
    err = hkdfExtract(SHA256, handshake_salt_v1, 20, thisdir->QUIC_conn_id, conn_id_len, initial_secret);
    if (err !=0)
      return;
    
    /* HKDF-Expand-Label from: https://tools.ietf.org/html/rfc8446 
       Client Initial Secret:  */
    static const char HkdfLabel_client_initial_secret[19] =
        {0x00, 0x20, 0x0F, 't', 'l', 's', '1', '3', ' ', 'c', 'l', 'i', 'e', 'n', 't', ' ', 'i', 'n', 0x00};
    unsigned char client_initial_secret[32];     
    err = hkdfExpand(SHA256, initial_secret, 32, HkdfLabel_client_initial_secret, 19,
                            client_initial_secret, 32);
    if (err !=0)
        return;

    //  Key
    static const char HkdfLabel_key[18] =
        {0x00, 0x10, 0x0E, 't', 'l', 's', '1', '3', ' ', 'q', 'u', 'i', 'c', ' ', 'k', 'e', 'y', 0x00};    
    unsigned char key[16];  
    err = hkdfExpand(SHA256, client_initial_secret, SHA256HashSize, HkdfLabel_key, 18,
                             key, 16);
    if (err !=0)
        return;

    // Initialization Vector
    static const char HkdfLabel_iv[17] =
        {0x00, 0x0C, 0x0D, 't', 'l', 's', '1', '3', ' ', 'q', 'u', 'i', 'c', ' ', 'i', 'v', 0x00};
        
    unsigned char iv[12];  
    err = hkdfExpand(SHA256, client_initial_secret, SHA256HashSize, HkdfLabel_iv, 17,
                             iv, 12);
    if (err !=0)
        return;

    // Header Protection
    static const char HkdfLabel_hp[17] =
        {0x00, 0x10, 0x0D, 't', 'l', 's', '1', '3', ' ', 'q', 'u', 'i', 'c', ' ', 'h', 'p', 0x00};
    unsigned char hp[16];  
    err = hkdfExpand(SHA256, client_initial_secret, SHA256HashSize, HkdfLabel_hp, 17,
                             hp, 16);
    if (err !=0)
        return;

    /* Decrypt Header */
    AES_KEY decKey;
    if (AES_set_encrypt_key(hp, 128, &decKey) < 0 || payload_offset+3 + 16 > data_len)
      return;
    // Mask obtained from encrypting first 16B with 'hp', but assuming 4B pkt len
    AES_encrypt(data+payload_offset+3, plaintext, &decKey);
    // Note: Working only for packet numbers of 1B
    uint8_t pkn = ((uint8_t)*(data+payload_offset-1)) ^ plaintext[1]; 

    // Make XOR of packet number:
    // from https://github.com/NanXiao/code-for-my-blog/blob/master/2020/09/quic_server_initial/main.c
    iv[11] = iv[11] ^ pkn; //0x01;   
    
    /* From: https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption*/  
    /* Decrypt Payload */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        return;
    if(!EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, key, iv)){
        EVP_CIPHER_CTX_free(ctx);
        return;
    }  
    if(!EVP_DecryptUpdate(ctx, plaintext, &plaintext_len, data+payload_offset, data_len - payload_offset)){ 
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    // Process plain text
    unsigned char * ptr = &plaintext[0];
    int max_length = 0;
    int iterations = 0;

    while (ptr < plaintext + plaintext_len - 16 && ptr >= plaintext && iterations <= 1500 &&
           ptr < plaintext + hdr.pkt_len -18 ){
        iterations ++;
        if ( *ptr == 0x01 || *ptr == 0x00) // PING or PADDING
            ptr++;
        else if ( *ptr == 0x06 ){ //CRYPTO
            uint8_t delta = 0;
            uint8_t delta_tot = 0;
            uint64_t offset = read_var_len_int(ptr + 1 + delta_tot, &delta);
            delta_tot += delta ;
            uint64_t length = read_var_len_int(ptr + 1 + delta_tot, &delta);
            delta_tot += delta ;
            if (ptr + 1 + delta_tot + length > plaintext + plaintext_len ||
                offset + length > 1500 )
               break;

            memcpy( client_hello + offset, ptr + 1 + delta_tot, length);
            if (offset + length > max_length)
              max_length = offset + length;
            ptr=ptr + 1 + delta_tot+length;
            
        }
        else{ // UNKNOWN FRAME
          break;
        }
    }

    // Parsing from tcpL7.c
    int idx = 38; // Was 43 in tcpL7.c, but need to subtract 5
  
    // Add session length = 1st byte of cipher suite section
    if (idx > max_length) 
      return;

    idx += 1 + client_hello[idx];

    // Add length of cipher suite section = 1st byte of compression section
    if (idx + 2 > max_length) 
      return;

    idx += 2 + ntohs(*(tt_uint16 *)(client_hello+idx)); 

    // Add length of compression section = 1st byte of extensions section
    if (idx > max_length)
      return;

    idx += 1 + client_hello[idx];

    // Full extensions section length
    if (idx + 2 > max_length) 
      return;

    int all_ext_len = ntohs(*(tt_uint16 *)(client_hello+idx));
    if (all_ext_len < 0)
      return;
    idx += 2; 

    // From tcpL7.c
    int ii = 0;   // pointer within the current extension
    int next = 0;
    char cname[81];
    int ext_type, ext_len, name_len, j, this_ii;
    
    while (ii < all_ext_len && idx+ii < max_length){

        // extract extension type
        if (idx+ii+2 > max_length) 
          return;
        ext_type = ntohs(*(tt_uint16 *)(client_hello+idx+ii));
        ii += 2;

        // extract extension length
        if (idx + ii + 2 > max_length) 
          return;
        ext_len = ntohs(*(tt_uint16 *)(client_hello + idx + ii));
        if (ext_len < 0)
          return;
        ii += 2;
        
        switch (ext_type)
         {
            // SNI (Server Name Indication)
            case 0x0000:
                // extension length
                if (idx+ii+2 > max_length) 
                  return;
                next = ii + ext_len;

                // skip up to the 1st byte of "Server Name"
                ii += 3;
                if (idx+ii+2 > max_length) 
                  return;
                name_len = ntohs(*(tt_uint16 *)(client_hello+idx+ii));
                ii += 2;

                // copy server name
                if (idx+ii > max_length) 
                  return;
                for (j=0; j < name_len && j < 79 && idx+ii+j < max_length; j++)
                 {
                    cname[j]=client_hello[idx+ii+j];
                 }
                cname[j]='\0';

                // crosscheck that subject has a reasonable syntax
                if (regexec(&re_ssl_subject,cname, (size_t) 0, NULL, 0)==0)
                {
                  if (regexec(&re_ssl_clean,cname, (size_t) 0, NULL, 0)==0)

                    if (thisdir->pup->quic_sni_name==NULL){
                      thisdir->pup->quic_sni_name = url_encode(cname);
                      //printf("%s\n", thisdir->pup->quic_sni_name);
                    }
                }

                ii = next;
                break;
            // QUIC transport parameters
            case 0x0039:
                this_ii = ii;
                iterations = 0;
                while(this_ii < ii + ext_len && this_ii>=0 && iterations <= 1500){
                    
                    // Read Type and Len
                    uint8_t offset = 0;
                    uint8_t offset_tot = 0;
                    if (idx+this_ii+offset_tot + 4 > max_length )
                      return;
                    uint64_t param_type = read_var_len_int(client_hello+idx+this_ii+offset_tot, &offset);
                    offset_tot +=offset;
                    if (idx+this_ii+offset_tot + 4 > max_length)
                      return;
                    uint64_t param_len =  read_var_len_int(client_hello+idx+this_ii+offset_tot, &offset);
                    offset_tot +=offset;

                    // Find Google User Agent
                    if (param_type == 0x3129){
                        if (idx+this_ii+offset_tot + param_len > max_length && idx+this_ii+offset_tot + param_len >= 0)
                          return;
                        memcpy(cname, client_hello+idx+this_ii+offset_tot, min(80, param_len));
                        cname[min(80, param_len)]='\0';
                        thisdir->pup->quic_ua_string = url_encode(cname);
                    }
                    this_ii += offset_tot + param_len;
                    iterations ++;
                }

                ii += ext_len;
                break;

            default:
                ii += ext_len;
                break;
         }
     }

    return;                     
}

#endif

quic_hdr parse_quic_hdr (unsigned char *base, int data_len){

    quic_hdr hdr;
    memset(&hdr, 0, sizeof(hdr));

    if (data_len<=5)
      return hdr;

    hdr.header_form = (base[0] & ( 1 << 7 )) >> 7;
    hdr.fixed_bit = (base[0] & ( 1 << 6 )) >> 6;

    if (hdr.header_form == 1){ // Long Packet
        hdr.packet_type = (base[0] & ( 3 << 4 )) >> 4;
        hdr.reserved = (base[0] & ( 3 << 2 )) >> 2; 
        hdr.packet_nb_len = ((base[0] & ( 3 << 0 )) >> 0) + 1;
        memcpy(hdr.version, base + 1, 4);

        hdr.dcid_len = base[5];
        if (hdr.dcid_len > 20 || 5 + 1 + hdr.dcid_len >= data_len)
          return hdr;
        memcpy(hdr.dcid, base + 5 + 1, hdr.dcid_len);

        hdr.scid_len = base[5 + 1 + hdr.dcid_len];
        if (hdr.scid_len > 20 || 5 + 1 + hdr.dcid_len + 1 + hdr.scid_len >= data_len)
          return hdr;
        memcpy(hdr.scid, base + 5 + 1 + hdr.dcid_len + 1, hdr.scid_len);
        
        // Search token and len only in initial packets
        if (hdr.packet_type == 0){
            unsigned char * ptr = base + 5 + 1 + hdr.dcid_len + 1 + hdr.scid_len;
            uint8_t token_len_len = 0;
            if (ptr + 4 >= base + data_len || ptr < base)
              return hdr;
            uint64_t token_len = read_var_len_int(ptr, &token_len_len);
            hdr.token_len = token_len_len + token_len; // Include both len and token
            uint8_t pkt_len_len = 0;
            ptr += token_len_len + token_len;
            if (ptr + 4 >= base + data_len || ptr < base)
              return hdr;
            hdr.pkt_len = read_var_len_int(ptr, &pkt_len_len);
        }
    }
    else // Short Packet
      hdr.spin_bit = (base[0] & ( 1 << 5 )) >> 5;

    return hdr;
}



void check_QUIC(struct ip * pip, struct udphdr * pudp, void *plast,
                ucb *thisdir, ucb *otherdir)
{
  int payload_len;
  int data_len;
  unsigned char *base;
  int seq_nr;
  char connection_id[8];

  if (thisdir->is_QUIC==1 && otherdir->is_QUIC==1)
    return;  /* Flow already classified */

  payload_len = ntohs (pudp->uh_ulen);
  /* This is the UDP complete length, included the header size */

  base = (unsigned char *) pudp;
  data_len = (unsigned char *) plast - (unsigned char *) base + 1;

  if (data_len < 27 || payload_len == 0)
    return;  /* Minimum safe QUIC size is probably 8+19 bytes */


    /* New code for Google QUIC Version >= 46 */
  switch(thisdir->QUIC_state)
   {
    /*
      MATCHING QUIC IETF
      We only have part of the header in clear.
      We match the DCID with SCID and version across "Initial" (or "0-RTT") packets
    */
     case QUIC_UNKNOWN:
     case QUIC_OPEN_SENT:
        
        ;
        quic_hdr hdr;
        hdr = parse_quic_hdr(base + 8, data_len - 8);

        //printf("HDR: %d TYPE: %d, FX: %d, DLEN: %d, SLEN:  %d\n", hdr.header_form, hdr.packet_type, hdr.fixed_bit, hdr.dcid_len, hdr.scid_len);

        // Look for initial well-formed packets
        if ( hdr.header_form == 1 && hdr.packet_type == 0 &&
             hdr.fixed_bit == 1   &&
             hdr.dcid_len <= 20   && hdr.scid_len <= 20  ){
        
            memcpy(thisdir->QUIC_conn_id,hdr.dcid,hdr.dcid_len); // Save the connection ID
            
            // Look for Client Packets with DCID in case in state UNK
            if ( hdr.dcid_len > 0 && otherdir->QUIC_state != QUIC_OPEN_SENT){
                memcpy(thisdir->pup->quic_c_vers,hdr.version,4); // Save the version
                thisdir->QUIC_state=QUIC_OPEN_SENT; // Set is as "open", we have see an "Initial" packet
            } 
            
            // Look for Server Packets with SCID in case in state QUIC_OPEN_SENT
            else if ( hdr.scid_len > 0 && otherdir->QUIC_state == QUIC_OPEN_SENT){
                memcpy(thisdir->pup->quic_s_vers,hdr.version,4); // Save the version
                
                if ( memcmp(thisdir->pup->quic_c_vers, thisdir->pup->quic_s_vers, 4) == 0 ){
                    thisdir->QUIC_state = otherdir->QUIC_state = QUIC_DATA_SENT; // Mark the flow forever
                    thisdir->is_QUIC = otherdir->is_QUIC = 1;
                }
                
            }
           
#ifdef HAVE_OPENSSL
            search_QUIC_SNI(thisdir, base, data_len, 18 + hdr.dcid_len + hdr.scid_len + hdr.token_len, hdr );
#endif

            // Search 0-RTT
            unsigned char * ptr_next = base + 17 +
                                       hdr.dcid_len + hdr.scid_len + hdr.token_len + hdr.pkt_len;
            if (ptr_next + 5 < base + data_len ){
                quic_hdr hdr_second = parse_quic_hdr(ptr_next, 5);
                if (hdr_second.packet_type == 1)
                    thisdir->pup->quic_zero_rtt=1;
            }    
                    
        }              
                  
        // Look for inflight 0-rtt
        else if ( thisdir->QUIC_state == QUIC_OPEN_SENT &&
                  hdr.header_form == 1 && hdr.packet_type == 1 &&
                  hdr.dcid_len > 0     && hdr.fixed_bit == 1   &&
                  hdr.dcid_len <= 20   && hdr.scid_len <= 20  )
            thisdir->pup->quic_zero_rtt=1;
        

       break;
     default:
       break;
   
  }
   
  if (thisdir->is_QUIC==1 && otherdir->is_QUIC==1)
   {
     if (thisdir->type==UDP_UNKNOWN ||
    	 thisdir->type==FIRST_RTP_PLUS || 
    	 thisdir->type==FIRST_RTP || 
    	 thisdir->type==FIRST_RTCP)
      { thisdir->type=UDP_QUIC; }
     else
      { 
        // fprintf(fp_stderr, "QUIC type overriding %d\n",thisdir->type);
    	thisdir->type=UDP_QUIC; 
      }

     if (otherdir->type==UDP_UNKNOWN ||
    	 otherdir->type==FIRST_RTP_PLUS || 
    	 otherdir->type==FIRST_RTP || 
    	 otherdir->type==FIRST_RTCP)
      { otherdir->type=UDP_QUIC; }
     else
      { 
        // fprintf(fp_stderr, "QUIC type overriding %d\n",otherdir->type);
    	otherdir->type=UDP_QUIC; 
      }
   }
  return;
}

void check_udp_vod(struct ip * pip, struct udphdr * pudp, void *plast,
                ucb *thisdir, ucb *otherdir)
{
  int payload_len;
  int data_len;
  unsigned char *base;

  if (thisdir->is_VOD==1 && otherdir->is_VOD==1)
    return;  /* Flow already classified */

  payload_len = ntohs (pudp->uh_ulen);
  /* This is the UDP complete length, included the header size */

  base = (unsigned char *) pudp;
  data_len = (unsigned char *) plast - (unsigned char *) base + 1;

  if (data_len < 9 || payload_len == 0)
   {
     thisdir->first_VOD=TRUE;
     return;  /* Minimum VOD size is 8+188 bytes */
   }
  
  /* According to the MPEG2 over IP information, we should always have
    7 PES (i.e. 188*7 bytes) */

  if (payload_len!=1324)
   {
     thisdir->first_VOD=TRUE;
     return;  /* Minimum VOD size is 8+188 bytes */
   }
    
  /* Check if we have at least two PES */
  
  if (data_len>196)
   {
     if (base[8]==0x47 && base[196]==0x47)
      {
        thisdir->is_VOD=1;
        otherdir->is_VOD=1;
        thisdir->first_VOD=FALSE;
        thisdir->type=UDP_VOD;
        otherdir->type=UDP_VOD;
        return;
      }
   }
  else  /* Only one PES, check the first byte (and the size 1324) */
   {
     if (base[8]==0x47)
      {
        thisdir->is_VOD=1;
        otherdir->is_VOD=1;
        thisdir->first_VOD=FALSE;
        thisdir->type=UDP_VOD;
        otherdir->type=UDP_VOD;
        return;
      }
   }
  
  /* Scrambled PES - Signature byte differs among flows, but is the same
     for all the frames in each flow. Match at least 3 packets */

  if (thisdir->first_VOD==TRUE)
   {
     thisdir->first_VOD=FALSE;
     thisdir->VOD_scrambled_sig[0]=base[8];
     if (data_len>196) 
       { thisdir->VOD_scrambled_sig[1]=base[196];}
     else
       { thisdir->VOD_scrambled_sig[1]=-1;}
     thisdir->VOD_count=1;
   }  
  else
   {
     if (data_len>196)
      {
        if (thisdir->VOD_scrambled_sig[0]==base[8] &&
            thisdir->VOD_scrambled_sig[1]==base[196] )
         {
            thisdir->VOD_count++;
        
   	    if (thisdir->VOD_count==3)
	     {
      	       thisdir->is_VOD=1;
      	       otherdir->is_VOD=1;
      	       thisdir->type=UDP_VOD;
      	       otherdir->type=UDP_VOD;
      	       return;
	     }
      	  }
     	 else
     	  {
     	    thisdir->first_VOD=TRUE;
     	  }
      }
     else
      {
        if (thisdir->VOD_scrambled_sig[0]==base[8] )
         {
            thisdir->VOD_count++;
        
   	    if (thisdir->VOD_count==3)
	     {
      	       thisdir->is_VOD=1;
      	       otherdir->is_VOD=1;
      	       thisdir->type=UDP_VOD;
      	       otherdir->type=UDP_VOD;
      	       return;
	     }
      	  }
     	 else
     	  {
     	    thisdir->first_VOD=TRUE;
     	  }
      }
   }  
  return;
}

void
udp_header_stat (struct udphdr * pudp, struct ip * pip, void *plast)
{
  int ip_len = gethdrlength (pip, plast) + getpayloadlength (pip, plast);

  if (internal_src && !internal_dst)
    {
      L4_bitrate.out[UDP_TYPE] += ip_len;
      L3_bitrate.out[PIP_ISV6(pip)?L3_IPv6_UDP:L3_IPv4_UDP] += ip_len;
      add_histo (udp_port_dst_out, (float) ntohs(pudp->uh_dport));
      if (cloud_dst)
       {
         L4_bitrate.c_out[UDP_TYPE] += ip_len;
       }
      else
       {
         L4_bitrate.nc_out[UDP_TYPE] += ip_len;
       }
    }
  else if (!internal_src && internal_dst)
    {
      L4_bitrate.in[UDP_TYPE] += ip_len;
      L3_bitrate.in[PIP_ISV6(pip)?L3_IPv6_UDP:L3_IPv4_UDP] += ip_len;
      add_histo (udp_port_dst_in, (float) ntohs(pudp->uh_dport));
      if (cloud_src)
       {
         L4_bitrate.c_in[UDP_TYPE] += ip_len;
       }
      else
       {
         L4_bitrate.nc_in[UDP_TYPE] += ip_len;
       }
    }
#ifndef LOG_UNKNOWN
  else if (internal_src && internal_dst)
#else
  else
#endif
    {
      L4_bitrate.loc[UDP_TYPE] += ip_len;
      L3_bitrate.loc[PIP_ISV6(pip)?L3_IPv6_UDP:L3_IPv4_UDP] += ip_len;
      add_histo (udp_port_dst_loc, (float) ntohs(pudp->uh_dport));
    }

  return;
}

int
udp_flow_stat (struct ip * pip, struct udphdr * pudp, void *plast)
{

  udp_pair *pup_save;
  ucb *thisdir;
  ucb *otherdir;
  udp_pair tp_in;
  int dir;
  u_short uh_sport;		/* source port */
  u_short uh_dport;		/* destination port */
  u_short uh_ulen;		/* data length */
  int ip_len;

  /* make sure we have enough of the packet */
  if ((unsigned long) pudp + sizeof (struct udphdr) - 1 >
      (unsigned long) plast)
    {
      if (warn_printtrunc)
	fprintf (fp_stderr,
		 "UDP packet %lu truncated too short to trace, ignored\n",
		 pnum);
      ++ctrunc;
      return (FLOW_STAT_SHORT);
    }


  /* convert interesting fields to local byte order */
  uh_sport = ntohs (pudp->uh_sport);
  uh_dport = ntohs (pudp->uh_dport);
  uh_ulen = ntohs (pudp->uh_ulen);
  ip_len = gethdrlength (pip, plast) + getpayloadlength (pip, plast);

  /* stop at this level of analysis */
  ++udp_trace_count;

  /* make sure this is one of the connections we want */
  pup_save = FindUTP (pip, pudp, &dir);

  ++packet_count;

  /*MT/MMM: log periodic - Do this before updating counters*/
#ifdef LOG_PERIODIC
  if ( elapsed(pup_save->last_print_time, current_time) > GLOBALS.Log_Periodic_Interval) 
    {
      print_udp_periodic_log(pup_save);
   }
#endif // LOG_PERIODIC
   
  if (pup_save == NULL)
    {
      return (FLOW_STAT_NULL);
    }

  /* do time stats */
  if (ZERO_TIME (&pup_save->first_time))
    {
      pup_save->first_time = current_time;

    }
  pup_save->last_time = current_time;

  /* grab the address from this packet */
  CopyAddr (&tp_in.addr_pair, pip, uh_sport, uh_dport);

  /* figure out which direction this packet is going */
  if (dir == C2S)
    {
      thisdir = &pup_save->c2s;
      otherdir = &pup_save->s2c;
    }
  else
    {
      thisdir = &pup_save->s2c;
      otherdir = &pup_save->c2s;
    }

#ifdef CHECK_UDP_DUP
  /* check if this is a dupe udp */
  if (dup_udp_check (pip, pudp,thisdir)) {
    return (FLOW_STAT_DUP);
  }
#endif

  if ((thisdir->last_pkt_time.tv_sec) == -1)	/* is the first time I see this flow */
    {
      /* destination port of the flow */
      add_histo (udp_port_flow_dst, (float) (ntohs (pudp->uh_dport)));
      /* flow starting time */
      thisdir->first_pkt_time = current_time;
    }
  thisdir->last_pkt_time = current_time;

  /* do data stats */
  thisdir->data_bytes += uh_ulen - 8;	/* remove the UDP header */

#ifdef PACKET_STATS
 {
  int udp_data_length;
  
      udp_data_length = (uh_ulen -8);
      thisdir->data_pkts_sum2 += udp_data_length*udp_data_length; 
      
      { double current_intertime;
      if (thisdir->seg_count==0)
       {
         thisdir->last_seg_time=time2double(current_time);
       }
      else
       {
         current_intertime = 
	      time2double(current_time) - thisdir->last_seg_time;
         thisdir->last_seg_time=time2double(current_time);
	 thisdir->seg_intertime_sum += current_intertime;
	 thisdir->seg_intertime_sum2 += current_intertime*current_intertime;
       }

      if (thisdir->seg_count<MAX_COUNT_SEGMENTS)
       {
         thisdir->seg_size[thisdir->seg_count] = udp_data_length;
	 if (thisdir->seg_count>0)
	  {
	    thisdir->seg_intertime[thisdir->seg_count-1] = current_intertime;
	  }
       }

	 thisdir->seg_count++;
      }
 }
#endif


  /* total packets stats */
  ++pup_save->packets;
  ++thisdir->packets;

  if (PIP_ISV4(pip))
   {
   /*TOPIX*/
    /*TTL stats */
     if ((thisdir->ttl_min == 0) || (thisdir->ttl_min > (int) pip->ip_ttl))
       thisdir->ttl_min = (int) pip->ip_ttl;
     if (thisdir->ttl_max < (int) pip->ip_ttl)
       thisdir->ttl_max = (int) pip->ip_ttl;
     thisdir->ttl_tot += (u_llong) pip->ip_ttl;
   }
  else
   {
   /*TOPIX*/
    /*TTL stats */
     if ((thisdir->ttl_min == 0) || (thisdir->ttl_min > (int) PIP_V6(pip)->ip6_hlimit))
       thisdir->ttl_min = (int) PIP_V6(pip)->ip6_hlimit;
     if (thisdir->ttl_max < (int) PIP_V6(pip)->ip6_hlimit)
       thisdir->ttl_max = (int) PIP_V6(pip)->ip6_hlimit;
     thisdir->ttl_tot += (u_llong) PIP_V6(pip)->ip6_hlimit;
   }
   /*TOPIX*/
    //
    // NOW, this should be called by proto_analyzer...
    //
    //   p_rtp = getrtp (pudp, plast);
    //   if ((p_rtp) != NULL)
    //       rtpdotrace (thisdir, p_rtp, dir, pip);
    // 
    // 

    //fprintf(stderr, "BEFORE: %f\n", time2double(thisdir->skype->win.start));
    proto_analyzer (pip, pudp, PROTOCOL_UDP, thisdir, dir, plast);
    //fprintf(stderr, "AFTER: %f\n\n", time2double(thisdir->skype->win.start));

    //if (thisdir != NULL && thisdir->pup != NULL)
    make_udpL7_rate_stats(thisdir, ip_len);

  return (FLOW_STAT_OK);
}

void
behavioral_flow_wrap (struct ip *pip, void *pproto, int tproto, void *pdir,
	       int dir, void *hdr, void *plast)
{
  if (tproto == PROTOCOL_UDP)
    {
	ucb *thisdir;
	ucb *otherdir;
	udphdr *pudp = (udphdr *)hdr;
	udp_pair *pup_save = ((ucb *)pdir)->pup;
	u_short uh_ulen = ntohs (pudp->uh_ulen);		/* data length */
	
	/* figure out which direction this packet is going */
	if (dir == C2S)
	 {
	   thisdir = &pup_save->c2s;
	   otherdir = &pup_save->s2c;
	 }
	else
	 {
	   thisdir = &pup_save->s2c;
	   otherdir = &pup_save->c2s;
	 }
	
	/* DUMP for QUIC exploration. To be removed
	if (ntohs(pudp->uh_sport)==443 ||  ntohs(pudp->uh_dport)==443)
	 {
	   int iidx;
	   unsigned char *ibase;
	   ibase = (unsigned char *)pudp;
	   printf("=Q= ");
	   for (iidx=8; iidx<min(8+32,uh_ulen);iidx++)
	    {
	      printf("%02x ",ibase[iidx]);
	    }
	   printf("\n");
	   printf("=q= ");
	   for (iidx=8; iidx<min(8+32,uh_ulen);iidx++)
	    {
	      printf(" %c ",isprint(ibase[iidx])?ibase[iidx]:'.');
	    }
	   printf("\n");
	   printf("\n");
	 }
	 */
	 
	if (pup_save->packets<MAX_UDP_UTP)
	  check_uTP(pip, pudp,plast,thisdir,otherdir);
	
	if (pup_save->packets<MAX_UDP_QUIC)
	  check_QUIC(pip, pudp,plast,thisdir,otherdir);

	if (pup_save->packets<MAX_UDP_VOD)
	  check_udp_vod(pip, pudp,plast,thisdir,otherdir);
	
	if (pup_save->packets<MAX_UDP_OBFUSCATE)
	  check_udp_obfuscate(thisdir,otherdir,uh_ulen);
    }
  else
    {
	tcb *thisdir;
	tcphdr *ptcp = (tcphdr *) hdr;
	tcp_pair *ptp_save = ((tcb *) pdir)->ptp;
	
	if (ptp_save == NULL)
	  return;
	
	/* figure out which direction this packet is going */
	if (dir == C2S)
 	 {
	   thisdir = &ptp_save->c2s;
	 }
	else
	 {
	   thisdir = &ptp_save->s2c;
	 }
	
	/* Message size evaluation used for MSE detection might be incomplete 
	 if the last FIN segment is not considered */
	if (FIN_SET(ptcp) && thisdir != NULL && thisdir->ptp != NULL && 
	    thisdir->ptp->con_type == UNKNOWN_PROTOCOL)
	   mse_protocol_check(thisdir->ptp);
	
    }

}


void
udptrace_init (void)
{
  static Bool initted = FALSE;
  extern udp_pair **pup_hashtable;

  if (initted)
    return;

  initted = TRUE;

  /* initialize the hash table */

  pup_hashtable = (udp_pair **) MallocZ (GLOBALS.Hash_Table_Size * sizeof (udp_pair *));

  /* create an array to hold any pairs that we might create */
  utp = (udp_pair **) MallocZ (GLOBALS.Max_UDP_Pairs * sizeof (udp_pair *));
}

void
udptrace_done (void)
{
    udp_pair *pup;
    int ix;
    int dir = -1;

    for (ix = 0; ix < GLOBALS.Max_UDP_Pairs; ix++) {
        pup = utp[ix];
        // check if the flow has been already closed
        if (pup == NULL)
            continue;
        /* consider this udp connection */
            close_udp_flow(pup, ix, dir);
/*
        if (!con_cat) {
            //flush histos and call the garbage colletor
            //Note: close_udp_flow() calls make_udp_conn_stats()
            close_udp_flow(pup, ix, dir);
        }
        else
            //only flush histos
            make_udp_conn_stats (pup, TRUE);
*/
    }
}

void
make_udp_conn_stats (udp_pair * pup_save, Bool complete)
{
  double etime;

  if (complete)
    {
      if (pup_save->internal_src && !pup_save->internal_dst)
	{
	  add_histo (udp_cl_b_s_out, pup_save->c2s.data_bytes);
	  add_histo (udp_cl_b_s_in, pup_save->s2c.data_bytes);
	  add_histo (udp_cl_b_l_out, pup_save->c2s.data_bytes);
	  add_histo (udp_cl_b_l_in, pup_save->s2c.data_bytes);

	  add_histo (udp_cl_p_out, pup_save->c2s.packets);
	  add_histo (udp_cl_p_in, pup_save->s2c.packets);
	}
      else if (!pup_save->internal_src && pup_save->internal_dst)
	{
	  add_histo (udp_cl_b_s_out, pup_save->s2c.data_bytes);
	  add_histo (udp_cl_b_s_in, pup_save->c2s.data_bytes);
	  add_histo (udp_cl_b_l_out, pup_save->s2c.data_bytes);
	  add_histo (udp_cl_b_l_in, pup_save->c2s.data_bytes);

	  add_histo (udp_cl_p_out, pup_save->s2c.packets);
	  add_histo (udp_cl_p_in, pup_save->c2s.packets);
	}
      else if (pup_save->internal_src && pup_save->internal_dst)
	{
	  add_histo (udp_cl_b_s_loc, pup_save->s2c.data_bytes);
	  add_histo (udp_cl_b_s_loc, pup_save->c2s.data_bytes);
	  add_histo (udp_cl_b_l_loc, pup_save->s2c.data_bytes);
	  add_histo (udp_cl_b_l_loc, pup_save->c2s.data_bytes);

	  add_histo (udp_cl_p_loc, pup_save->s2c.packets);
	  add_histo (udp_cl_p_loc, pup_save->c2s.packets);

	}
      else
	{
	  if (warn_IN_OUT)
	    {
	      fprintf (fp_stderr, 
            "\nWARN: This udp flow is neither incoming nor outgoing: src - %s;",
		    HostName (pup_save->addr_pair.a_address));
	      fprintf (fp_stderr, " dst - %s!\n",
		      HostName (pup_save->addr_pair.b_address));
	      warn_IN_OUT = FALSE;
	    }
#ifndef LOG_UNKNOWN
	  return;
#else
/* fool the internal and external definition... */
	  add_histo (udp_cl_b_s_loc, pup_save->s2c.data_bytes);
	  add_histo (udp_cl_b_s_loc, pup_save->c2s.data_bytes);
	  add_histo (udp_cl_b_l_loc, pup_save->s2c.data_bytes);
	  add_histo (udp_cl_b_l_loc, pup_save->c2s.data_bytes);

	  add_histo (udp_cl_p_loc, pup_save->s2c.packets);
	  add_histo (udp_cl_p_loc, pup_save->c2s.packets);
#endif
	}
    }
    
#ifdef LOG_PERIODIC
  print_udp_periodic_log(pup_save);
#endif //LOG_PERIODIC
  
  /* Statistics using plugins */

  make_proto_stat (pup_save, PROTOCOL_UDP);

  /* connection time */
  /* from microseconds to ms */
  etime = elapsed (pup_save->first_time, pup_save->last_time);
  etime = etime / 1000;
  add_histo (udp_tot_time, etime);
}



void
close_udp_flow (udp_pair * pup, int ix, int dir)
{

  extern udp_pair **pup_hashtable;
  udp_pair **ppuph_head = NULL;
  udp_pair *puph_tmp, *puph, *puph_prev;
  unsigned int cleaned = 0;
  hash hval;
  int j;
  int tmp;

  /* must be cleaned */
  cleaned++;

  /* Consider this flow for statistic collections */
  make_udp_conn_stats (pup, TRUE);
  if (profile_flows->flag == HISTO_ON)
     AVE_departure(current_time, &active_flows_win_UDP);
  tot_conn_UDP--;

  /* free up hash element->.. */
  hval = pup->addr_pair.hash % GLOBALS.Hash_Table_Size;

  ppuph_head = &pup_hashtable[hval];
  j = 0;
  puph_prev = *ppuph_head;
  for (puph = *ppuph_head; puph; puph = puph->next)
    {
      j++;
      if (SameConn (&pup->addr_pair, &puph->addr_pair, &tmp))
	{
	  puph_tmp = puph;
	  if (j == 1)
	    {
	      /* it is the top of the list */
	      pup_hashtable[hval] = puph->next;
	    }
	  else
	    {
	      /* it is in the middle of the list */
	      puph_prev->next = puph->next;
	    }
	  utp_release (puph_tmp);
	  break;
	}
      puph_prev = puph;
    }

  if (ix == -1)			/* I should look for the correct ix value */
    {
      for (ix = 0; ix < GLOBALS.Max_UDP_Pairs; ++ix)
	{
	  //      pup = utp[ix];

	  if (utp[ix] == NULL)
	    continue;

	  if (SameConn (&pup->addr_pair, &utp[ix]->addr_pair, &tmp))
	    {
	      break;
	    }
	}
    }

  utp[ix] = NULL;

}

/* 
** Code to URLencode (percent-encode) a string. 
** Public domain code from http://www.geekhideout.com/urlcode.shtml
*/

/* Converts a hex character to its integer value */
char from_hex(char ch) 
{
  return isdigit(ch) ? ch - '0' : tolower(ch) - 'a' + 10;
}

/* Converts an integer value to its hex character*/
char to_hex(char code) 
{
  static char hex[] = "0123456789abcdef";
  return hex[code & 15];
}

/* Returns a url-encoded version of str */
/* IMPORTANT: be sure to free() the returned string after use */
char *url_encode(char *str)
{
  char *pstr = str, *buf = malloc(strlen(str) * 3 + 1), *pbuf = buf;
  while (*pstr)
   {
     if (isalnum(*pstr) || *pstr == '-' || *pstr == '_' || *pstr == '.' || *pstr == '~') 
       *pbuf++ = *pstr;
     else if (*pstr == ' ') 
       *pbuf++ = '+';
     else 
       *pbuf++ = '%', *pbuf++ = to_hex(*pstr >> 4), *pbuf++ = to_hex(*pstr & 15);
     pstr++;
   }
  *pbuf = '\0';
  return buf;
}

/* Returns a url-decoded version of str */
/* IMPORTANT: be sure to free() the returned string after use */
char *url_decode(char *str)
{
  char *pstr = str, *buf = malloc(strlen(str) + 1), *pbuf = buf;
  while (*pstr)
   {
     if (*pstr == '%')
      {
        if (pstr[1] && pstr[2])
	 {
           *pbuf++ = from_hex(pstr[1]) << 4 | from_hex(pstr[2]);
           pstr += 2;
         }
      }
     else if (*pstr == '+')
      { 
       *pbuf++ = ' ';
      }
     else
      {
       *pbuf++ = *pstr;
      }
     pstr++;
   }
  *pbuf = '\0';
  return buf;
}

#ifdef LOG_PERIODIC
void print_udp_periodic_log(udp_pair * pup_save) {
  ucb *thisUdir,*thisC2S,*thisS2C;
  udp_pair *pup;
  
  thisC2S = &(pup_save->c2s);
  thisS2C = &(pup_save->s2c);

  if (!fp_periodic_udp_logc)
    return;

  thisUdir = thisC2S;
  pup = thisUdir->pup;

  //     #   Field Meaning
  //    --------------------------------------
  //     1   Source Address
  //     2   Source Port

  if (pup->crypto_src==FALSE)
     wfprintf (fp_periodic_udp_logc, "%s %s",
	       HostName (pup->addr_pair.a_address),
	       ServiceName (pup->addr_pair.a_port));
  else 
     wfprintf (fp_periodic_udp_logc, "%s %s",
	       HostNameEncrypted (pup->addr_pair.a_address),
	       ServiceName (pup->addr_pair.a_port));
	       
/*
  //     3   Flow Start Time
  //     4   Flow Elapsed Time [s]
  //     5   Flow Size [Bytes]
  wfprintf (fp_periodic_udp_logc,
	   " %f %.6f %llu",
	   time2double ((thisUdir->first_pkt_time))/1000., 
//         elapsed (first_packet,thisUdir->first_pkt_time)/1000,
	   elapsed (thisUdir->first_pkt_time, thisUdir->last_pkt_time) /
	   1000.0 / 1000.0, thisUdir->data_bytes);

  //     6   No. of Total flow packets
  wfprintf (fp_periodic_udp_logc, " %lld", thisUdir->packets);
*/
  // 7 internal address
  // 8 udp_type

  wfprintf (fp_periodic_udp_logc, " %d %d",
	   pup_save->internal_src, pup_save->crypto_src);

  thisUdir = thisS2C;
  pup = thisUdir->pup;

  //     #   Field Meaning
  //    --------------------------------------
  //     9   Source Address
  //     10   Source Port

  if (pup->crypto_dst==FALSE)
     wfprintf (fp_periodic_udp_logc, " %s %s",
	       HostName (pup->addr_pair.b_address),
	       ServiceName (pup->addr_pair.b_port));
  else
     wfprintf (fp_periodic_udp_logc, " %s %s",
	       HostNameEncrypted (pup->addr_pair.b_address),
	       ServiceName (pup->addr_pair.b_port));
/*
  //     11   Flow Start Time
  //     12   Flow Elapsed Time [s]
  //     13   Flow Size [Bytes]
  wfprintf (fp_periodic_udp_logc,
	   " %f %.6f %llu",
	   time2double ((thisUdir->first_pkt_time))/1000., 
//         elapsed (first_packet,thisUdir->first_pkt_time)/1000,
	   elapsed (thisUdir->first_pkt_time, thisUdir->last_pkt_time) /
	   1000.0 / 1000.0, thisUdir->data_bytes);

  //     14   No. of Total flow packets
  wfprintf (fp_periodic_udp_logc, " %lld", thisUdir->packets);
*/
  // 15 internal address
  // 16 udp_type

  wfprintf (fp_periodic_udp_logc, " %d %d",
	   pup_save->internal_dst, pup_save->crypto_dst);

    /* TIME */

    wfprintf (fp_periodic_udp_logc, " %f %f %f %f",
              time2double(pup_save->last_print_time)/1000.0,
              elapsed(pup_save->first_time, pup_save->last_print_time)/1000.0,
              elapsed(pup_save->first_time, pup_save->last_time)/1000.0,
              elapsed(pup_save->last_print_time, pup_save->last_time)/1000.0
             );

    /* Packets and bytes*/

    wfprintf (fp_periodic_udp_logc,
              " %lu %lu",
              pup_save->c2s.packets - pup_save->last_print_c2s.packets,
              pup_save->c2s.data_bytes - pup_save->last_print_c2s.data_bytes);

    wfprintf (fp_periodic_udp_logc,
              " %lu %lu",
              pup_save->s2c.packets - pup_save->last_print_s2c.packets,
              pup_save->s2c.data_bytes - pup_save->last_print_s2c.data_bytes);
  
  
  wfprintf (fp_periodic_udp_logc, "\n");

  /*update counters*/
  pup_save->last_print_time = current_time; //ptp_save->last_time;
  pup_save->last_print_c2s = pup_save->c2s;
  pup_save->last_print_s2c = pup_save->s2c;
  
  return;
 
}

#endif //LOG_PERIODIC



