#include "mospf_daemon.h"
#include "mospf_proto.h"
#include "mospf_nbr.h"
#include "mospf_database.h"

#include "ip.h"

#include "list.h"
#include "log.h"

#include "rtable.h"							// should separate this "include" and all related codes to another source file 

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>

#define MOSPF_DB_ENTRY_TIMER 40
#define MAX_GRAPH_NODE 10

#define DEBUG
//#define DEBUG_WTFIGO						// print what is going on
//#define DEBUG_ETH_TYPE
//#define DEBUG_CHECK_NBR
//#define DEBUG_PRINT_NBR
//#define DEBUG_SEND_LSU
#define DEBUG_PRINT_MOSPF_DB
//#define DEBUG_PRINT_MOSPF_LSU_RECV
//#define DEBUG_PRINT_MOSPF_LSU_SEND
//#define DEBUG_MOSPF_LSU_SEND
//#define DEBUG_FORWARD_LSU
//#define DEBUG_PRINT_MOSPF_DB_WHEN_HANDLE
//#define DEBUG_PRINT_MOSPF_DB_WHEN_TIMING

extern ustack_t *instance;

pthread_mutex_t mospf_lock, mospfDbLock;

struct db_entry_timer
{
	struct list_head list;
	int timer;
};

struct list_head dbTimerHead;

int nbrChanged = 0;							// Send LSU Message when neighboor list changes; [not] Protected by mospf_lock

#ifdef DEBUG_PRINT_NBR
void FprintIfaceNbrList(iface_info_t *iface)
{
	mospf_nbr_t *nbrEntry, *nbrNextEntry;
	fprintf(stdout, "\n------------------\niface: 0x%08x\n------------------\nid\tip\tmask\talive\t\n------------------\n", iface->ip);
	list_for_each_entry_safe(nbrEntry, nbrNextEntry, &iface->nbr_list, list)
	{
		fprintf(stdout, "0x%08x\t0x%08x\t0x%08x\t%d\t\n", nbrEntry->nbr_id, nbrEntry->nbr_ip, nbrEntry->nbr_mask, nbrEntry->alive);
	}
	fprintf(stdout, "------------------\n\n");
}
#endif

#ifdef DEBUG_PRINT_MOSPF_DB
void FprintMospfDB()
{
	mospf_db_entry_t *entry, *nextEntry;
	struct db_entry_timer *timer = list_entry(dbTimerHead.next, struct db_entry_timer, list);
	fprintf(stdout, "\nMospf DB\nrid\tsubnet\tmask\tnbr\n-------------------------------------\n");
	list_for_each_entry_safe(entry, nextEntry, &mospf_db, list)
	{		
		for (int i = 0; i < entry->nadv; i++)
		{
			fprintf(stdout, "0x%08x\t", entry->rid);
			//fprintf(stdout, "seq: %d\t", entry->seq);
			//fprintf(stdout, "nadv: %d\t", entry->nadv);
			//fprintf(stdout, "timer: %d\t", timer->timer);
			fprintf(stdout, "0x%08x\t0x%08x\t0x%08x\n", ntohl(entry->array[i].subnet), ntohl(entry->array[i].mask), ntohl(entry->array[i].rid));
		}
		timer = list_entry(timer->list.next, struct db_entry_timer, list);
	}
	fprintf(stdout, "------------------------------------\n");
}
#endif

#ifdef DEBUG_PRINT_MOSPF_LSU_RECV
void FprintMospfLsuRecv(struct mospf_hdr *mospfHdr)
{
	struct mospf_lsu * mospfLsu = (struct mospf_lsu *)((char *)mospfHdr + MOSPF_HDR_SIZE);
	struct mospf_lsa *mospfFirstLsa = (struct mospf_lsa *)((char *)mospfLsu + MOSPF_LSU_SIZE);
	int nadv = ntohl(mospfLsu->nadv);
	fprintf(stdout, "------Recv LSU: 0x%08x, seq: %d-------\n", ntohl(mospfHdr->rid), ntohs(mospfLsu->seq));
	for (int i = 0; i < nadv; i++)
	{
		fprintf(stdout, "rid = 0x%08x\tmask = 0x%08x\n", ntohl(mospfFirstLsa[i].rid), ntohl(mospfFirstLsa[i].mask));
	}
	fprintf(stdout, "-----------------------------\n");
}
#endif

#ifdef DEBUG_PRINT_MOSPF_LSU_SEND
void FprintMospfLsuSend(struct mospf_lsa *mospfFirstLsa, int nadv)
{
	fprintf(stdout, "------Send LSU: 0x%08x-------\n", instance->router_id);
	for (int i = 0; i < nadv; i++)
	{
		fprintf(stdout, "rid = 0x%08x\tmask = 0x%08x\n", ntohl(mospfFirstLsa[i].rid), ntohl(mospfFirstLsa[i].mask));
	}
	fprintf(stdout, "-----------------------------\n");
}
#endif

void mospf_init()
{
	pthread_mutex_init(&mospf_lock, NULL);

	instance->area_id = 0;
	// get the ip address of the first interface
	iface_info_t *iface = list_entry(instance->iface_list.next, iface_info_t, list);
	instance->router_id = iface->ip;
	instance->sequence_num = 0;
	instance->lsuint = MOSPF_DEFAULT_LSUINT;

	iface = NULL;
	list_for_each_entry(iface, &instance->iface_list, list) {
		iface->helloint = MOSPF_DEFAULT_HELLOINT;
		init_list_head(&iface->nbr_list);
	}

	init_mospf_db();
	init_list_head(&dbTimerHead);
}

void *sending_mospf_hello_thread(void *param);
void *sending_mospf_lsu_thread(void *param);
void *checking_nbr_thread(void *param);
void *checking_db_timer_thread(void *param);				// update db timer
void *update_rtable_thread(void *param);

void mospf_run()
{
	pthread_t hello, lsu, nbr, db, rtable;

	pthread_create(&hello, NULL, sending_mospf_hello_thread, NULL);
	pthread_create(&lsu, NULL, sending_mospf_lsu_thread, NULL);
	pthread_create(&nbr, NULL, checking_nbr_thread, NULL);
	pthread_create(&db, NULL, checking_db_timer_thread, NULL);
	pthread_create(&rtable, NULL, update_rtable_thread, NULL);
}

void *sending_mospf_hello_thread(void *param)
{
	while (1)
	{
		#ifdef DEBUG_WTFIGO
		fprintf(stdout, "Seems Working Now: send mOSPF Hello message periodically.\n");
		#endif
		iface_info_t *iface = list_entry(instance->iface_list.next, iface_info_t, list);
		#ifdef DEBUG_CHECK_NBR
		sleep(20);
		#else
		sleep(iface->helloint);
		#endif
		list_for_each_entry(iface, &instance->iface_list, list)
		{
			char *packet = (char *)malloc(ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE + MOSPF_HELLO_SIZE);
			struct ether_header *ethHdr = (struct ether_header *)packet;
			struct iphdr *ipHdr = (struct iphdr *)(packet + ETHER_HDR_SIZE);
			struct mospf_hdr *mospfHdr = (struct mospf_hdr *)(packet + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE);
			struct mospf_hello *mospfHello = (struct mospf_hello *)(packet + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE);
			//mospfHello->mask = iface->mask;
			//mospfHello->helloint = iface->helloint;
			//mospfHello->padding = 0;
			mospf_init_hello(mospfHello, iface->mask);
			mospf_init_hdr(mospfHdr, MOSPF_TYPE_HELLO, MOSPF_HDR_SIZE + MOSPF_HELLO_SIZE, instance->router_id, instance->area_id);
			mospfHdr->checksum = mospf_checksum(mospfHdr);
			// ipHdr->ihl = IP_BASE_HDR_SIZE / 4;
			// ipHdr->version = 4;
			// ipHdr->tos = 0;
			// ipHdr->tot_len = htons(ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE + MOSPF_HELLO_SIZE);
			// ipHdr->id = htons(0);
			// ipHdr->frag_off = htons(0);
			// ipHdr->ttl = MOSPF_MAX_LSU_TTL;
			// ipHdr->protocol = IPPROTO_MOSPF;
			// ipHdr->saddr = htonl(iface->ip);
			// ipHdr->daddr = htonl(MOSPF_ALLSPFRouters);
			// ipHdr->checksum = htons(ip_checksum(ipHdr));
			ip_init_hdr(ipHdr, iface->ip, MOSPF_ALLSPFRouters, (IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE + MOSPF_HELLO_SIZE), IPPROTO_MOSPF);
			ipHdr->checksum = ip_checksum(ipHdr);
			//ethHdr->ether_dhost = {0x01, 0x00, 0x5E, 0x00, 0x00, 0x05};
			ethHdr->ether_dhost[0] = 0x01;
			ethHdr->ether_dhost[1] = 0x00;
			ethHdr->ether_dhost[2] = 0x5E;
			ethHdr->ether_dhost[3] = 0x00;
			ethHdr->ether_dhost[4] = 0x00;
			ethHdr->ether_dhost[5] = 0x05;
			//ethHdr->ether_shost = iface->mac;
			for (int i = 0; i < ETH_ALEN; i++)
				ethHdr->ether_shost[i] = iface->mac[i];
			ethHdr->ether_type = htons(ETH_P_IP);
			#ifdef DEBUG_ETH_TYPE
			fprintf(stdout, "ethHdr->ether_type = 0x%04hx\n", ethHdr->ether_type);
			#endif
			//ip_send_packet(packet, ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE + MOSPF_HELLO_SIZE);
			iface_send_packet(iface, packet, ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE + MOSPF_HELLO_SIZE);
			//free(packet);						// cause double free exception
		}
	}	

	return NULL;
}

void *checking_nbr_thread(void *param)
{
	while (1)
	{
		#ifdef DEBUG_WTFIGO
		fprintf(stdout, "Seems Working Now: neighbor list timeout operation.\n");
		#endif
		sleep(1);
		pthread_mutex_lock(&mospf_lock);

		iface_info_t *iface;
		list_for_each_entry(iface, &instance->iface_list, list)
		{
			int nbrCount = 0;
			mospf_nbr_t *nbrEntry = NULL;
			list_for_each_entry(nbrEntry, &iface->nbr_list, list)
			{
				if((nbrEntry->alive - 1) > 0)
				{
					nbrEntry->alive = nbrEntry->alive - 1;
					nbrCount++;
				}
				else
				{
					// timeout: delete entry from neighboor list
					mospf_nbr_t *entryToBeDeleted = nbrEntry;
					list_delete_entry(&nbrEntry->list);
					nbrEntry = list_entry(entryToBeDeleted->list.prev, mospf_nbr_t, list);
					free(entryToBeDeleted);
					nbrChanged = 1;
				}
				
				#ifdef DEBUG_PRINT_NBR
				FprintIfaceNbrList(iface);
				#endif
			}
			iface->num_nbr = nbrCount;
			#ifdef DEBUG_PRINT_NBR
			fprintf(stdout, "checking nbr thread: iface 0x%08x num_nbr = %d\n", iface->ip, iface->num_nbr);
			#endif
		}

		pthread_mutex_unlock(&mospf_lock);
	}
}

void handle_mospf_hello(iface_info_t *iface, const char *packet, int len)
{
	#ifdef DEBUG_WTFIGO
	fprintf(stdout, "Seems Working Now: handle mOSPF Hello message.\n");
	#endif
	struct iphdr *ipHdr = packet_to_ip_hdr(packet);
	struct mospf_hdr *mospfHdr = (struct mospf_hdr *)IP_DATA(ipHdr);
	struct mospf_hello *mospfHello = (struct mospf_hello *)((char *)mospfHdr + MOSPF_HDR_SIZE);
	
	if (mospfHdr->checksum != mospf_checksum(mospfHdr))
	{
		log(ERROR, "Mospf checksum is not equal to the one in mospf header.");
		return;
	}
	
	pthread_mutex_lock(&mospf_lock);
	// find entry in existing entries
	mospf_nbr_t *nbrEntry = NULL;
	list_for_each_entry(nbrEntry, &iface->nbr_list, list)
	{
		if(nbrEntry->nbr_id == ntohl(mospfHdr->rid))
		{
			if ((nbrEntry->nbr_ip != ntohl(ipHdr->saddr)) || (nbrEntry->nbr_mask != ntohl(mospfHello->mask)))
			{
				nbrEntry->nbr_ip = ntohl(ipHdr->saddr);
				nbrEntry->nbr_mask = ntohl(mospfHello->mask);
				nbrChanged = 1;
			}
			nbrEntry->alive = 3 * ntohs(mospfHello->helloint);

			// update num_nbr
			// mospf_nbr_t *tmpNbr;
			// int countNbr = 0;
			// list_for_each_entry(tmpNbr, &iface->nbr_list, list)
			// 	countNbr++;
			// iface->num_nbr = countNbr;

			pthread_mutex_unlock(&mospf_lock);
			
			#ifdef DEBUG_PRINT_NBR
			FprintIfaceNbrList(iface);
			#endif
			
			return;
		}
	}

	// create and insert new entry
	mospf_nbr_t *mospfNbr = (mospf_nbr_t *)malloc(sizeof(mospf_nbr_t));
	mospfNbr->nbr_id = ntohl(mospfHdr->rid);
	mospfNbr->nbr_ip = ntohl(ipHdr->saddr);
	mospfNbr->nbr_mask = ntohl(mospfHello->mask);
	mospfNbr->alive = 3 * ntohs(mospfHello->helloint);
	list_add_head(&mospfNbr->list, &iface->nbr_list);

	// update num_nbr
	// mospf_nbr_t *tmpNbr;
	// int countNbr = 0;
	// list_for_each_entry(tmpNbr, &iface->nbr_list, list)
	// 	countNbr++;
	// iface->num_nbr = countNbr;

	nbrChanged = 1;
	pthread_mutex_unlock(&mospf_lock);
	
	#ifdef DEBUG_PRINT_NBR
	FprintIfaceNbrList(iface);
	#endif
}

void *sending_mospf_lsu_thread(void *param)
{
	#ifdef DEBUG_SEND_LSU
	int timer = 7;
	#else
	int timer = instance->lsuint;
	#endif

	#ifdef DEBUG_WTFIGO
	fprintf(stdout, "Seems Working Now: send mOSPF LSU message periodically. (Every %d seconds)\n", timer);
	#endif

	while (1)
	{
		sleep(1);
		if (timer < 0 || nbrChanged)			
		{
			#ifdef DEBUG_SEND_LSU
			timer = 7;
			fprintf(stdout, "Sending mOSPF LSU message now.\n");
			#else
			timer = instance->lsuint;
			#endif

			pthread_mutex_lock(&mospf_lock);				// protect nbrChanged and neighboor list

			// Send LSU Message
			// First calculate length of packet
			int numNbr = 0;
			iface_info_t *iface;
			list_for_each_entry(iface, &instance->iface_list, list)
			{
				if (iface->num_nbr > 0)
					numNbr = numNbr + iface->num_nbr;
				else
					numNbr++;
			}

			int packetLength = ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE + MOSPF_LSU_SIZE + numNbr * MOSPF_LSA_SIZE;
			if (packetLength > ETH_FRAME_LEN)
			{
				log(ERROR, "LSU message is longer than an ethernet frame.");
				continue;
			}
			char *packet = (char *)malloc(packetLength);
			
			// Fill in the packet
			struct mospf_hdr *mospfHdr = (struct mospf_hdr *)(packet + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE);
			struct mospf_lsu *mospfLsu = (struct mospf_lsu *)(((char *)mospfHdr) + MOSPF_HDR_SIZE);
			struct mospf_lsa *mospfFirstLsa = (struct mospf_lsa *)(((char *)mospfLsu) + MOSPF_LSU_SIZE);
			struct mospf_lsa *p = mospfFirstLsa;
			list_for_each_entry(iface, &instance->iface_list, list)
			{
				if (iface->num_nbr > 0)
				{
					mospf_nbr_t *nbr;
					list_for_each_entry(nbr, &iface->nbr_list, list)
					{
						p->rid = htonl(nbr->nbr_id);
						p->mask = htonl(nbr->nbr_mask);
						p->subnet = htonl((nbr->nbr_ip) & (ntohl(p->mask)));
						#ifdef DEBUG_MOSPF_LSU_SEND
						fprintf(stdout, "\niface 0x%08x: rid = 0x%08x, mask = 0x%08x\n", iface->ip, nbr->nbr_id, nbr->nbr_mask);
						fprintf(stdout, "lsarid = 0x%08x, lsamask = 0x%08x\n", ntohl(p->rid), ntohl(p->mask));
						#endif
						p++;
					}
				}
				else
				{
					p->rid = htonl(0);
					p->mask = htonl(iface->mask);
					p->subnet = htonl((iface->ip) & (ntohl(p->mask)));
					#ifdef DEBUG_MOSPF_LSU_SEND
					fprintf(stdout, "\niface 0x%08x has no neighboors.\nlsarid = 0x%08x, lsamask = 0x%08x\n", iface->ip ,ntohl(p->rid), ntohl(p->mask));
					#endif
					p++;
				}
			}

			nbrChanged = 0;
			pthread_mutex_unlock(&mospf_lock);

			mospf_init_lsu(mospfLsu, numNbr);
			mospf_init_hdr(mospfHdr, MOSPF_TYPE_LSU, (MOSPF_HDR_SIZE + MOSPF_LSU_SIZE + MOSPF_LSA_SIZE * numNbr), instance->router_id, instance->area_id);
			mospfHdr->checksum = mospf_checksum(mospfHdr);

			#ifdef DEBUG_PRINT_MOSPF_LSU_SEND
			FprintMospfLsuSend(((struct mospf_lsa *)(packet + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE + MOSPF_LSU_SIZE)), numNbr);
			#endif

			/*// Create or update mospf db entry
			pthread_mutex_lock(&mospfDbLock);
			// fprintf(stdout, "send: get lock\n");

			if (ntohs(mospfLsu->seq) == 0)
			{
				//fprintf(stdout, "create entry and timer\n");
				mospf_db_entry_t *newEntry = (mospf_db_entry_t *)malloc(sizeof(mospf_db_entry_t));
				newEntry->rid = ntohl(mospfHdr->rid);
				newEntry->seq = ntohs(mospfLsu->seq);
				newEntry->nadv = ntohl(mospfLsu->nadv);
				newEntry->array = (struct mospf_lsa *)malloc(newEntry->nadv * MOSPF_LSA_SIZE);
				memcpy(newEntry->array, mospfFirstLsa, numNbr * MOSPF_LSA_SIZE);
				list_add_head(&newEntry->list, &mospf_db);
				struct db_entry_timer *timer = (struct db_entry_timer *)malloc(sizeof(struct db_entry_timer));
				timer->timer = MOSPF_DB_ENTRY_TIMER;
				//fprintf(stdout, "send: add timer to list\n");
				list_add_head(&timer->list, &dbTimerHead);
				//fprintf(stdout, "send: added timer to list\n");
			}
			else
			{
				mospf_db_entry_t *entry;
				struct db_entry_timer *timer = list_entry(dbTimerHead.next, struct db_entry_timer, list);
				list_for_each_entry(entry, &mospf_db, list)
				{
					if (entry->rid == ntohl(mospfHdr->rid))
					{
						entry->seq = ntohs(mospfLsu->seq);
						entry->nadv = ntohl(mospfLsu->nadv);
						free(entry->array);
						entry->array = (struct mospf_lsa *)malloc(entry->nadv * MOSPF_LSA_SIZE);
						memcpy(entry->array, mospfFirstLsa, numNbr * MOSPF_LSA_SIZE);
						timer->timer = MOSPF_DB_ENTRY_TIMER;
					}
					timer = list_entry(timer->list.next, struct db_entry_timer, list);
				}
			}
			pthread_mutex_unlock(&mospfDbLock);
			//fprintf(stdout, "send: release lock\n");*/

			// Send lsu messages from every interface to every neighboor
			list_for_each_entry(iface, &instance->iface_list, list)
			{
				mospf_nbr_t *nbr;
				list_for_each_entry(nbr, &iface->nbr_list, list)
				{
					char *mirrorPacket = (char *)malloc(packetLength);				// Every packet will be freeed after sent. so every time a packet is sent, a mirror is needed.
					memcpy(mirrorPacket, packet, packetLength);

					struct iphdr *ipHdr = (struct iphdr *)(mirrorPacket + ETHER_HDR_SIZE);
					struct ether_header *ethHdr = (struct ether_header *)mirrorPacket;
					ip_init_hdr(ipHdr, iface->ip, nbr->nbr_ip, (IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE + MOSPF_LSU_SIZE + numNbr * MOSPF_LSA_SIZE), IPPROTO_MOSPF);
					ipHdr->checksum = ip_checksum(ipHdr);
					ethHdr->ether_type = htons(ETH_P_IP);
					// ethHdr->ether_shost = iface->mac;
					for (int i = 0; i < ETH_ALEN; i++)
						ethHdr->ether_shost[i] = iface->mac[i];
					// ethHdr->ether_dhost = ?									How can I get mac address of each neighboor?
					// some hack here

					// Send LSU Message
					iface_send_packet(iface, mirrorPacket, packetLength);
				}
			}

			instance->sequence_num++;
		}
		else
			timer--;
	}
}

void forward_mospf_lsu_packet(iface_info_t *iface, char *packet, int len)
{
	struct iphdr *ipHdr = packet_to_ip_hdr(packet);
	struct mospf_hdr *mospfHdr = (struct mospf_hdr *)IP_DATA(ipHdr);
	struct mospf_lsu *mospfLsu = (struct mospf_lsu *)((char *)mospfHdr + MOSPF_HDR_SIZE);

	iface_info_t *sendIface;
	list_for_each_entry(sendIface, &instance->iface_list, list)
	{
		if (sendIface->ip != iface->ip)
		{
			mospf_nbr_t *destNbr;
			list_for_each_entry(destNbr, &sendIface->nbr_list, list)
			{
				#ifdef DEBUG_FORWARD_LSU
				fprintf(stdout, "Received packet from interface 0x%08x\nforwarding from interface 0x%08x, to 0x%08x\n", iface->ip, sendIface->ip, destNbr->nbr_id);
				#endif

				char *newPacket = (char *)malloc(len);
				memcpy(newPacket, packet, len);
				struct ether_header *newEthHdr = (struct ether_header *)newPacket;
				struct iphdr *newIpHdr = (struct iphdr *)((char *)newEthHdr + ETHER_HDR_SIZE);
				struct mospf_hdr *newMospfHdr = (struct mospf_hdr *)((char *)newIpHdr + IP_BASE_HDR_SIZE);
				struct mospf_lsu *newMospfLsu = (struct mospf_lsu *)((char *)newMospfHdr + MOSPF_HDR_SIZE);
				//struct mospf_lsa *newMospfFirstLsa = (struct mospf_lsa *)((char *)newMospfLsu + MOSPF_LSU_SIZE);
				newMospfLsu->ttl = mospfLsu->ttl - 1;
				//mospf_init_hdr(newMospfHdr, MOSPF_TYPE_LSU, ntohs(mospfHdr->len), ntohl(mospfHdr->rid), ntohl(mospfHdr->aid));
				newMospfHdr->checksum = mospf_checksum(newMospfHdr);
				ip_init_hdr(newIpHdr, sendIface->ip, destNbr->nbr_ip, ntohs(ipHdr->tot_len), IPPROTO_MOSPF);
				newIpHdr->ttl = ipHdr->ttl - 1;
				newIpHdr->checksum = ip_checksum(newIpHdr);
				// newEthHdr->ether_shost = sendIface->mac;
				for (int i = 0; i < ETH_ALEN; i++)
					newEthHdr->ether_shost[i] = sendIface->mac[i];
				iface_send_packet(sendIface, newPacket, len);
				//ip_forward_packet(destNbr->nbr_ip, newPacket, len);
			}
		}
	}
}

void handle_mospf_lsu(iface_info_t *iface, char *packet, int len)
{
	#ifdef DEBUG_WTFIGO
	fprintf(stdout, "Seems working now: handle mOSPF LSU message.\n");					// maybe I should create another pthread to deal with time out
	#endif
	struct iphdr *ipHdr = packet_to_ip_hdr(packet);
	struct mospf_hdr *mospfHdr = (struct mospf_hdr *)IP_DATA(ipHdr);
	struct mospf_lsu *mospfLsu = (struct mospf_lsu *)((char *)mospfHdr + MOSPF_HDR_SIZE);
	struct mospf_lsa *mospfFirstLsa = (struct mospf_lsa *)((char *)mospfLsu + MOSPF_LSU_SIZE);

	if (mospfHdr->checksum != mospf_checksum(mospfHdr))
	{
		log(ERROR, "Mospf checksum is not equal to the one in mospf header.");
		return;
	}

	#ifdef DEBUG_PRINT_MOSPF_LSU_RECV
	FprintMospfLsuRecv(mospfHdr);
	#endif

	pthread_mutex_lock(&mospfDbLock);
	mospf_db_entry_t *mospfDbEntry;	
	struct db_entry_timer *timer = list_entry(dbTimerHead.next, struct db_entry_timer, list);
	list_for_each_entry(mospfDbEntry, &mospf_db, list)
	{
		if (mospfDbEntry->rid == ntohl(mospfHdr->rid))
		{
			if (mospfDbEntry->seq < ntohs(mospfLsu->seq))
			{
				// update mospf db entry
				mospfDbEntry->seq = ntohs(mospfLsu->seq);
				mospfDbEntry->nadv = ntohl(mospfLsu->nadv);
				free(mospfDbEntry->array);
				mospfDbEntry->array = (struct mospf_lsa *)malloc(mospfDbEntry->nadv * MOSPF_LSA_SIZE);
				memcpy(mospfDbEntry->array, mospfFirstLsa, (mospfDbEntry->nadv * MOSPF_LSA_SIZE));
				timer->timer = MOSPF_DB_ENTRY_TIMER;
				pthread_mutex_unlock(&mospfDbLock);

				#ifdef DEBUG_PRINT_MOSPF_DB_WHEN_HANDLE
				FprintMospfDB();
				#endif

				// forward packet from every interface to every neighboor
				forward_mospf_lsu_packet(iface, packet, len);
				return;
			}
			else
			{
				// do nothing but return
				pthread_mutex_unlock(&mospfDbLock);
				return;
			}
		}
		timer = list_entry(timer->list.next, struct db_entry_timer, list);
	}

	// create a new mospf db entry
	mospfDbEntry = (mospf_db_entry_t *)malloc(sizeof(mospf_db_entry_t));
	mospfDbEntry->rid = ntohl(mospfHdr->rid);
	mospfDbEntry->seq = ntohs(mospfLsu->seq);
	mospfDbEntry->nadv = ntohl(mospfLsu->nadv);
	mospfDbEntry->array = (struct mospf_lsa *)malloc(mospfDbEntry->nadv * MOSPF_LSA_SIZE);
	memcpy(mospfDbEntry->array, mospfFirstLsa, (mospfDbEntry->nadv * MOSPF_LSA_SIZE));
	list_add_head(&mospfDbEntry->list, &mospf_db);
	timer = (struct db_entry_timer *)malloc(sizeof(struct db_entry_timer));
	timer->timer = MOSPF_DB_ENTRY_TIMER;
	list_add_head(&timer->list, &dbTimerHead);
	pthread_mutex_unlock(&mospfDbLock);

	#ifdef DEBUG_PRINT_MOSPF_DB_WHEN_HANDLE
	FprintMospfDB();
	#endif

	// forward packet from every interface to every neighboor
	forward_mospf_lsu_packet(iface, packet, len);
}

void handle_mospf_packet(iface_info_t *iface, char *packet, int len)
{
	struct iphdr *ip = (struct iphdr *)(packet + ETHER_HDR_SIZE);
	struct mospf_hdr *mospf = (struct mospf_hdr *)((char *)ip + IP_HDR_SIZE(ip));

	if (mospf->version != MOSPF_VERSION) {
		log(ERROR, "received mospf packet with incorrect version (%d)", mospf->version);
		return ;
	}
	if (mospf->checksum != mospf_checksum(mospf)) {
		log(ERROR, "received mospf packet with incorrect checksum");
		return ;
	}
	if (ntohl(mospf->aid) != instance->area_id) {
		log(ERROR, "received mospf packet with incorrect area id");
		return ;
	}

	// log(DEBUG, "received mospf packet, type: %d", mospf->type);

	switch (mospf->type) {
		case MOSPF_TYPE_HELLO:
			handle_mospf_hello(iface, packet, len);
			break;
		case MOSPF_TYPE_LSU:
			handle_mospf_lsu(iface, packet, len);
			break;
		default:
			log(ERROR, "received mospf packet with unknown type (%d).", mospf->type);
			break;
	}
}

void *checking_db_timer_thread(void *param)					// new thread to update db timer
{
	while(1)
	{
		#ifdef DEBUG_WTFIGO
		fprintf(stdout, "Working on: Update DB Timer\n");
		#endif

		sleep(1);
		pthread_mutex_lock(&mospfDbLock);

		mospf_db_entry_t *mospfDbEntry;	
		struct db_entry_timer *timer = list_entry(dbTimerHead.next, struct db_entry_timer, list);

		list_for_each_entry(mospfDbEntry, &mospf_db, list)
		{
			//fprintf(stdout, "Update DB Timer\n");
			if ((timer->timer - 1) < 0)
			{
				// delete db entry and timer
				mospf_db_entry_t *tmpEntry = mospfDbEntry;
				struct db_entry_timer *tmpTimer = timer;
				list_delete_entry(&mospfDbEntry->list);
				list_delete_entry(&timer->list);
				mospfDbEntry = list_entry(tmpEntry->list.prev, mospf_db_entry_t, list);
				timer = list_entry(tmpTimer->list.prev, struct db_entry_timer, list);
				free(tmpEntry);
				free(tmpTimer);
			}
			else
			{
				// update timer
				timer->timer--;
			}
			timer = list_entry(timer->list.next, struct db_entry_timer, list);
		}

		pthread_mutex_unlock(&mospfDbLock);

		#ifdef DEBUG_PRINT_MOSPF_DB_WHEN_TIMING
		FprintMospfDB();
		#endif
	}
}

// Note: All functions below should be in another new source file. But to make the assignment
// submition as clean as a single file, I still write them here.

u32 nid_to_rid(u32 *nodes, int nid)
{
	return nodes[nid];
}

int rid_to_nid(u32 *nodes, u32 rid)
{
	for (int i = 0; i < MAX_GRAPH_NODE; i++)
		if (nodes[i] == rid)
			return i;
	return (MAX_GRAPH_NODE - 1);									// unknown node, maybe is a host
}

int find_node_with_min_distance(int *inFinishedSet, int *distance)
{
	int minDistance = DEFAULT_TTL + 1;
	int minNodeId = MAX_GRAPH_NODE - 1;

	for (int i = 0; i < MAX_GRAPH_NODE; i++)
	{
		if ((inFinishedSet[i] == 0) && (distance[i] <= minDistance))
		{
			minDistance = distance[i];
			minNodeId = i;
		}
	}

	return minNodeId;
}

int has_been_added(u32 *subnets, u32 subnet, int countSubnets)		// check if subnet has been added to rtable
{
	for (int i = 0; i < countSubnets; i++)
	{
		if (subnets[i] == subnet)
			return 1;
	}
	
	return 0;
}

iface_info_t *find_iface(int nodeId, int *prev, u32 *nodes)
{
	int i = nodeId;
	while (prev[i] != 0)
	{
		i = prev[i];
	}
	u32 rid = nid_to_rid(nodes, i);
	iface_info_t *iface, *ifaceNext;
	list_for_each_entry_safe(iface, ifaceNext, &instance->iface_list, list)
	{
		mospf_nbr_t *nbr, *nbrNext;
		list_for_each_entry_safe(nbr, nbrNext, &iface->nbr_list, list)
		{
			if (nbr->nbr_id == rid)
				return iface;
		}
	}
	
	return NULL;												// this should not happen
}

u32 find_gateway(int nodeId, int *prev, u32 *nodes, iface_info_t *iface)
{
	int i = nodeId;
	while (prev[i] != 0)
	{
		i = prev[i];
	}
	int rid = nid_to_rid(nodes, i);
	
	mospf_nbr_t *nbr, *nbrNext;
	list_for_each_entry_safe(nbr, nbrNext, &iface->nbr_list, list)
	{
		if (nbr->nbr_id == rid)
			return nbr->nbr_ip; 
	}
	
	return -1;													// this should not happen
}

void *update_rtable_thread(void *param)
{
	print_rtable();

	while (1)
	{
		sleep(45);

		#ifdef DEBUG
		fprintf(stdout, "Working on: update rtable\n");
		#endif

		pthread_mutex_lock(&mospf_lock);
		pthread_mutex_lock(&mospfDbLock);

		// create graph from mospf db and neighboors of interfaces
		int graph[MAX_GRAPH_NODE][MAX_GRAPH_NODE];				// should have been a linked-list, but for time saving sake, an array will be fine
		u32 nodes[MAX_GRAPH_NODE];								// store nodes' rids
		for (int i = 0; i < MAX_GRAPH_NODE; i++)
			for (int j = 0; j < MAX_GRAPH_NODE; j++)
				graph[i][j] = 0;

		nodes[0] = instance->router_id;
		mospf_db_entry_t *dbEntry, *dbNextEntry;
		int countNodes = 1;
		list_for_each_entry_safe(dbEntry, dbNextEntry, &mospf_db, list)
		{
			nodes[countNodes] = dbEntry->rid;
			countNodes++;
			#ifdef DEBUG
			fprintf(stdout, "countNodes = %d\n", countNodes);
			#endif
		}

		iface_info_t *iface, *ifaceNext;
		list_for_each_entry_safe(iface, ifaceNext, &instance->iface_list, list)
		{
			mospf_nbr_t *nbr, *nbrNext;
			list_for_each_entry_safe(nbr, nbrNext, &iface->nbr_list, list)
			{
				int nbrNodeId = rid_to_nid(nodes, nbr->nbr_id);
				graph[0][nbrNodeId] = 1;
				graph[nbrNodeId][0] = 1;
			}
		}
		list_for_each_entry_safe(dbEntry, dbNextEntry, &mospf_db, list)
		{
			int routerNodeId = rid_to_nid(nodes, dbEntry->rid);
			struct mospf_lsa *mospfLsaBase = dbEntry->array;
			for (int i = 0; i < dbEntry->nadv; i++)
			{
				if (ntohl(mospfLsaBase[i].rid) != 0)
				{
					int nbrNodeId = rid_to_nid(nodes, ntohl(mospfLsaBase[i].rid));
					graph[routerNodeId][nbrNodeId] = 1;
					graph[nbrNodeId][routerNodeId] = 1;
				}
			}
		}

		// dijkstra
		int distance[MAX_GRAPH_NODE], inFinishedSet[MAX_GRAPH_NODE], prev[MAX_GRAPH_NODE], sequence[MAX_GRAPH_NODE];
		for (int i = 0; i < MAX_GRAPH_NODE; i++)
		{
			distance[i] = DEFAULT_TTL + 1;						// max distance is DEFAULT_TTL + 1 (65)
			inFinishedSet[i] = 0;
			prev[i] = MAX_GRAPH_NODE - 1;						// a node that should not be any router
			sequence[i] = -1;									// order of node being selected
		}
		distance[0] = 0;										// current node (router)
		prev[0] = 0;
		for (int i = 0; i < countNodes; i++)
		{
			int minNodeId = find_node_with_min_distance(inFinishedSet, distance);
			inFinishedSet[minNodeId] = 1;
			sequence[i] = minNodeId;

			int newDistance = distance[minNodeId] + 1;
			for (int j = 0; j < MAX_GRAPH_NODE; j++)			// update distance and prev array
			{
				if ((graph[minNodeId][j] == 1) && (inFinishedSet[j] == 0) && (newDistance <= distance[j]))
				{
					distance[j] = newDistance;
					prev[j] = minNodeId;
				}
			}
		}

		// update rtable entry
		clear_rtable();
		u32 subnets[MAX_GRAPH_NODE * MAX_GRAPH_NODE];			// subnets that has been added into rtable
		for (int i = 0; i < MAX_GRAPH_NODE * MAX_GRAPH_NODE; i++)
			subnets[i] = (u32)-1;
		int countSubnets = 0;
		list_for_each_entry_safe(iface, ifaceNext, &instance->iface_list, list)			// subnets of current router
		{
			rt_entry_t *rtEntry = new_rt_entry(iface->ip, iface->mask, 0, iface);
			add_rt_entry(rtEntry);
			subnets[countSubnets] = iface->ip & iface->mask;
			countSubnets++;
			#ifdef DEBUG
			fprintf(stdout, "countSubnets = %d\n", countSubnets);
			#endif
		}
		for (int i = 1; i < countNodes; i++)											// add subnets by distance of increasing order
		{
			u32 rid = nid_to_rid(nodes, sequence[i]);

			#ifdef DEBUG
			fprintf(stdout, "Creating rtable entry for router 0x%08x's subnets (sequence[%d] = %d, countNodes = %d)\n", rid, i, sequence[i], countNodes);
			#endif

			//mospf_db_entry_t *dbEntry, *dbNextEntry;
			list_for_each_entry_safe(dbEntry, dbNextEntry, &mospf_db, list)
			{
				if (dbEntry->rid == rid)
				{
					for (int j = 0; j < dbEntry->nadv; j++)
					{
						#ifdef DEBUG
						fprintf(stdout, "j = %d, dbEntry->nadv = %d\n", j, dbEntry->nadv);
						#endif

						if (!has_been_added(subnets, ntohl(dbEntry->array[j].subnet), countSubnets))
						{
							iface_info_t *pIface = find_iface(sequence[i], prev, nodes);
							u32 gateway = find_gateway(sequence[i], prev, nodes, pIface);

							#ifdef DEBUG
							fprintf(stdout, "entry: subnet = 0x%08x, gateway = 0x%08x, interface = %s\n", ntohl(dbEntry->array[j].subnet), gateway, pIface->name);
							#endif

							rt_entry_t *rtEntry = new_rt_entry(ntohl(dbEntry->array[j].subnet), ntohl(dbEntry->array[j].mask), gateway, pIface);
							add_rt_entry(rtEntry);
							subnets[countSubnets] = ntohl(dbEntry->array[j].subnet);
							countSubnets++;
							#ifdef DEBUG
							fprintf(stdout, "countSubnets = %d\n", countSubnets);
							#endif
						}
						#ifdef DEBUG
						else
						{
							fprintf(stdout, "subnet 0x%08x has been added. do not create entry for it.\n", ntohl(dbEntry->array[j].subnet));
						}
						#endif						
					}
				}
			}
		}

		pthread_mutex_unlock(&mospfDbLock);
		pthread_mutex_unlock(&mospf_lock);

		#ifdef DEBUG_PRINT_MOSPF_DB
		FprintMospfDB();
		#endif

		print_rtable();
	}
	
}