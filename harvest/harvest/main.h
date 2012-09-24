//
//  main.h
//  harvest
//
//  Created by David R. Stites on 9/21/12.
//
//

#ifndef harvest_main_h
#define harvest_main_h

#include <pthread.h>
#include "common.h"
#include "list.h"

#define EN0 "en0"
#define EN1 "en1"

#define MAX_BYTES_TO_CAPTURE 2048

#define READ_TIMEOUT_MS 10000 /* 10 seconds */

#define PROMISC_OFF 0
#define PROMISC_ON 1

#define BIT_SET(var, pos) ((var) & (1 << (pos)))
#define TO_MbPS(rate) ((rate * 500) / 1000)

#define STRUCT_PACKED          __attribute__((__packed__))
#define STRUCT_ALIGNED(x)      __attribute__((__aligned__(x)))

node *head = NULL;
queue *q = NULL;

int sock;
ssize_t cnt;
struct sockaddr remote;

const char *PROBE_REQ_FILTER = "wlan subtype probe-req";

void getSupportedLinkTypes(pcap_t *stream);
void getAvailableInterfaces();
void getInterfaceInformation();
pcap_if_t *copyInterface(char *dev);
pcap_t *openDevice(pcap_if_t *dev);
//void setupFilter(struct bpf_program filter);
void startCapture();

void *capture_process_packets(pthread_mutex_t lock);
void *store_packets(pthread_mutex_t lock);
void send_harvest(harvest *h);
int setup_socks();

#endif
