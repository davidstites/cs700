//
//  main.h
//  harvest
//
//  Created by David R. Stites on 9/21/12.
//
//

#ifndef harvest_main_h
#define harvest_main_h

#import <pthread.h>
#import <stdio.h>
#import <stdlib.h>
#import <pcap.h>
#import <errno.h>
#import <sys/types.h>
#import <sys/socket.h>
#import <netinet/in.h>
#import <arpa/inet.h>
#import <sqlite3.h>

#import "list.h"
#import "dstites_sqlite.h"
#import "harvest.h"
#import "radiotap.h"
#import "dstites_radiotap.h"
#import "ieee80211_defs.h"

#define EN0 "en0"
#define EN1 "en1"

#define FALSE 0
#define TRUE 1

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
sqlite3 *db_handle = NULL;

#define DB_NAME "addresses.sqlite"

#define TIMESTAMP_BIND_IDX 1
#define TYPE_BIND_IDX 2
#define MSGID_BIND_IDX 3
#define RSSI_BIND_IDX 4
#define STNID_BIND_IDX 5
#define DST_BIND_IDX 6
#define SRC_BIND_IDX 7
#define BSSID_BIND_IDX 8
#define SSID_BIND_IDX 9

const char *CREATE_TBL_STMT = "CREATE TABLE IF NOT EXISTS packets (id INTEGER PRIMARY KEY, timestamp INTEGER NOT NULL, type INTEGER NOT NULL, msg_id INTEGER NOT NULL, rssi INTEGER NOT NULL, stn_id INTEGER NOT NULL, dst TEXT NOT NULL, src TEXT NOT NULL, bssid TEXT NOT NULL, SSID TEXT)";

const char *INSERT_ROW_STMT = "INSERT INTO packets (timestamp, type, msg_id, rssi, stn_id, dst, src, bssid, ssid) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";

const char *PROBE_REQ_FILTER = "wlan subtype probe-req";

void get_supported_link_types(pcap_t *stream);
void get_available_interfaces();
void get_interface_information();
pcap_if_t *copy_interface(char *dev);
pcap_t *open_device(pcap_if_t *dev);

sqlite3 *open_database();
void close_database(sqlite3 *handle);
void insert_packet_into_db(harvest *h);
void *capture_process_packets(pthread_mutex_t lock);
void *store_packets(pthread_mutex_t lock);

#endif
