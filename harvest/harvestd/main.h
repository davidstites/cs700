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
#include <stdio.h>
#include <pcap.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <net/if_dl.h>
#include <arpa/inet.h>
#include <sqlite3.h>

#include "list.h"
#include "dstites_sqlite.h"
#include "harvest.h"
#include "radiotap.h"
#include "dstites_radiotap.h"
#include "ieee80211_defs.h"

#define UID_ROOT 0

#ifdef __APPLE__
#define EN0 "en0"
#else
#define EN0 "eth0"
#endif

//#define LOGGING 1

#define QUIT -1

#define FALSE 0
#define TRUE 1

#define MAX_SIGNED_CHAR 0x7F
#define UNKNOWN_STATION_ID 0

#define MAX_BYTES_TO_CAPTURE 2048

#define READ_TIMEOUT_MS 10000 /* 10 seconds */

#define PROMISC_OFF 0
#define PROMISC_ON 1

#define BIT_SET(var, pos) ((var) & (1 << (pos)))
#define TO_MBPS(rate) ((rate * 500) / 1000)

#define STRUCT_PACKED          __attribute__((__packed__))
#define STRUCT_ALIGNED(x)      __attribute__((__aligned__(x)))


/* global vars */

u_int8_t station_id = UNKNOWN_STATION_ID;
node *head = NULL;
char *db_path = NULL;
queue *q = NULL;
sqlite3 *db_handle = NULL;
pthread_mutex_t lock;

#define DB_NAME "addresses.sqlite"

#define TIMESTAMP_BIND_IDX 1
#define TYPE_BIND_IDX 2
#define RSSI_BIND_IDX 3
#define STNID_BIND_IDX 4
#define DST_BIND_IDX 5
#define SRC_BIND_IDX 6
#define BSSID_BIND_IDX 7
#define SSID_BIND_IDX 8

enum MessageType {
  PROBE_REQ,
  PROBE_RESP,
  BEACON
};

const char *CREATE_TBL_STMT = "CREATE TABLE IF NOT EXISTS packets (id INTEGER PRIMARY KEY, timestamp INTEGER NOT NULL, type INTEGER NOT NULL, rssi INTEGER NOT NULL, stn_id INTEGER NOT NULL, dst TEXT NOT NULL, src TEXT NOT NULL, bssid TEXT NOT NULL, SSID TEXT)";

const char *INSERT_ROW_STMT = "INSERT INTO packets (timestamp, type, rssi, stn_id, dst, src, bssid, ssid) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";

const char *PROBE_REQ_FILTER = "wlan subtype probe-req";

void get_supported_link_types(pcap_t *stream);
int get_available_interfaces();
void get_interface_information();
pcap_if_t *copy_interface(int iface);
pcap_t *open_device(pcap_if_t *dev);

sqlite3 *open_database();
void close_database(sqlite3 *handle);
void insert_packet_into_db(harvest *h);
void *capture_process_packets();
void *store_packets();

#endif
