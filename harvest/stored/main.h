//
//  main.h
//  harvest
//
//  Created by David R. Stites on 9/24/12.
//
//

#ifndef harvest_main_h
#define harvest_main_h

#include <sqlite3.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#import "common.h"
#import "harvest.h"
#import "dstites_sqlite.h"

void *receive_packets(pthread_mutex_t lock);
void *store_packets(pthread_mutex_t lock);

#define DB_PATH "~/"
#define DB_NAME "addresses.sqlite"

const char *CREATE_TBL_STMT = "CREATE TABLE IF NOT EXISTS packets (id INTEGER PRIMARY KEY, timestamp INTEGER NOT NULL, type INTEGER NOT NULL, msg_id INTEGER NOT NULL, rssi INTEGER NOT NULL, stn_id INTEGER NOT NULL, dst TEXT NOT NULL, src TEXT NOT NULL, bssid TEXT NOT NULL, SSID TEXT)";

#endif
