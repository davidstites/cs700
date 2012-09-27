//
//  main.m
//  stored
//
//  Created by David R. Stites on 9/22/12.
//  Copyright (c) 2012 David R. Stites. All rights reserved.
//

#import "main.h"

void *receive_packets(pthread_mutex_t lock) {
  int server_sock;
  struct sockaddr server_address;
  
  unlink(SOCK_PATH);
  if((server_sock = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
    printf("socket create failure %d\n", errno);
    perror("create: ");
    exit(0);
  }
  
  memset(&server_address, 0, sizeof(struct sockaddr));
  server_address.sa_family = AF_UNIX;
  strncpy(server_address.sa_data, SOCK_PATH, strlen(SOCK_PATH));
  
  if(bind(server_sock, &server_address, sizeof(server_address)) < 0) {
    printf("bind failure %d\n", errno);
    perror("bind: ");
    exit(1);
  }
  
  if(listen(server_sock, 5) < 0) {
    printf("listen failure %d\n", errno);
    perror("listen: ");
    exit(1);
  }
  
  int client_sock;
  socklen_t client_len;
  struct sockaddr client_address;
  ssize_t cnt;
  while(true) {
    printf("Waiting for a connection...");
    
    if((client_sock = accept(server_sock, &client_address, &client_len)) < 0) {
      printf("accept failure %d\n", errno);
      perror("accept: ");
      exit(1);
    }
    
    printf("connected.\n");
    
    if(fork() == 0) {
      close(server_sock);
      
      struct harvest h;
      while((cnt = recv(client_sock, &h, sizeof(struct harvest), 0)) > 0) {
        printf("===============================\n");
        printf("Timestamp: %llu\n", h.timestamp);
        printf("Message type: %d\n", h.msg_type);
        printf("Message ID: %llu\n", h.msg_id);
        printf("Message RSSI: %i\n", h.rssi);
        printf("Station ID: %i\n", h.stn_id);
        printf("DST: %02x:%02x:%02x:%02x:%02x:%02x\n", h.dst[0], h.dst[1], h.dst[2], h.dst[3], h.dst[4], h.dst[5]);
        printf("SRC: %02x:%02x:%02x:%02x:%02x:%02x\n",  h.src[0],  h.src[1],  h.src[2],  h.src[3], h.src[4], h.src[5]);
        printf("BSSID: %02x:%02x:%02x:%02x:%02x:%02x\n", h.bssid[0], h.bssid[1], h.bssid[2], h.bssid[3], h.bssid[4], h.bssid[5]);
        printf("SSID: %s\n", h.ssid);
      }
      
      close(client_sock);
      exit(0);
    }
  }
}

void *store_packets(pthread_mutex_t lock) {
  // do sqlite things here
  
  sqlite3 *db_handle = NULL;
  
  // DRS
  CALL_SQLITE(open("/Users/dstites/addresses.sqlite", &db_handle));

  
  // create table if necessary
  sqlite3_exec(db_handle, CREATE_TBL_STMT, NULL, NULL, NULL);
  
  char * sql;
  sqlite3_stmt * stmt;
  int i;
  sql = "INSERT INTO packets (xyz) VALUES (?)";
  CALL_SQLITE (prepare_v2 (db_handle, sql, strlen (sql) + 1, & stmt, NULL));
  CALL_SQLITE (bind_text (stmt, 1, "fruit", 6, SQLITE_STATIC));
  CALL_SQLITE_EXPECT (step (stmt), DONE);
  printf ("row id was %d\n", (int) sqlite3_last_insert_rowid (db_handle));
  
  sqlite3_close(db_handle);
  return NULL;
}

int main(int argc, const char * argv[]) {
  pthread_t receive_thread;
  pthread_t db_thread;
  
  pthread_mutex_t lock;
  
  pthread_mutex_init(&lock, NULL);
  
  // init the capture thread and storage threads
  if(pthread_create(&receive_thread, NULL, receive_packets, &lock) != 0) {
    pthread_mutex_destroy(&lock);
    printf("could not create capture thread");
    exit(1);
  }
  
  if(pthread_create(&db_thread, NULL, store_packets, &lock) != 0) {
    pthread_join(receive_thread, NULL);
    pthread_mutex_destroy(&lock);
    printf("could not create store thread");
    exit(1);
  }
  
  // wait forever for the capture thead
  pthread_join(receive_thread, NULL);
  pthread_join(db_thread, NULL);
  
  pthread_mutex_destroy(&lock);
  
  return 0;
}

