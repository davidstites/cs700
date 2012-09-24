//
//  main.m
//  stored
//
//  Created by David R. Stites on 9/22/12.
//  Copyright (c) 2012 David R. Stites. All rights reserved.
//

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#import "common.h"
#import "harvest.h"

int main(int argc, const char * argv[]) {
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
      
      struct harvest *h = NULL;
      while((cnt = recv(client_sock, h, sizeof(struct harvest), 0)) > 0) {
        printf("Timestamp: %llu\n", h->timestamp);
        printf("Message type: %d\n", h->msg_type);
        printf("Message type: %llu\n", h->msg_id);
        printf("Message type: %i\n", h->rssi);
        printf("Message type: %i\n", h->stn_id);
        printf("DST: %02x:%02x:%02x:%02x:%02x:%02x\n", h->dst[0], h->dst[1], h->dst[2], h->dst[3], h->dst[4], h->dst[5]);
        printf("SRC: %02x:%02x:%02x:%02x:%02x:%02x\n",  h->src[0],  h->src[1],  h->src[2],  h->src[3], h->src[4], h->src[5]);
        printf("BSSID: %02x:%02x:%02x:%02x:%02x:%02x\n", h->bssid[0], h->bssid[1], h->bssid[2], h->bssid[3], h->bssid[4], h->bssid[5]);
        printf("SSID: %s", h->ssid);
      }
      
      close(client_sock);
      exit(0);
    }
  }
  return 0;
}

