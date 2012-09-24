//
//  main.m
//  client
//
//  Created by David R. Stites on 9/22/12.
//  Copyright (c) 2012 David R. Stites. All rights reserved.
//

#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sqlite3.h>

#import "socks.h"

const char *SOCK_PATH = "/tmp/sock";

int main(int argc, const char * argv[]) {
  int sock;
  ssize_t cnt;
  char buf[80];
  struct sockaddr remote;
  
  socklen_t socklen = sizeof(struct sockaddr);
  memset(&remote, 0, socklen);
  
  if((sock = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
    printf("client socket failure %d\n", errno);
    perror("socket: ");
    exit(1);
  }
  
  remote.sa_family = AF_UNIX;
  strncpy(remote.sa_data, SOCK_PATH, strlen(SOCK_PATH));
  
  if(connect(sock, &remote, socklen) < 0) {
    printf("client connect failure %d\n", errno);
    perror("connect: ");
    exit(1);
  }
  
  strcpy(buf, "Message to server.");
  
  struct socks s;
  s.timestamp = 987654321;
  s.stn_id = 0;
  s.rssi = -54;
  
  for(int i = 0; i < 6; i++) {
    s.bssid[i] = 0xff;
    s.src[i] = 0xff;
    s.dst[i] = 0xff;
  }
  
  //cnt = send(sock, buf, strlen(buf), 0);
  cnt = send(sock, &s, sizeof(struct socks), 0);
  
  memset(buf, 0, 80);
  
  /*while((cnt = read(sock, buf, strlen(buf))) > 0) {
    printf("Client got message: %s\n", buf);
  }*/
  
  return 0;
}

