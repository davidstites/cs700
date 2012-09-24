//
//  main.m
//  server
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

#import "socks.h"

const char *SOCK_PATH = "/tmp/sock";
#define BUFSIZE 80

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
  char buf[BUFSIZE];
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
      
      struct socks s;
      
      printf("test 2");
      while((cnt = recv(client_sock, &s, sizeof(struct socks), 0)) > 0) {
        printf("test");
        //printf("Server got message: %s\n", buf);
      }
      
      /*while((cnt = read(client_sock, buf, 80)) > 0) {
        //printf("Server got message: %s\n", buf);
      }*/
      
      /*memset(buf, 0, 80);
      strcpy(buf, "Message to client");
      cnt = write(client_sock, buf, strlen(buf));*/
      
      close(client_sock);
      exit(0);
    }
  }
  return 0;
}

