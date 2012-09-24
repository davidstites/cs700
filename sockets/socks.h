//
//  socks.h
//  sockets
//
//  Created by David R. Stites on 9/23/12.
//  Copyright (c) 2012 David R. Stites. All rights reserved.
//

#ifndef sockets_socks_h
#define sockets_socks_h

#pragma pack(1)
typedef struct socks {
  unsigned long long timestamp; /* 4 bytes */
  u_int8_t src[6]; /* 1 bytes x 6 = 6 bytes */
  u_int8_t dst[6]; /* 1 bytes x 6 = 6 bytes */
  u_int8_t bssid[6]; /* 1 bytes x 6 = 6 bytes */
  int8_t rssi; /* 1 bytes */
  u_int8_t stn_id; /* 1 byte */
} socks;
#pragma pack(0)

#endif
