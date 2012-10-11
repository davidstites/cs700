//
//  dstites_radiotap.h
//  harvest
//
//  Created by David R. Stites on 9/21/12.
//
//

/* http://www.radiotap.org/ */

#ifndef harvest_dstites_radiotap_h
#define harvest_dstites_radiotap_h

#define STRUCT_PACKED          __attribute__((__packed__))

struct ieee80211_radiotap_data {
  u_int64_t                               tsft;
  u_int8_t                                flags;
  u_int8_t                                rate;
  u_int16_t                               chan_freq;
  u_int16_t                               chan_flags;
  int8_t                                  ant_signal;
  int8_t                                  ant_noise;
  
  /* DRS */
  /* u_int8_t                                hop_set;
  u_int8_t                                hop_pattern;
  u_int16_t                               lock;
  u_int16_t                               tx_atten;
  u_int16_t                               tx_db_atten;*/
} STRUCT_PACKED;

/* DRS */
struct rx_radiotap_header {
  struct ieee80211_radiotap_header      hdr;
  struct ieee80211_radiotap_data        data;
} STRUCT_PACKED;

#endif
