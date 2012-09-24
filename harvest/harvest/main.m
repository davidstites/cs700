//
//  main.m
//  harvest
//
//  Created by David R. Stites on 9/18/12.
//
//

#import <Foundation/Foundation.h>
#import <pthread.h>
#import <stdio.h>
#import <stdlib.h>
#import <pcap.h>
#import <errno.h>
#import <sys/socket.h>
#import <netinet/in.h>
#import <arpa/inet.h>

#import "main.h"
#import "radiotap.h"
#import "dstites_radiotap.h"
#import "ieee80211_defs.h"

void getSupportedLinkTypes(pcap_t *stream) {
  int *dlt_buf;
  int n;
  
  if((n = pcap_list_datalinks(stream, &dlt_buf)) == -1) {
    pcap_perror(stream, "couldn't get list of datalink types.");
  }
  else {
    printf("%d different link types are supported: \n\n", n);

    for(int i = 0; i < n; i++) {
      const char *str1 = pcap_datalink_val_to_name(dlt_buf[i]);
      const char *str2 = pcap_datalink_val_to_description(dlt_buf[i]);
      printf("%s (%d, %s)\n",str2, dlt_buf[i], str1);
    }
    pcap_free_datalinks(dlt_buf);
  }
}

void getInterfaceInformation(pcap_if_t *iface, bpf_u_int32 *netp, bpf_u_int32 *maskp) {
  char *net;
  char *mask;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct in_addr addr;
  
  // ask pcap for the network address and mask of the device
  if(pcap_lookupnet(iface->name, netp, maskp, errbuf) == -1) {
    printf("%s\n", errbuf);
    exit(1);
  }
  
  // get the network address in a human readable form
  addr.s_addr = *netp;
  net = inet_ntoa(addr);
  
  if(net == NULL) {
    perror("inet_ntoa");
    exit(1);
  }
  
  printf("Network address: %s\n", net);
  
  // do the same as above for the device's mask
  addr.s_addr = *maskp;
  mask = inet_ntoa(addr);
  
  if(mask == NULL) {
    perror("inet_ntoa");
    exit(1);
  }
  
  printf("Netmask: %s\n", mask);
}

void getAvailableInterfaces() {
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t *devlist;
  
  printf("Interfaces available: \n\n");

  /* get a list of all the devices that we can open */
  if(pcap_findalldevs(&devlist, errbuf) != -1) {
    pcap_if_t *iface = devlist;
    while(iface->next != NULL) {
      printf("%s\n", iface->name);
      iface = iface->next;
    }
  }
  
  printf("\n");
  pcap_freealldevs(devlist);
}

pcap_if_t *copyInterface(char *dev) {
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t *devlist;
  
  if(dev == NULL) {
    return NULL;
  }
  
  /* get a list of all the devices that we can open */
  if(pcap_findalldevs(&devlist, errbuf) != -1) {
    pcap_if_t *cur_iface = devlist;
    while(cur_iface->next != NULL) {
      if(strcmp(cur_iface->name, dev) == 0) {
        pcap_if_t *iface = (pcap_if_t *)malloc(sizeof(pcap_if_t));
        
        iface->next = NULL;
        
        iface->name = (char *)malloc(sizeof(char) * strlen(cur_iface->name));
        strncpy(iface->name, cur_iface->name, strlen(cur_iface->name));
        
        iface->addresses = (pcap_addr_t *)malloc(sizeof(pcap_addr_t));
        memcpy(iface->addresses, cur_iface->addresses, sizeof(pcap_addr_t));
        
        iface->flags = (bpf_u_int32)malloc(sizeof(bpf_u_int32));
        memcpy(&iface->flags, &cur_iface->flags, sizeof(bpf_u_int32));
      
        pcap_freealldevs(devlist);
        return iface;
      }
      
      cur_iface = cur_iface->next;
    }
  }
  
  pcap_freealldevs(devlist);
  return NULL;
}

pcap_t *openDevice(pcap_if_t *dev) {
  char errbuf[PCAP_ERRBUF_SIZE];

  if(dev == NULL) {
    return NULL;
  }
  
  return pcap_open_live(dev->name /* device */, MAX_BYTES_TO_CAPTURE /* bytes to capture */, PROMISC_ON /* promisc mode */, READ_TIMEOUT_MS /* timeout */, errbuf);
}

int main(int argc, const char * argv[]) {
  @autoreleasepool {
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 netp = 0;
    bpf_u_int32 maskp = 0;
    
    struct bpf_program filter;          /* Place to store the BPF filter program  */
    struct pcap_pkthdr pkthdr;          /* Packet information (timestamp,size...) */
    const unsigned char *packet = NULL; /* Received raw data */
  
    getAvailableInterfaces();
    pcap_if_t *iface = copyInterface(EN1);
    
    getInterfaceInformation(iface, &netp, &maskp);
    
    pcap_t *capStream = openDevice(iface);
    if(capStream != NULL) {
      printf("opened interface: %s\n", iface->name);
    }
    
    /* do we need this? */
    pcap_set_promisc(capStream, PROMISC_ON);
    pcap_set_rfmon(capStream, PROMISC_ON);
    
    getSupportedLinkTypes(capStream);
    
    // do this better
    pcap_set_datalink(capStream, DLT_IEEE802_11_RADIO);
    
    // compiles the filter expression into a BPF filter program
    if (pcap_compile(capStream, &filter, PROBE_REQ_FILTER, 1, /*maskp*/ /* DRS */ PCAP_NETMASK_UNKNOWN) == -1) {
      fprintf(stderr, "ERROR: %s\n", pcap_geterr(capStream));
      exit(1);
    }
    
    // load the filter program into the packet capture device
    if (pcap_setfilter(capStream, &filter) == -1) {
      fprintf(stderr, "ERROR: %s\n", pcap_geterr(capStream));
      exit(1);
    }
    
    while(1){
      if ((packet = pcap_next(capStream, &pkthdr)) == NULL) {
        // most likely due to timeout
        fprintf(stderr, "ERROR: Error getting the packet (%s).\n", errbuf);
      }
      else {
        struct ieee80211_radiotap_header *rh = (struct ieee80211_radiotap_header *)packet;
        
        printf("\nReceived Packet Size: %d\n", pkthdr.len);

        // as of the current radiotap standard, version is always zero
        printf("Radiotap Version: %d\n",rh->it_version);
        
        // currently unused according to the radiotap standard
        printf("Radiotap Pad: %d\n",rh->it_pad);
        
        // indicates the entire length of the radiotap data, including the radiotap header
        printf("Radiotap Length: %d\n", rh->it_len);
        
        // a bitmask of the radiotap data fields that follows the radiotap header.
        // if bit 31 of the it_present field is not set, the data for fields specified
        // in the it_present bitmask immediately follow the radiotap header. If it is set,
        // then more it_present words follow and the radiotap data follows after the
        // it_present word that has bit 31 unset. multiple namespaces may be present.
        // fields are strictly ordered; The developer can specify any combination of fields,
        // but the data must appear following the radiotap header in the order they are
        // specified in the it_present bitmask (or more accurately, in the order the bit
        // numbers for the it_present bitmask are defined).
        // data is specified in little endian byte-order
        
        if(BIT_SET(rh->it_present, IEEE80211_RADIOTAP_EXT)) {
          printf("more headers are available\n");
        }
        
        /* DRS */
        struct ieee80211_radiotap_data *rt_data = (rh + (sizeof(struct ieee80211_radiotap_header) / 8));
         
        if(BIT_SET(rh->it_present, IEEE80211_RADIOTAP_TSFT)) {
          // shift off the size of a radiotap header and you should be at the beginning
          // of your radiotap data
          printf("Radiotap Timestamp: %llu\n", rt_data->tsft);
        }
        
        if(BIT_SET(rh->it_present, IEEE80211_RADIOTAP_RATE)) {
          // rate is in 500 kbps
          printf("Radiotap data rate: %u Mb/s\n", TO_MbPS(rt_data->rate));
        }
        
        if(BIT_SET(rh->it_present, IEEE80211_RADIOTAP_CHANNEL)) {
          // shift off the size of a radiotap header and you should be at the beginning
          // of your radiotap data
          printf("Radiotap channel: %u MHz, ", rt_data->chan_freq);
          
          if(rt_data->chan_flags & IEEE80211_CHAN_2GHZ) {
            printf("2 GHz band\n");
          }
          else if(rt_data->chan_flags & IEEE80211_CHAN_5GHZ) {
            printf("5 GHz band\n");
          }
          
          /* DRS */
          if(rt_data->chan_flags & IEEE80211_CHAN_PASSIVE) {
            printf("Radiotap channel: passive\n");
          }
        }
        
        if(BIT_SET(rh->it_present, IEEE80211_RADIOTAP_DBM_ANTSIGNAL)) {
          printf("Radiotap signal: %i\n", rt_data->ant_signal);
        }
        
        if(BIT_SET(rh->it_present, IEEE80211_RADIOTAP_DBM_ANTNOISE)) {
          printf("Radiotap noise: %i\n", rt_data->ant_noise);
        }
        
        // adding rh->it_len should get us to the very start of the 802.11 probe request
        /* DRS */
        struct ieee80211_mgmt *wh = (packet + rh->it_len);
        
        printf("SRC: %02x:%02x:%02x:%02x:%02x:%02x\n", wh->sa[0], wh->sa[1], wh->sa[2], wh->sa[3], wh->sa[4], wh->sa[5]);
        printf("DST: %02x:%02x:%02x:%02x:%02x:%02x\n", wh->da[0], wh->da[1], wh->da[2], wh->da[3], wh->da[4], wh->da[5]);
        printf("BSSID: %02x:%02x:%02x:%02x:%02x:%02x\n", wh->bssid[0], wh->bssid[1], wh->bssid[2], wh->bssid[3], wh->bssid[4], wh->bssid[5]);
        
        // what follows seq_ctrl are some variable length data items, and in this particular case it is ssid and supported rates
        // we would only really be interested in the ssid to see that it is *not* a base-station but rather a client broadcast
        
        // the format is u_int8_t tag, u_int8_t length then some u_int8_t data for the length read in
        
        u_int8_t *thing = wh->u.probe_req.variable;
        thing++;
        
        int len = *thing;

        if(len > 0) {
          thing++;
          printf("SSID: ");
          for(int i = 0; i < len; i++) {
            printf("%c", *thing);
            thing++;
          }
          
          printf("\n");
        }
      }
    }
    
    // this should never be reached
    free(iface);
  }
  
  // this should never be reached
  return 0;
}