//
//  main.m
//  harvest
//
//  Created by David R. Stites on 9/18/12.
//
//

#include "main.h"

#pragma mark pcap functions

void get_supported_link_types(pcap_t *stream) {
  int *dlt_buf;
  int n;
  
  if((n = pcap_list_datalinks(stream, &dlt_buf)) == -1) {
    pcap_perror(stream, "couldn't get list of datalink types.");
  }
  else {
    printf("\n%d link types are supported: \n\n", n);

    for(int i = 0; i < n; i++) {
      const char *str1 = pcap_datalink_val_to_name(dlt_buf[i]);
      const char *str2 = pcap_datalink_val_to_description(dlt_buf[i]);
      printf("%d.\t%s (%d, %s)\n", i, str2, dlt_buf[i], str1);
    }
		
    pcap_free_datalinks(dlt_buf);
  }
}

void get_interface_information(pcap_if_t *iface, bpf_u_int32 *netp, bpf_u_int32 *maskp) {
  char *net;
  char *mask;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct in_addr addr;
  
  // ask pcap for the network address and mask of the device
  if(iface == NULL) {
    return;
  }
  
  if(pcap_lookupnet(iface->name, netp, maskp, errbuf) == -1) {
    printf("%s\n", errbuf);
    exit(1);
  }
  
  // get the network address in a human readable form
  addr.s_addr = *netp;
  net = inet_ntoa(addr);
  
  printf("Network:\t%s\n", net);

  // do the same as above for the device's mask
  addr.s_addr = *maskp;
  mask = inet_ntoa(addr);
  
  printf("Mask:\t%s\n", mask);
}

int get_available_interfaces() {
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t *devlist = NULL;
  
	int i = 0;
  printf("Interfaces available: (-1 to exit)\n\n");

  /* get a list of all the devices that we can open */
  if(pcap_findalldevs(&devlist, errbuf) != -1) {
    pcap_if_t *iface = devlist;
    while(iface->next != NULL) {
      printf("%d.\t%s\n", i, iface->name);
			
			i++;
      iface = iface->next;
    }
  }
  
  printf("\n");
  
  pcap_freealldevs(devlist);
	
	int iface_chosen = 0;
	do {
		printf("Choose an interface: ");
		scanf("%d", &iface_chosen);
	} while ((iface_chosen < QUIT) || (iface_chosen > (i - 1)));
	
	return iface_chosen;
}

pcap_if_t *copy_interface(int iface_chosen) {
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t *devlist;
	int i = 0;
  
  /* get a list of all the devices that we can open */
  if(pcap_findalldevs(&devlist, errbuf) != -1) {
    pcap_if_t *cur_iface = devlist;
    while(cur_iface->next != NULL) {
      if(i == iface_chosen || ((prechosen_iface != NULL) && (strcmp(cur_iface->name, prechosen_iface) == 0))) {
        pcap_if_t *iface = (pcap_if_t *)malloc(sizeof(pcap_if_t));
				memset(iface, 0, sizeof(pcap_if_t));
        
        iface->next = NULL;
        
        iface->name = (char *)malloc(sizeof(char) * (strlen(cur_iface->name) + 1 /* dont forget the null byte */));
        strncpy(iface->name, cur_iface->name, strlen(cur_iface->name));
        
        iface->addresses = (pcap_addr_t *)malloc(sizeof(pcap_addr_t));
        memcpy(iface->addresses, cur_iface->addresses, sizeof(pcap_addr_t));
        
        iface->flags = (bpf_u_int32)malloc(sizeof(bpf_u_int32));
        memcpy(&iface->flags, &cur_iface->flags, sizeof(bpf_u_int32));
      
        pcap_freealldevs(devlist);
        return iface;
      }
      
			i++;
      cur_iface = cur_iface->next;
    }
  }
  
  pcap_freealldevs(devlist);
  return NULL;
}

pcap_t *open_device(pcap_if_t *dev) {
  char errbuf[PCAP_ERRBUF_SIZE];

  if(dev == NULL) {
    return NULL;
  }
  
  return pcap_open_live(dev->name, MAX_BYTES_TO_CAPTURE, PROMISC_ON, READ_TIMEOUT_MS, errbuf);
}

#pragma mark sqlite3

sqlite3 *open_database() {
  sqlite3 *db_handle = NULL;
  
	
	if(db_path != NULL) {
		CALL_SQLITE(open(db_path, &db_handle));
	}
	else {
		char *path;
		asprintf(&path, "%s%s%s", getenv("HOME"), "/", DB_NAME);
		
		CALL_SQLITE(open(path, &db_handle));
		free(path);
	}
  
  // create table if necessary
  sqlite3_exec(db_handle, CREATE_TBL_STMT, NULL, NULL, NULL);
  
  return db_handle;
}

void close_database(sqlite3 *handle) {
  sqlite3_close(handle);
}

void insert_packet_into_db(harvest *h) {
  sqlite3_stmt *stmt;
  CALL_SQLITE(prepare_v2(db_handle, INSERT_ROW_STMT, strlen(INSERT_ROW_STMT) + 1, &stmt, NULL));
  
  CALL_SQLITE(bind_int64(stmt, TIMESTAMP_BIND_IDX, h->timestamp));
  CALL_SQLITE(bind_int(stmt, TYPE_BIND_IDX, h->msg_type));
  CALL_SQLITE(bind_int(stmt, RSSI_BIND_IDX, h->rssi));
  CALL_SQLITE(bind_int(stmt, STNID_BIND_IDX, h->stn_id));
	
  char *dst;
  char *src;
  char *bssid;
  char *ssid;
  
  asprintf(&dst, "%02x:%02x:%02x:%02x:%02x:%02x", h->dst[0], h->dst[1], h->dst[2], h->dst[3], h->dst[4], h->dst[5]);
  asprintf(&src, "%02x:%02x:%02x:%02x:%02x:%02x", h->src[0], h->src[1], h->src[2], h->src[3], h->src[4], h->src[5]);
  asprintf(&bssid, "%02x:%02x:%02x:%02x:%02x:%02x", h->bssid[0], h->bssid[1], h->bssid[2], h->bssid[3], h->bssid[4], h->bssid[5]);
  
  CALL_SQLITE(bind_text(stmt, DST_BIND_IDX, dst, strlen(dst), SQLITE_STATIC));
  CALL_SQLITE(bind_text(stmt, SRC_BIND_IDX, src, strlen(src), SQLITE_STATIC));
  CALL_SQLITE(bind_text(stmt, BSSID_BIND_IDX, bssid, strlen(bssid), SQLITE_STATIC));
  
  if(h->ssid != NULL && (strlen(h->ssid) > 0) && (strlen(h->ssid) <= MAX_SSID_LEN)) {
    asprintf(&ssid, "%s", h->ssid);
    CALL_SQLITE(bind_text(stmt, SSID_BIND_IDX, ssid, strlen(ssid), SQLITE_STATIC));
    free(ssid);
  }
  else {
    CALL_SQLITE(bind_text(stmt, SSID_BIND_IDX, "", 0, SQLITE_STATIC));
  }
  
  CALL_SQLITE_EXPECT(step(stmt), DONE);
  
  free(dst);
  free(src);
  free(bssid);
}

#pragma mark packet storage functions

void *store_packets() {
  db_handle = open_database();

  while(TRUE) {
    pthread_mutex_lock(&lock);

    if(q->count > 0 && q->head != NULL) {
      insert_packet_into_db(q->head->h);
      
      q->head = remove_front(q->head);
      q->count--;
      
#ifdef LOGGING
      printf("Packet queue count (remove): %i\n", q->count);
      printf ("Primary row id was %d\n", (int)sqlite3_last_insert_rowid (db_handle));
#endif
      
      pthread_mutex_unlock(&lock);
    }
    else {
      pthread_mutex_unlock(&lock);
			
#ifdef __APPLE__
      pthread_yield_np();
#else
			pthread_yield();
#endif
			
    }
  }
  
  close_database(db_handle);
  
  return NULL;
}

#pragma mark packet capture functions

void *capture_process_packets() {
  char errbuf[PCAP_ERRBUF_SIZE];
  bpf_u_int32 netp = 0;
  bpf_u_int32 maskp = 0;
  struct bpf_program filter;          /* Place to store the BPF filter program  */
  struct pcap_pkthdr pkthdr;          /* Packet information (timestamp,size...) */
  const unsigned char *packet = NULL; /* Received raw data */
  
  unsigned long long packets_captured = 0;
  
  pcap_if_t *iface;
  if(prechosen_iface == NULL) {
    int iface_chosen = get_available_interfaces();
    if(iface_chosen == QUIT){
      exit(0);
    }
    iface = copy_interface(iface_chosen);
  }
  else {
    iface = copy_interface(prechosen_iface);
  }
  
  pcap_t *capStream = open_device(iface);
  if(capStream != NULL) {
    printf("\nOpened interface:\t%s\n", iface->name);
  }
	
	get_interface_information(iface, &netp, &maskp);
  
  pcap_set_promisc(capStream, PROMISC_ON);
  pcap_set_rfmon(capStream, PROMISC_ON);
  
  get_supported_link_types(capStream);
  
	unsigned char linkType = DLT_IEEE802_11_RADIO;
  pcap_set_datalink(capStream, linkType);
	
	// we can only apply the filter if it is wireless
	if(linkType == DLT_IEEE802_11_RADIO || linkType == DLT_IEEE802_11) {
		// compiles the filter expression into a BPF filter program
		if (pcap_compile(capStream, &filter, PROBE_REQ_FILTER, 1, PCAP_NETMASK_UNKNOWN) == -1) {
			fprintf(stderr, "ERROR: %s\n", pcap_geterr(capStream));
			exit(1);
		}
		
		// load the filter program into the packet capture device
		if (pcap_setfilter(capStream, &filter) == -1) {
			fprintf(stderr, "ERROR: %s\n", pcap_geterr(capStream));
			exit(1);
		}
	}
  
  while(TRUE){
    if ((packet = pcap_next(capStream, &pkthdr)) == NULL) {
      // most likely due to capture timeout
      fprintf(stderr, "ERROR: Error getting the packet (%s).\n", errbuf);
    }
    else {
      harvest *h = (harvest *)malloc(sizeof(harvest));
      memset(h, 0, sizeof(harvest));
      
      h->msg_type = PROBE_REQ;
      h->stn_id = station_id;
      
      struct ieee80211_radiotap_header *rh = (struct ieee80211_radiotap_header *)packet;
      
#ifdef LOGGING
      printf("\nReceived Packet Size: %d\n", pkthdr.len);
      
      // as of the current radiotap standard, version is always zero
      printf("Radiotap Version: %d\n",rh->it_version);
      
      // currently unused according to the radiotap standard
      printf("Radiotap Pad: %d\n",rh->it_pad);
      
      // indicates the entire length of the radiotap data, including the radiotap header
      printf("Radiotap Length: %d\n", rh->it_len);
#endif
      
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
      
#ifdef LOGGING
      if(BIT_SET(rh->it_present, IEEE80211_RADIOTAP_EXT)) {
        printf("more headers are available\n");
      }
#endif
      
      /* DRS */
      //struct ieee80211_radiotap_data *rt_data = (struct ieee80211_radiotap_data *)((struct ieee80211_radiotap_header *)rh + 1);
      struct ieee80211_radiotap_data *rt_data = ((u_int8_t*)rh) + sizeof(struct ieee80211_radiotap_header);
      
			if(BIT_SET(rh->it_present, IEEE80211_RADIOTAP_TSFT)) {
        // shift off the size of a radiotap header and you should be at the beginning
        // of your radiotap data
        
        h->timestamp = rt_data->tsft;
        
#ifdef LOGGING
        printf("Radiotap Timestamp: %llu\n", rt_data->tsft);
#endif
      }
      
#ifdef LOGGING
      if(BIT_SET(rh->it_present, IEEE80211_RADIOTAP_RATE)) {
        // rate is in 500 kbps
        printf("Radiotap data rate: %u Mb/s\n", TO_MBPS(rt_data->rate));
      }
#endif
      
      if(BIT_SET(rh->it_present, IEEE80211_RADIOTAP_CHANNEL)) {
        // shift off the size of a radiotap header and you should be at the beginning
        // of your radiotap data
#ifdef LOGGING
        printf("Radiotap channel: %u MHz, ", rt_data->chan_freq);
#endif
        
#ifdef LOGGING
        if(rt_data->chan_flags & IEEE80211_CHAN_2GHZ) {
          printf("2 GHz band\n");
        }
        else if(rt_data->chan_flags & IEEE80211_CHAN_5GHZ) {
          printf("5 GHz band\n");
        }
        
        if(rt_data->chan_flags & IEEE80211_CHAN_PASSIVE) {
          printf("Radiotap channel: passive\n");
        }
#endif
      }
      
      if(BIT_SET(rh->it_present, IEEE80211_RADIOTAP_DBM_ANTSIGNAL)) {
        h->rssi = rt_data->ant_signal;
        
#ifdef LOGGING
        printf("Radiotap signal: %i dBm\n", rt_data->ant_signal);
#endif
      }
      
#ifdef LOGGING
      if(BIT_SET(rh->it_present, IEEE80211_RADIOTAP_DBM_ANTNOISE)) {
        printf("Radiotap noise: %i dBm\n", rt_data->ant_noise);
      }
#endif
      
      // adding rh->it_len should get us to the very start of the 802.11 probe request
      /* DRS */
      struct ieee80211_mgmt *wh = (packet + rh->it_len);
			//ieee80211_h = (struct ieee80211_frame*) &(packet[sizeof(struct ieee80211_radiotap_header) + 1]);
      
      for(int i = 0; i < ETH_ALEN; i++) {
        h->bssid[i] = wh->bssid[i];
        h->src[i] = wh->sa[i];
        h->dst[i] = wh->da[i];
      }
      
#ifdef LOGGING
      printf("SRC: %02x:%02x:%02x:%02x:%02x:%02x\n", wh->sa[0], wh->sa[1], wh->sa[2], wh->sa[3], wh->sa[4], wh->sa[5]);
      printf("DST: %02x:%02x:%02x:%02x:%02x:%02x\n", wh->da[0], wh->da[1], wh->da[2], wh->da[3], wh->da[4], wh->da[5]);
      printf("BSSID: %02x:%02x:%02x:%02x:%02x:%02x\n", wh->bssid[0], wh->bssid[1], wh->bssid[2], wh->bssid[3], wh->bssid[4], wh->bssid[5]);
#endif
      
      // what follows seq_ctrl are some variable length data items, and in this particular case it is ssid and supported rates
      // we would only really be interested in the ssid to see that it is *not* a base-station but rather a client broadcast
      
      // the format is u_int8_t tag, u_int8_t length then some u_int8_t data for the length read in
			
			// DRS
			// data = &(packet_buffer[sizeof(struct ieee80211_radiotap_header) + 1 + sizeof(struct ieee80211_frame)]); 
      u_int8_t *tag = wh->u.probe_req.variable;
      tag++;
      
      int len = *tag;
      if(len > 0 && len <= MAX_SSID_LEN) {
        tag++;
        
#ifdef LOGGING
        printf("SSID: ");
#endif
        
        // DRS copy over the length of the SSID
        if(len <= MAX_SSID_LEN) {
          strncpy(h->ssid, (const char *)tag, len);
          // add on the null byte
          h->ssid[len] = '\0';
        }
        else {
          strncpy(h->ssid, (const char *)tag, MAX_SSID_LEN);
          // add on the null byte
          h->ssid[MAX_SSID_LEN] = '\0';
        }
        
#ifdef LOGGING
        printf("%s\n", h->ssid);
#endif
      }
      
      pthread_mutex_lock(&lock);

      node *n = create();
      memcpy(n->h, h, sizeof(harvest));
      free(h);
      
      q->head = insert_back(n, q->head);
      q->count++;
      
      pthread_mutex_unlock(&lock);
      
#ifdef LOGGING
      packets_captured++;
      printf("Packets captured thus far: %llu, \nPacket queue count (insert): %i\n", packets_captured, q->count);
#endif
    }
  }
  
  // this should never be reached
  free(iface);
  
  if(db_path != NULL) {
    free(db_path);
  }
  
  if(prechosen_iface != NULL) {
    free(prechosen_iface);
  }
  
  while(q->head->next != NULL) {
    node *prev = q->head;
    q->head = q->head->next;
    free(prev);
  }
  
  return NULL;
}

int main(int argc, const char * argv[]) {
  pthread_t store_thread;
  pthread_t capture_thread;
	
	if(getuid() != UID_ROOT) {
		printf("You must be root to run this program.\n");
		//exit(1);
	}
  
  struct ifaddrs *ifaces;
  struct ifaddrs *cur = NULL;
  if(getifaddrs(&ifaces) == 0) {
    cur = ifaces;
    
    while(cur->ifa_next != NULL) {
      if((strcmp(cur->ifa_name, EN0) == 0) && (cur->ifa_addr->sa_family == AF_LINK)) {
        const struct sockaddr_dl *dlAddr = (const struct sockaddr_dl *) cur->ifa_addr;
        const unsigned char *base = (const unsigned char *) &dlAddr->sdl_data[dlAddr->sdl_nlen];
        station_id = (u_int8_t)(base + 5);
        
        break;
      }
      cur = cur->ifa_next;
    }
    
    freeifaddrs(ifaces);
  }
  else {
    station_id = UNKNOWN_STATION_ID;
  }
	
	// parse any arguments passed to harvestd
	for(int i = 0; i < argc; i++) {
		if(strcmp(argv[i], "-f") == 0) {
			int len = strlen(argv[i + 1]);
      if(len < 1) {
        printf("You must enter a file path.\n");
        exit(1);
      }
      
			db_path = (char *)malloc(sizeof(char) * len);
			strncpy(db_path, argv[i + 1], len);
		}
    else if(strcmp(argv[i], "-i") == 0) {
			int len = strlen(argv[i + 1]);
      
      if(len < 1) {
        printf("You must enter a station ID.\n");
        exit(1);
      }
      else {
        u_int8_t id = atoi(argv[i + 1]);
        if(id < MAX_SIGNED_CHAR) {
          printf("Station ID must be between 0-255.\n");
          exit(1);
        }
        
        station_id = id;
      }
		}
    else if(strcmp(argv[i], "-n") == 0) {
      int len = strlen(argv[i + 1]);
      
      if(len < 1) {
        printf("You must enter an interface name.\n");
        exit(1);
      }
      
      prechosen_iface = (char *)malloc(sizeof(char) * len);
			strncpy(prechosen_iface, argv[i + 1], len);
		}
	}
  
  printf("Using station ID: %i.\n", station_id);
  
  pthread_mutex_init(&lock, NULL);
  
  q = (queue *)malloc(sizeof(queue));
  q->head = NULL;
  q->head = NULL;
  q->count = 0;
  
  // init the capture thread and storage threads
  if(pthread_create(&capture_thread, NULL, capture_process_packets, NULL) != 0) {
    pthread_mutex_destroy(&lock);
    printf("could not create capture thread");
    exit(1);
  }
  
  if(pthread_create(&store_thread, NULL, store_packets, NULL) != 0) {
    pthread_join(capture_thread, NULL);
    pthread_mutex_destroy(&lock);
    printf("could not create store thread");
    exit(1);
  }
  
  // wait forever for the capture thead
  pthread_join(capture_thread, NULL);
  pthread_join(store_thread, NULL);
  
  pthread_mutex_destroy(&lock);
  
  close_database(db_handle);
  free(q);

  return 0;
}