CC = gcc
LIBS = -lpcap -lsqlite3 -lpthread
FLAGS := -D_GNU_SOURCE -Os
COMMON = ../common
CFLAGS := -I$(COMMON) -Iinc/radiotap -Iinc/ieee80211 -I. -std=gnu99 $(FLAGS)
LDFLAGS := $(FLAGS) $(LIBS)

all: harvestd

H_SOURCE := main.c $(COMMON)/list.c
H_HEADERS := $(COMMON)/list.h $(COMMON)harvest.h $(COMMON)dstites_sqlite.h ./inc/ieee80211/ieee80211_defs.h ./inc/radiotap/radiotap.h ./inc/radiotap/dstites_radiotap.h

harvestd:  $(H_SOURCE:.c=.o)
	$(CC) $(LDFLAGS) $^ -o $@
   
%.o: %.c $(H_HEADERS)
	$(CC) $(CFLAGS) $(LIBS) -c %<

clean:
	rm -rf *.o harvestd $(COMMON)/*.o