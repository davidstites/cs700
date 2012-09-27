CC = gcc
ARCHS = i386
LIBS = -lpcap
FLAGS := -arch $(ARCHS)
COMMON = ../common
CFLAGS := -I$(COMMON) -Iinc/radiotap -Iinc/ieee80211 -I. -std=c99 $(FLAGS)
LDFLAGS := $(FLAGS) -lpcap -lsqlite3

all: harvestd

H_SOURCE := main.c $(COMMON)/list.c
H_HEADERS := $(COMMON)/list.h $(COMMON)harvest.h $(COMMON)dstites_sqlite.h ./inc/ieee80211/ieee80211_defs.h ./inc/radiotap/radiotap.h ./inc/radiotap/dstites_radiotap.h

harvestd:  $(H_SOURCE:.c=.o)
	$(CC) $(LDFLAGS) $^ -o $@
   
%.o: %.c $(H_HEADERS)
	$(CC) $(CFLAGS) $(LIBS) -c %<

clean:
	rm *.o