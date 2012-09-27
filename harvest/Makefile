CC = gcc
ARCHS = i386
LIBS = -lpcap
CFLAGS = -I../ -I. -std=c99 -arch $(ARCHS)
LDFLAGS =

all: harvestd

H_SOURCE = main.c list.c

harvestd:  $(H_SOURCE:.c=.o)
	gcc $^ -o harvestd
   
list.o: list.h harvest.h list.c
    $(CC) $(CFLAGS) $(LIBS) -c list.c

main.o: common.h list.h list.c main.c
    $(CC) $(CFLAGS) $(LIBS) -c main.c