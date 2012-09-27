all: harvestd

harvestd: harvest-main.o
	gcc harvest-main.o -o harvestd

harvest-main.o: harvest/main.c
	gcc harvest/main.h harvest/main.c