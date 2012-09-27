all: harvestd

harvestd: harvest-main.o
	gcc harvest-main.o -o harvestd

harvest-main.o: harvest/main.c common.h list.h list.c
	cd harvest;
	gcc main.c
	

	
clean:
	rm *.o