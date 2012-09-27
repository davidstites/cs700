//
//  list.h
//  harvest
//
//  Created by David R. Stites on 9/24/12.
//
//

#ifndef harvest_list_h
#define harvest_list_h

#import <string.h>
#import <stdlib.h>
#import <pthread.h>

#import "harvest.h"

typedef struct node {
  harvest *h;
  struct node *next;
} node;

typedef struct queue {
  node *head;
  //node *tail;
  unsigned int count;
} queue;

node *create();
node *insert_back(node *newNode, node *head);
node *remove_front(node *head);

#endif
