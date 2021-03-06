//
//  list.c
//  harvestd
//
//  Created by David R. Stites on 9/24/12.
//
//

#include "list.h"

node *create() {  
  node *n;
  
  n = (node *)malloc(sizeof(node));
  if(!n) {
    return NULL;
  }
  
  n->next = NULL;
  
  n->h = (harvest *)malloc(sizeof(harvest));
  memset(n->h, 0, sizeof(harvest));
  
	return n;
}

node *insert_back(node *newNode, node *head) {
  if(newNode == NULL) {
    return NULL;
  }
  
  if(head == NULL) {
    head = newNode;
    return head;
  }
  
  node *cur = head;
  while(cur->next != NULL) {
    cur = cur->next;
  }
  
  cur->next = newNode;
  
  return head;
}

node *remove_front(node *head) {
  if(head == NULL) {
    return NULL;
  }
  
  node *oldHead = head;
  head = head->next;
  
  free(oldHead->h);
  free(oldHead);
  
  return head;
}