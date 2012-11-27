#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include "tslist.h"

void free_tslist(tslist_node *list){
	

	if(list == NULL){
		return;
	}

	free_tslist(list->next);
	free(list);
	
	return;
}

void add_tsnode(tslist_node *list, struct tcp_stream *a_tcp, struct timeval last){
	if(list == NULL || a_tcp == NULL)
		return;

	while(list->next != NULL)
		list = list->next;

	list->next = (tslist_node *) calloc(sizeof(tslist_node), 1);
	list->a_tcp = a_tcp;
	list->last = last;
}

struct timeval* find_ts(tslist_node* list, struct tcp_stream *a_tcp){

	if(list == NULL || a_tcp == NULL || list->a_tcp == NULL)
		return NULL;

	while(list){
		if(list->a_tcp == a_tcp)
			return &list->last;
		else
			list = list->next;
	}
	
	return NULL;
}