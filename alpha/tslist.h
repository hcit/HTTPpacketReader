#ifndef _tslist
#define _tslist

#include <time.h>
#include <nids.h>

typedef struct _tslist_node {
    struct _tslist_node* next;
    struct tcp_stream *a_tcp;
    struct timeval last;
} tslist_node;

void free_tslist(tslist_node *list);
void add_tsnode(tslist_node *list, struct tcp_stream *a_tcp, struct timeval last);
struct timeval* find_ts(tslist_node *list, struct tcp_stream *a_tcp);

#endif
