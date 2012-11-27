#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>

#include "libnids-1.24/src/nids.h"
#include "colours.h"
#include "http.h"
#include <glib.h>

#define STREAM_OUT stdout

typedef struct _intercambio{
	char   *request;
	char   *response;
	int n_request_pkt;
	int n_response_pkt;
	struct timeval ts_request;
	struct timeval ts_response;
	struct _intercambio *next;
} intercambio;

typedef struct {
    intercambio *peticiones;
    intercambio *last;
    int n_peticiones;
} hash_value;

 void liberaPeticion(intercambio *peticion);
 void funcionLiberacion(gpointer data);
 char *hash_key(struct tcp_stream *a_tcp);
 char *timeval_to_char(struct timeval ts);

 

static int packets = 0;
GHashTable *table = NULL;
// static char* response = NULL;

#define int_ntoa(x)	inet_ntoa(*((struct in_addr *)&x))

// struct tuple4 contains addresses and port numbers of the TCP connexions
// the following auxiliary function produces a string looking like
// 10.0.0.1,1024,10.0.0.2,23

void how_to_use(char *app_name){
	
	fprintf(STREAM_OUT, "\nHOW TO USE\n%s <filename> \"pcap_filter\"\n\nIMPORTANT: Please write the filter in quotes (\"\")\n", app_name);
	
	fprintf(STREAM_OUT, "\nBe aware that this applies to the link-layer.\nSo filters like \"tcp dst port 23\" will NOT correctly handle fragmented traffic.\nOne should add \"or (ip[6:2] & 0x1fff != 0)\" to process all fragmented packets.\n\n");
	
	return;
}

char *timeval_to_char(struct timeval ts){

	char time_buf[64] = {0};
	char *ret = (char *) calloc(sizeof(char), 1024);

	struct tm *my_time = NULL;
	time_t nowtime;
	nowtime = ts.tv_sec;
	my_time = localtime(&nowtime);

	strftime(time_buf, 1024, "%Y-%m-%d %H:%M:%S", my_time);
	snprintf(ret, 1024, "%s %lld", time_buf, (long long) ts.tv_usec);

	return ret;
}

char * adres (struct tuple4 addr, char *direction){
  static char buf[256] = {0};
  strcpy (buf, int_ntoa (addr.saddr));
  sprintf (buf + strlen (buf), ":%i %s", addr.source, direction);
  strcat (buf, int_ntoa (addr.daddr));
  sprintf (buf + strlen (buf), ":%i ", addr.dest);
  return buf;
}

// void ip_func(struct ip * a_packet, int len){

// 	fprintf(stderr, "paqueteeeeeeeee\n");

// 	return;
// }


void tcp_callback (struct tcp_stream *a_tcp, void ** this_time_not_needed) {

	char buf[1024] = {0};
	char *received_time = NULL;
	struct half_stream *hlf_server=NULL, *hlf_client=NULL;

	packets++;

	received_time = timeval_to_char(nids_last_pcap_header->ts);
	if(received_time == NULL){
		return;
	}

	hlf_server = &a_tcp->server;
	hlf_client = &a_tcp->client;

	if(a_tcp->nids_state == NIDS_EXITING) {
		//fprintf(STREAM_OUT, COLOUR_RED "\nNIDS is closing!\n" COLOUR_NONE);
	}
	
	if(a_tcp->nids_state == NIDS_JUST_EST) {
		// connexion described by a_tcp is established
		// here we decide, if we wish to follow this stream
		// sample condition: if (a_tcp->addr.dest!=23) return;
		// in this simple app we follow each stream, so..
      a_tcp->client.collect++; // we want data received by a client
      a_tcp->server.collect++; // and by a server, too
		fprintf(STREAM_OUT, COLOUR_B_GREEN "#%d\tSYN\t" COLOUR_NONE, packets);
		fprintf(STREAM_OUT, "%s", adres(a_tcp->addr, "\t"));
		fprintf(STREAM_OUT, "\t%s\n", received_time);
	}

	if(a_tcp->nids_state == NIDS_RESET) {
		fprintf(STREAM_OUT, COLOUR_B_YELLOW "#%d\tRST\t" COLOUR_NONE, packets);
		fprintf(STREAM_OUT, "%s", adres(a_tcp->addr, "\t"));
		fprintf(STREAM_OUT, "\t%s\n", received_time);
	}
	
	if(a_tcp->nids_state == NIDS_CLOSE || a_tcp->nids_state == NIDS_EXITING) {

		fprintf(STREAM_OUT, COLOUR_B_RED "#%d\tFIN\t" COLOUR_NONE, packets);
		fprintf(STREAM_OUT, "%s\n", adres(a_tcp->addr, "\t"));
	}
	
	//LLEGA PAQUETE TCP CON PAYLOAD
	if(a_tcp->nids_state == NIDS_DATA) {

		http_packet http = NULL;
		
		if(hlf_client->count_new){ //RESPONSE
			http_parse_packet(hlf_client->data, hlf_client->count_new, &http);
		}else if(hlf_server->count_new){ //PETICION
			http_parse_packet(hlf_server->data, hlf_server->count_new, &http);
		}

		if(hlf_client->count_new && http_get_op(http) == RESPONSE){ //RESPONSE
			
			char *hashkey = hash_key(a_tcp);
			hash_value *hashvalue = NULL;
			gpointer gkey = NULL, gval = NULL;
			intercambio *peticion = NULL;
						
			g_hash_table_lookup_extended(table, hashkey, &gkey, &gval);
			hashvalue = (hash_value *) gval;
			
			if(hashvalue != NULL){
				peticion = hashvalue->last;
				if(hlf_client->offset == 0)
					peticion->ts_response = nids_last_pcap_header->ts;
				peticion->response = (char *) realloc(peticion->response, hlf_client->offset+hlf_client->count_new);
				strncpy(peticion->response+hlf_client->offset, hlf_client->data, hlf_client->count_new);
				peticion->n_response_pkt = packets;
			}else{
				fprintf(STREAM_OUT, COLOUR_B_RED "RESPONSE WITHOUT REQUEST!! \t%d\t%s\n" COLOUR_NONE, packets, hashkey);
				free(received_time);
				return;
			}
			
			g_hash_table_steal(table, hashkey);			
			g_hash_table_insert(table, gkey, hashvalue);
			free(hashkey);

			struct timeval time_last = hashvalue->last->ts_request;
			struct timeval res;
			timersub(&nids_last_pcap_header->ts, &time_last, &res);

			char *received_rq_time = timeval_to_char(time_last);
			http_packet http_request = NULL;
			http_parse_packet(hashvalue->last->request, strlen(hashvalue->last->request), &http_request);

			fprintf(STREAM_OUT, "———————————————————————————————————————————————————————————————————————————————————————————————————————————\n");
			fprintf(STREAM_OUT, COLOUR_B_BLUE "#%d\t%s\t" COLOUR_NONE, hashvalue->last->n_request_pkt, http_get_method(http_request));
			fprintf(STREAM_OUT, "%s:%u\t", int_ntoa (a_tcp->addr.saddr), a_tcp->addr.source);
			fprintf(STREAM_OUT, "%s:%u", int_ntoa (a_tcp->addr.daddr), a_tcp->addr.dest);
			fprintf(STREAM_OUT, "\t%s\n", received_rq_time);

			fprintf(STREAM_OUT, COLOUR_B_BLUE "#%d\tDATA\t" COLOUR_NONE, packets);
			fprintf(STREAM_OUT, "%s:%u\t", int_ntoa (a_tcp->addr.daddr), a_tcp->addr.dest);
			fprintf(STREAM_OUT, "%s:%u ", int_ntoa (a_tcp->addr.saddr), a_tcp->addr.source);
			fprintf(STREAM_OUT, "\t%s\t%ld.%ld\n", received_time, res.tv_sec, res.tv_usec);

			strcpy (buf, adres (a_tcp->addr, "<==")); // we put conn params into buf

			free(received_rq_time);
			http_free_packet(&http_request);
			
		}else if(hlf_server->count_new && http_get_op(http) == GET){ //PETICION
			
			//fprintf(STREAM_OUT, COLOUR_B_BLUE "#%d\t%s\t" COLOUR_NONE, packets, http_get_method(http));

			//HASH TABLE
			char *hashkey = hash_key(a_tcp);
			hash_value *hashvalue = NULL;
			gpointer gkey = NULL, gval = NULL;
			g_hash_table_lookup_extended(table, hashkey, &gkey, &gval);
			hashvalue = (hash_value *) gval;
			intercambio *peticion = NULL;
			if(hashvalue == NULL){ //si no existe creo una nueva entrada en la tabla;
				hashvalue = (hash_value *) calloc(sizeof(hash_value), 1);
				hashvalue->n_peticiones = 1;
				hashvalue->peticiones = (intercambio *) calloc(sizeof(intercambio), 1);
				hashvalue->last = hashvalue->peticiones;
			}else{ //si existe, añado un nuevo nodo a la lista enlazada "peticiones"
				g_hash_table_steal(table, hashkey);		
				hashvalue->last->next = (intercambio *) calloc(sizeof(intercambio), 1);
				hashvalue->n_peticiones++;
				hashvalue->last = hashvalue->last->next;
			}
			
			peticion = hashvalue->last;
			peticion->ts_request = nids_last_pcap_header->ts;
			peticion->request = (char *) calloc(sizeof(char), hlf_server->count_new);
			peticion->response = NULL;
			peticion->n_request_pkt = packets;
			strncpy(peticion->request, hlf_server->data, hlf_server->count_new);

			g_hash_table_insert(table, hashkey, hashvalue);
			
			if(gkey != NULL)
				free(gkey);
			
			strcpy (buf, adres (a_tcp->addr, "==>")); // we put conn params into buf

		}//FIN DE BLOQUE TCP_DATA
		http_free_packet(&http);
	}
	
	//fprintf(STREAM_OUT, "%s\n", buf);
	free(received_time);
	//nids_discard(a_tcp, 0);
	
  return;
}

int main(int argc, char *argv[]){
	
  // here we can alter libnids params, for instance:

	nids_params.filename = argv[1];
	nids_params.pcap_filter = argv[2];
	nids_params.device = NULL; 

  if(argc!=3){
  	how_to_use(argv[0]);
  	return 1;
  }

  table = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, funcionLiberacion);
  if(table == NULL){
  	fprintf(STREAM_OUT, "Error al crear tabla hash.");
  	return -1;
  }


  if (!nids_init ()){
  	fprintf(STREAM_OUT,"Error nids_init. %s\n",nids_errbuf);
	g_hash_table_destroy(table);
  	return -2;
  }

  // nids_register_ip(ip_func);
  // nids_run();
  // nids_unregister_ip(ip_func);

  nids_register_tcp (tcp_callback);
  nids_run ();
  nids_unregister_tcp(tcp_callback);

  g_hash_table_destroy(table);

  return 0;

}

 char *hash_key(struct tcp_stream *a_tcp){

   char *buf = (char*) calloc(45, sizeof(char));
   sprintf(buf, "%s%i", int_ntoa(a_tcp->addr.saddr), a_tcp->addr.source);
   sprintf(buf, "%s%s%i", buf, int_ntoa(a_tcp->addr.daddr), a_tcp->addr.dest);
   return buf;

}

void funcionLiberacion(gpointer data){
	
	if(data == NULL) return;

	hash_value *hashvalue = (hash_value *) data;
	
	if(hashvalue == NULL) return;

	liberaPeticion(hashvalue->peticiones);

	hashvalue->peticiones = NULL;
	hashvalue->last = NULL;
	
	free(hashvalue);

	return;
}

void liberaPeticion(intercambio *peticion){

	if(peticion == NULL){
		return;
	}

	if(peticion->request != NULL){
		free(peticion->request);
	}

	if(peticion->response != NULL){
		free(peticion->response);
	}

	liberaPeticion(peticion->next);

	free(peticion);

	return;
}
