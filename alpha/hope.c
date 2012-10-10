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

#include "nids.h"
#include "colours.h"
#include "http.h"
#include "tslist.h"
#include <glib.h>

typedef struct _intercambio{
	char   *request;
	char   *response;
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
static tslist_node *tslist = NULL;
GHashTable *table = NULL;
// static char* response = NULL;

#define int_ntoa(x)	inet_ntoa(*((struct in_addr *)&x))

// struct tuple4 contains addresses and port numbers of the TCP connexions
// the following auxiliary function produces a string looking like
// 10.0.0.1,1024,10.0.0.2,23

void how_to_use(char *app_name){
	
	fprintf(stderr, "\nHOW TO USE\n%s <filename> \"pcap_filter\"\nIMPORTANT: Please write the filter in quotes (\"\")\n", app_name);
	
	fprintf(stderr, "\nBe aware that this applies to the link-layer.\nSo filters like \"tcp dst port 23\" will NOT correctly handle fragmented traffic.\nOne should add \"or (ip[6:2] & 0x1fff != 0)\" to process all fragmented packets.\n\n");
	
	return;
}

char *timeval_to_char(struct timeval ts){
	char time_buf[32] = {0};
	char *ret = (char*) calloc(sizeof(char), 256);
	
	time_t nowtime = ts.tv_sec;
	struct tm *my_time = localtime(&nowtime); 
	strftime(time_buf, sizeof time_buf, "%Y-%m-%d %H:%M:%S", my_time);
	sprintf(ret, "%s.%ld", time_buf, ts.tv_usec);
	return ret;
}

char * adres (struct tuple4 addr, char *direction){
  static char buf[256];
  strcpy (buf, int_ntoa (addr.saddr));
  sprintf (buf + strlen (buf), ":%i %s ", addr.source, direction);
  strcat (buf, int_ntoa (addr.daddr));
  sprintf (buf + strlen (buf), ":%i ", addr.dest);
  return buf;
}

void tcp_callback (struct tcp_stream *a_tcp, void ** this_time_not_needed) {

	if(tslist == NULL){
		tslist = (tslist_node *) calloc(sizeof(tslist_node), 1);
	}

	packets++;
	char buf[1024] = {0};
	char *received_time = timeval_to_char(nids_last_pcap_header->ts);
	fprintf(stderr, COLOUR_B_BLUE "\nPacket #%d " COLOUR_NONE "received at %s\n" , packets, received_time);
	struct half_stream *hlf_server = &a_tcp->server, *hlf_client = &a_tcp->client;

	if(a_tcp->nids_state == NIDS_EXITING) {
		fprintf(stderr, COLOUR_RED "\nNIDS is closing!\n" COLOUR_NONE);
		//fprintf(stderr, "RESPONSE!!!!!!!!!!!! ======= \n%s", response);
		// g_hash_table_remove(table, hash_key(a_tcp));
		//free(response);
		// g_hash_table_destroy(table);
	}
	
	if(a_tcp->nids_state == NIDS_JUST_EST) {
		// connexion described by a_tcp is established
		// here we decide, if we wish to follow this stream
		// sample condition: if (a_tcp->addr.dest!=23) return;
		// in this simple app we follow each stream, so..
      a_tcp->client.collect++; // we want data received by a client
      a_tcp->server.collect++; // and by a server, too
		fprintf(stderr, COLOUR_B_GREEN "SYN\t" COLOUR_NONE);
	}
	if(a_tcp->nids_state == NIDS_RESET) {
		fprintf(stderr, COLOUR_B_YELLOW "RST\t" COLOUR_NONE);
	}
	
	if(a_tcp->nids_state == NIDS_CLOSE || a_tcp->nids_state == NIDS_EXITING) {
		fprintf(stderr, COLOUR_B_RED "FIN\t" COLOUR_NONE);
		char *key = hash_key(a_tcp);
		hash_value *dato = (hash_value *) g_hash_table_lookup(table, key);
		if(dato == NULL){
			fprintf(stderr, "NULL\n");
		}else{
			char *time_val = timeval_to_char(dato->peticiones->ts_response);
			//fprintf(stderr, "REQUEST:\n |%s|\n|%s|\n", dato->peticiones->request, time_val);
			//fprintf(stderr, "RESPONSE:\n |%s|\n", dato->peticiones->response);
			free(time_val);
		}
		free(key);
	}
	
	if(a_tcp->nids_state == NIDS_DATA) {

		fprintf(stderr, COLOUR_B_BLUE "DATA\t" COLOUR_NONE);
		//fprintf(stderr, "New data length. Server: %d - Client: %d\n", hlf_server->count_new, hlf_client->count_new);

		http_packet http_server = NULL, http_client = NULL;
		
		if(hlf_client->count_new){ //RESPONSE
			char *hashkey = hash_key(a_tcp);
			hash_value *hashvalue = NULL;
			gpointer gkey = NULL, gval = NULL;
			g_hash_table_lookup_extended(table, hashkey, &gkey, &gval);
			hashvalue = (hash_value *) gval;
			intercambio *peticion = NULL;
			if(hashvalue != NULL){
				peticion = hashvalue->last;
				if(hlf_client->offset == 0)
					peticion->ts_response = nids_last_pcap_header->ts;
				peticion->response = (char *) realloc(peticion->response, hlf_client->offset+hlf_client->count_new);
				strncpy(peticion->response+hlf_client->offset, hlf_client->data, hlf_client->count_new);
			}
			
			g_hash_table_steal(table, hashkey);			
			g_hash_table_insert(table, gkey, hashvalue);
			free(hashkey);

			struct timeval* time_last = find_ts(tslist, a_tcp);
			struct timeval res;
			timersub(&nids_last_pcap_header->ts, time_last, &res);

			fprintf(stderr, "%s:%u\t%s:%u ", int_ntoa (a_tcp->addr.daddr), a_tcp->addr.dest, int_ntoa (a_tcp->addr.saddr), a_tcp->addr.source);
			fprintf(stderr, "\t%s\t%ld.%ld\n", received_time, res.tv_sec, res.tv_usec);
			strcpy (buf, adres (a_tcp->addr, "<==")); // we put conn params into buf
			/*int ret = */http_parse_packet(hlf_client->data, hlf_client->count_new, &http_client);
			// if(ret != -1){
			// 	fprintf(stderr, "\n------> ///////////// ========= |%s|", find("Transfer-Encoding", http_get_headers(http_client)->fields));
			// }

			/*fprintf(stderr, "%s\n", http_get_version(http_client));
			fprintf(stderr, "%d\n", http_get_response_code(http_client));
			fprintf(stderr, "%s\n", http_get_response_msg(http_client));
			http_print_headers(&http_client);*/
			
			//write(1, hlf_client->data, hlf_client->count_new);
			fprintf(stderr, "%d - %d - %d\n", hlf_client->offset, hlf_client->count, hlf_client->count_new);
			http_free_packet(&http_client);

			// response = (char *) realloc(response, hlf_client->count);
			// memcpy(response+hlf_client->offset, hlf_client->data, hlf_client->count_new);

		}else if(hlf_server->count_new){ //PETICION

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
			strncpy(peticion->request, hlf_server->data, hlf_server->count_new);

			g_hash_table_insert(table, hashkey, hashvalue);
			
			if(gkey != NULL)
				free(gkey);

			// strcpy(hashvalue->peticiones->response, "respuesta");

			add_tsnode(tslist, a_tcp, nids_last_pcap_header->ts);
			fprintf(stderr, "%s:%u\t%s:%u ", int_ntoa (a_tcp->addr.saddr), a_tcp->addr.source, int_ntoa (a_tcp->addr.daddr), a_tcp->addr.dest);
			fprintf(stderr, "\t%s\n", received_time);
			//fprintf(stderr, "Total data length. Server: %d - Client: %d\n", hlf_server->count, hlf_client->count);
			http_parse_packet(hlf_server->data, hlf_server->count_new, &http_server);
			/*fprintf(stderr, "%s\n", http_get_method(http_server));
			fprintf(stderr, "%s\n", http_get_host(http_server));
			fprintf(stderr, "%s\n", http_get_uri(http_server));
			fprintf(stderr, "%s\n\n\n", http_get_version(http_server));*/
			//write(1, hlf_server->data, hlf_server->count_new);
			fprintf(stderr, "%d - %d - %d\n", hlf_server->offset, hlf_server->count, hlf_server->count_new);
			http_free_packet(&http_server);
			strcpy (buf, adres (a_tcp->addr, "==>")); // we put conn params into buf
		}
	}else{
		fprintf(stderr, "%s:%u\t%s:%u", int_ntoa (a_tcp->addr.saddr), a_tcp->addr.source, int_ntoa (a_tcp->addr.daddr), a_tcp->addr.dest);	
		fprintf(stderr, "\t%s\n", received_time);
	}
	
	fprintf(stderr, "%s\n", buf);
	free(received_time);
	//nids_discard(a_tcp, 0);
	
  return;
}

int main(int argc, char *argv[]){
	
  // here we can alter libnids params, for instance:
	nids_params.filename = argv[1];
	nids_params.device = NULL;

  table = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, funcionLiberacion);
  if(table == NULL){
  	fprintf(stderr, "Error al crear tabla hash.");
  	return -1;
  }


  if (!nids_init ()){
  	fprintf(stderr,"Error nids_init. %s\n",nids_errbuf);
  	exit(1);
  }
 

  nids_register_tcp (tcp_callback);
  nids_run ();
  nids_unregister_tcp(tcp_callback);
  free_tslist(tslist);


  g_hash_table_destroy(table);

  return 0;

}

 char *hash_key(struct tcp_stream *a_tcp){

   char *buf = (char*) calloc(45, sizeof(char));
   sprintf(buf, "%s%i%s%i", int_ntoa(a_tcp->addr.saddr), a_tcp->addr.source, int_ntoa(a_tcp->addr.daddr), a_tcp->addr.dest);
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











