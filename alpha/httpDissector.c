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


typedef struct _intercambio{
	char   *request;
	char   *response;
	int request_bytes;
	int response_bytes;
	int chunks;
	int n_request_pkt;
	int n_response_pkt;
	struct timeval ts_request;
	struct timeval ts_response;
	struct timeval ts_last_response;
	struct _intercambio *next;
	struct _intercambio *prev;
} intercambio;

typedef struct {
    intercambio *peticiones;
    intercambio *last;
    intercambio **array;
    int n_peticiones;
    int n_respuestas;
} hash_value;

 void liberaPeticion(intercambio *peticion);
 void funcionLiberacion(gpointer data);
 char *hash_key(struct tcp_stream *a_tcp);
 char *timeval_to_char(struct timeval ts);

FILE *stream_out;
FILE *file_out = NULL;

static int running = 0;
static int packets = 0;
static unsigned long pcap_position = 0;
static unsigned long pcap_size = 0;
GHashTable *table = NULL;
static GMutex *table_mutex = NULL;
GThread *recolector =  NULL;
GThread *progreso =  NULL;

struct timeval start, aux_exec; 

// static char* response = NULL;

#define int_ntoa(x)	inet_ntoa(*((struct in_addr *)&x))

// struct tuple4 contains addresses and port numbers of the TCP connexions
// the following auxiliary function produces a string looking like
// 10.0.0.1,1024,10.0.0.2,23



void how_to_use(char *app_name){
	
	fprintf(stream_out, "\nHOW TO USE\n%s <filename> \"pcap_filter\"\n\nIMPORTANT: Please write the filter in quotes (\"\")\n", app_name);
	
	fprintf(stream_out, "\nBe aware that this applies to the link-layer.\nSo filters like \"tcp dst port 23\" will NOT correctly handle fragmented traffic.\nOne should add \"or (ip[6:2] & 0x1fff != 0)\" to process all fragmented packets.\n\n");
	
	return;
}

char *timeval_to_char(struct timeval ts){

	char time_buf[64] = {0};
	char *ret = (char *) calloc(sizeof(char), 1024);

	time_t nowtime;
	nowtime = ts.tv_sec;

	//UTC TIME
	struct tm *my_time = gmtime(&nowtime);
	strftime(time_buf, 64, "%Y-%m-%d %H:%M:%S", my_time);
	snprintf(ret, 1024, "%s %ld", time_buf, ts.tv_usec);
	
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

gboolean hash_check_time (gpointer key, gpointer value, gpointer user_data){
  hash_value *hashvalue = (hash_value *) value;

  if(hashvalue!=NULL){
  		struct timeval res_peticion;
  		struct timeval res_respuesta;
		timersub(&nids_last_pcap_header->ts, &hashvalue->last->ts_request, &res_peticion);
		timersub(&nids_last_pcap_header->ts, &hashvalue->last->ts_last_response, &res_respuesta);
  	if(res_peticion.tv_sec > 60 && res_respuesta.tv_sec > 60){
  		// fprintf(stderr, "(%d)\t(%ld,%ld)\t(%ld,%ld)\t|%.50s|\n", hashvalue->n_peticiones, hashvalue->last->ts_request.tv_sec, hashvalue->last->ts_request.tv_usec, hashvalue->last->ts_last_response.tv_sec, hashvalue->last->ts_last_response.tv_usec, hashvalue->peticiones->request);
  		// fprintf(stderr, "YEAH! - (%ld,%ld) (%ld,%ld)", res_respuesta.tv_sec, res_respuesta.tv_usec, nids_last_pcap_header->ts.tv_sec, nids_last_pcap_header->ts.tv_usec);
  		
  		return TRUE;
  	}else if(res_peticion.tv_sec > 60 && hashvalue->last->request == NULL){
  		// fprintf(stderr, "(%d)\t(%ld,%ld)\t(%ld,%ld)\t|%.50s|\n", hashvalue->n_peticiones, hashvalue->last->ts_request.tv_sec, hashvalue->last->ts_request.tv_usec, hashvalue->last->ts_last_response.tv_sec, hashvalue->last->ts_last_response.tv_usec, hashvalue->peticiones->request);
  		// fprintf(stderr, "YEAH2! - (%ld,%ld) ", res_peticion.tv_sec, res_peticion.tv_usec);
  		
  		
  		return TRUE;
  	}

  	//fprintf(stderr, "(%d) (%d)\t(%ld,%ld)\t(%ld,%ld)\t|%.50s|\n", hashvalue->n_peticiones, hashvalue->last->chunks, hashvalue->last->ts_request.tv_sec, hashvalue->last->ts_request.tv_usec, hashvalue->last->ts_last_response.tv_sec, hashvalue->last->ts_last_response.tv_usec, hashvalue->peticiones->request);

  }

  return FALSE;

}

// Process has done x out of n rounds,
// and we want a bar of width w and resolution r.
static inline void loadBar(unsigned long x, unsigned long n, int r, int w)
{
 
  struct timeval elapsed;
  char elapsed_time[30] = {0};
  struct tm *my_time = NULL;

  	// Only update r times.
    if ( x % (n/r) != 0 ) return;
 
    // Calculuate the ratio of complete-to-incomplete.
    float ratio = x/(float)n;
    int   c     = ratio * w;
 
    // Show the percentage complete. 
    fprintf(stderr, "%3.0d%% [", ((int)(ratio*100)));

    int i=0;

    // Show the load bar.
    for (i=0; i<c; i++)
       fprintf(stderr, "=");
 
    for (i=c; i<w; i++)
       fprintf(stderr, " ");

   fprintf(stderr, "]");

   	gettimeofday(&aux_exec, NULL);  
  	timersub(&aux_exec, &start, &elapsed);
  	my_time = gmtime(&elapsed.tv_sec);
  	strftime(elapsed_time, 30, "%X", my_time);
  	fprintf(stderr, " Elapsed Time: (%ld %s)", (elapsed.tv_sec/86400), elapsed_time);
 
    // ANSI Control codes to go back to the
    // previous line and clear it.
    fprintf(stderr, "\n\033[F");
    fprintf(stderr, "\r");
    fflush(stderr);


}


GThreadFunc recolector_de_basura(){ 
	sleep(10);
	while(running){
	 	g_mutex_lock (table_mutex);
	 	//fprintf(stderr, "==============================\nNp\tTSp\t\t\tTSlr\t\t\tDATA\n");
	 	g_hash_table_foreach_remove(table, hash_check_time, NULL);
	 	//fprintf(stderr, "==============================\n\n");
	 	g_mutex_unlock (table_mutex);
	 	sleep(10);
	}
	return NULL;
}

GThreadFunc barra_de_progreso(){
	FILE *pcap = NULL;
	while(running && nids_params.pcap_desc != NULL){
		pcap = pcap_file(nids_params.pcap_desc);
		if(pcap == 0) break;
		pcap_position = ftell(pcap);
		if(pcap_position == -1L) break;
		loadBar(pcap_position, pcap_size, pcap_size, 40);
		usleep(500000);
	}
	
	return NULL;
}

// void ip_func(struct ip * a_packet, int len){

// 	fprintf(stderr, "paqueteeeeeeeee\n");

// 	return;
// }

intercambio *get_n_intercambio(intercambio **i, int n, int t){

	if (i == NULL || n > t || n<=0){
		return NULL;
	}

	return i[n-1];
}


void tcp_callback (struct tcp_stream *a_tcp, void ** this_time_not_needed) {

	g_mutex_lock (table_mutex);
	char buf[1024] = {0};
	char *received_time = NULL;
	struct half_stream *hlf_server=NULL, *hlf_client=NULL;

	packets++;

	received_time = timeval_to_char(nids_last_pcap_header->ts);

	hlf_server = &a_tcp->server;
	hlf_client = &a_tcp->client;

	// if(a_tcp->nids_state == NIDS_EXITING) {
	// 	fprintf(stream_out, COLOUR_RED "\nNIDS is closing!\n" COLOUR_NONE);
	// }else 

	if(a_tcp->nids_state == NIDS_JUST_EST) {
		// connexion described by a_tcp is established
		// here we decide, if we wish to follow this stream
		// sample condition: if (a_tcp->addr.dest!=23) return;
		// in this simple app we follow each stream, so..
      	a_tcp->client.collect++; // we want data received by a client
      	a_tcp->server.collect++; // and by a server, too
		fprintf(stream_out, COLOUR_B_GREEN "#%d\tSYN\t" COLOUR_NONE, packets);
		fprintf(stream_out, "%s", adres(a_tcp->addr, "\t"));
		fprintf(stream_out, "\t%s\n", received_time);
	}else if(a_tcp->nids_state == NIDS_RESET) {
		fprintf(stream_out, COLOUR_B_YELLOW "#%d\tRST\t" COLOUR_NONE, packets);
		fprintf(stream_out, "%s", adres(a_tcp->addr, "\t"));
		fprintf(stream_out, "\t%s\n", received_time);
	}else if(a_tcp->nids_state == NIDS_CLOSE || a_tcp->nids_state == NIDS_EXITING) {
		
		fprintf(stream_out, COLOUR_B_RED "#%d\tFIN\t" COLOUR_NONE, packets);
		fprintf(stream_out, "%s\n", adres(a_tcp->addr, "\t"));
		
		char *clave_hash = hash_key(a_tcp);
		g_hash_table_remove(table, clave_hash);
		

		if(clave_hash != NULL){
			free(clave_hash);
		}
		
		a_tcp->client.collect--;
		a_tcp->server.collect--;

 	//LLEGA PAQUETE TCP CON PAYLOAD
	}else if(a_tcp->nids_state == NIDS_DATA) { 	

/***      PACKETES TCP CON PAYLOAD
 *
 *    |¯¯¯¯\    /¯¯¯¯¯| |¯¯¯¯¯|   /¯¯¯¯¯| 
 *    |  x  \  /  !   | |     |  /  !   | 
 *    |_____/ /__/¯|__'  ¯|_|¯  /__/¯|__| 
 */

		http_packet http = NULL;
		
		if(hlf_client->count_new){ //RESPONSE
			// fprintf(stderr, COLOUR_B_YELLOW "\n|%s - (%u, %u, %u, %d)|\n" COLOUR_NONE, received_time, hlf_client->seq, hlf_client->ack_seq, hlf_client->curr_ts, hlf_client->count_new);
			// fprintf(stderr, "|");
			// write(2, hlf_client->data, 130);
			// fprintf(stderr, "|\n" );
			http_parse_packet(hlf_client->data, hlf_client->count_new, &http);
		}else if(hlf_server->count_new){ //PETICION
			// fprintf(stderr, COLOUR_B_GREEN "\n|%s - (%u, %u, %u, %d)|\n" COLOUR_NONE, received_time, hlf_server->seq, hlf_server->ack_seq, hlf_server->curr_ts, hlf_server->count_new);
			// fprintf(stderr, "|");
			// write(2, hlf_server->data, 130);
			// fprintf(stderr, "|\n" );
			http_parse_packet(hlf_server->data, hlf_server->count_new, &http);
		}

		//RESPUESTA Y QUE COINCIDA QUE ES PRIMER PAQUETE DE RESPUESTA
		if(hlf_client->count_new && http_get_op(http) == RESPONSE){ //RESPONSE

			char *hashkey = hash_key(a_tcp);
			hash_value *hashvalue = NULL;
			gpointer gkey = NULL, gval = NULL;
			intercambio *peticion = NULL;
			g_hash_table_lookup_extended(table, hashkey, &gkey, &gval);
			
			hashvalue = (hash_value *) gval;
			
			//Si hay una entrada en la tabla hash
			if(hashvalue != NULL){
				//peticion = hashvalue->last;
				hashvalue->n_respuestas++;
				//Obtener el par peticion/respuesta correspondiente
				peticion = get_n_intercambio(hashvalue->array, hashvalue->n_respuestas, hashvalue->n_peticiones);
				if(peticion==NULL){
					fprintf(stream_out, COLOUR_B_RED "ERROR OBTAINING REQUEST!! \t%d\t" COLOUR_NONE, packets);
					fprintf(stream_out, "%s:%u\t", int_ntoa (a_tcp->addr.daddr), a_tcp->addr.dest);
					fprintf(stream_out, "%s:%u ", int_ntoa (a_tcp->addr.saddr), a_tcp->addr.source);
					fprintf(stream_out, "\t%s\n", received_time);
					free(hashkey);
					free(received_time);
					g_mutex_unlock (table_mutex);
					return;
				}
				//Copiar timestamp
				peticion->ts_response = nids_last_pcap_header->ts;
				peticion->ts_last_response = nids_last_pcap_header->ts;
				peticion->chunks += 1;
				//copiar los datos de la respuesta a la estructura
				// ===================================
				//DESCARTADOS PARA AHORRAR MEMORIA
				peticion->response = (char *) realloc(peticion->response, hlf_client->count_new);
				strncpy(peticion->response, hlf_client->data, hlf_client->count_new);
				//FIN DESCARTADOS PARA AHORRAR MEMORIA
				// ===================================
				peticion->n_response_pkt = packets;
				peticion->response_bytes = hlf_client->count_new;
			}else{ //NO HAY ENTRADA EN LA TABLA HASH
				fprintf(stream_out, COLOUR_B_RED "RESPONSE WITHOUT REQUEST!! \t%d\t" COLOUR_NONE, packets);
				fprintf(stream_out, "%s:%u\t", int_ntoa (a_tcp->addr.daddr), a_tcp->addr.dest);
				fprintf(stream_out, "%s:%u ", int_ntoa (a_tcp->addr.saddr), a_tcp->addr.source);
				fprintf(stream_out, "\t%s\n", received_time);
				free(hashkey);
				free(received_time);
				g_mutex_unlock (table_mutex);
				return;
			}

			g_hash_table_steal(table, hashkey);			
			g_hash_table_insert(table, gkey, hashvalue);
			
			free(hashkey);

			//Datos de la peticion
			http_packet http_request = NULL;
			
			http_parse_packet(peticion->request, peticion->request_bytes, &http_request);

			//Preparacion para imprimir los datos y tiempos junto con el RTT
			struct timeval time_last = peticion->ts_request;
			struct timeval res;
			timersub(&nids_last_pcap_header->ts, &time_last, &res);

			char *received_rq_time = timeval_to_char(time_last);

			fprintf(stream_out, "———————————————————————————————————————————————————————————————————————————————————————————————————————\n");
			fprintf(stream_out, COLOUR_B_BLUE "#%d\t%s\t" COLOUR_NONE, peticion->n_request_pkt, http_get_method(http_request));
			fprintf(stream_out, "%s:%u\t", int_ntoa (a_tcp->addr.saddr), a_tcp->addr.source);
			fprintf(stream_out, "%s:%u", int_ntoa (a_tcp->addr.daddr), a_tcp->addr.dest);
			fprintf(stream_out, "\t%s\n", received_rq_time);

			fprintf(stream_out, COLOUR_B_BLUE "#%d\tDATA\t" COLOUR_NONE, packets);
			fprintf(stream_out, "%s:%u\t", int_ntoa (a_tcp->addr.daddr), a_tcp->addr.dest);
			fprintf(stream_out, "%s:%u ", int_ntoa (a_tcp->addr.saddr), a_tcp->addr.source);
			fprintf(stream_out, "\t%s\t%ld.%ld\n", received_time, res.tv_sec, res.tv_usec);
			fprintf(stream_out, "———————————————————————————————————————————————————————————————————————————————————————————————————————\n");

			strcpy (buf, adres (a_tcp->addr, "<==")); // we put conn params into buf

			if(peticion->prev != NULL){
				if(timercmp(&peticion->ts_response, &peticion->prev->ts_response, ==)){
					fprintf(stream_out, COLOUR_B_RED "Possible packet reordering due to an unordered response.\n" COLOUR_NONE);
				}
			}

			free(received_rq_time);
			http_free_packet(&http_request);

		}else if(hlf_client->count_new){ 
		//Paquete TCP con datos. Es la continuacion a una respuesta anterior
		//Se concatenan los datos

			//Comprobar que la entrada en la tabla hash existe
			char *hashkey = hash_key(a_tcp);
			hash_value *hashvalue = NULL;
			gpointer gkey = NULL, gval = NULL;
			intercambio *peticion = NULL;

			g_hash_table_lookup_extended(table, hashkey, &gkey, &gval);
			
			hashvalue = (hash_value *) gval;
			
			//Si hay una entrada en la tabla hash
			if(hashvalue != NULL){
				//Obtener el par peticion/respuesta correspondiente
				peticion = get_n_intercambio(hashvalue->array, hashvalue->n_respuestas, hashvalue->n_peticiones);
				if(peticion==NULL){
					fprintf(stream_out, COLOUR_B_RED "ERROR OBTAINING REQUEST!! \t%d\t" COLOUR_NONE, packets);
					fprintf(stream_out, "%s:%u\t", int_ntoa (a_tcp->addr.daddr), a_tcp->addr.dest);
					fprintf(stream_out, "%s:%u ", int_ntoa (a_tcp->addr.saddr), a_tcp->addr.source);
					fprintf(stream_out, "\t%s\n", received_time);
					free(hashkey);
					free(received_time);
					g_mutex_unlock (table_mutex);
					return;
				}

				//Comprobaciones
				if(peticion->request == NULL || peticion->response_bytes == 0){
					g_mutex_unlock (table_mutex);
					return;
				}

				//Concatenar los datos
				peticion->chunks += 1;
				//DESCARTADOS PARA AHORRAR MEMORIA
				// ===================================
				peticion->response = (char *) realloc(peticion->response, peticion->response_bytes+hlf_client->count_new);
				strncpy(peticion->response+peticion->response_bytes, hlf_client->data, hlf_client->count_new);
				//FIN DESCARTADOS PARA AHORRAR MEMORIA
				// ===================================
				peticion->response_bytes += hlf_client->count_new;
				//Se guarda el tiempo de la ultima respuesta
				peticion->ts_last_response = nids_last_pcap_header->ts;
			}else{ //NO HAY ENTRADA EN LA TABLA HASH => No es un trozo de la respuesta
				// fprintf(stream_out, COLOUR_B_RED "RESPONSE WITHOUT REQUEST!! \t%d\t" COLOUR_NONE, packets);
				// fprintf(stream_out, "%s:%u\t", int_ntoa (a_tcp->addr.daddr), a_tcp->addr.dest);
				// fprintf(stream_out, "%s:%u ", int_ntoa (a_tcp->addr.saddr), a_tcp->addr.source);
				// fprintf(stream_out, "\t%s\n", received_time);
				free(hashkey);
				free(received_time);
				g_mutex_unlock (table_mutex);
				return;
			}

			g_hash_table_steal(table, hashkey);			
			g_hash_table_insert(table, gkey, hashvalue);
			
			free(hashkey);

	 	//PETICION
		}else if(hlf_server->count_new && http_get_op(http) == GET){ //PETICION
			
			//fprintf(stream_out, COLOUR_B_BLUE "#%d\t%s\t" COLOUR_NONE, packets, http_get_method(http));

			//HASH TABLE
			char *hashkey = hash_key(a_tcp);
			hash_value *hashvalue = NULL;
			gpointer gkey = NULL, gval = NULL;

			g_hash_table_lookup_extended(table, hashkey, &gkey, &gval);
			
			hashvalue = (hash_value *) gval;
			intercambio *peticion = NULL;

			//Se comprueba si existe entrada en la tabla hash que de la misma cuadrupla
			if(hashvalue == NULL){ //si no existe creo una nueva entrada en la tabla;
				hashvalue = (hash_value *) calloc(sizeof(hash_value), 1);
				hashvalue->n_peticiones = 1;
				hashvalue->n_respuestas = 0;
				hashvalue->peticiones = (intercambio *) calloc(sizeof(intercambio), 1);
				hashvalue->last = hashvalue->peticiones;
				hashvalue->peticiones->prev = NULL;
				hashvalue->peticiones->next = NULL;
			}else{ //si existe, añado un nuevo nodo a la lista enlazada "peticiones"
				
				//Removes a key and its associated value from a GHashTable 
				//without calling the key and value destroy functions.

				g_hash_table_steal(table, hashkey); 
				
				hashvalue->n_peticiones++;
				hashvalue->last->next = (intercambio *) calloc(sizeof(intercambio), 1);
				hashvalue->last->next->prev = hashvalue->last;
				hashvalue->last = hashvalue->last->next;

			}

			//BETA
			hashvalue->array =  (intercambio **) realloc(hashvalue->array, sizeof(intercambio*)*hashvalue->n_peticiones);
			hashvalue->array[hashvalue->n_peticiones-1] = hashvalue->last;
			//FIN BETA

			peticion = hashvalue->last;
			peticion->ts_request = nids_last_pcap_header->ts;
			//Se copian los bytes de datos que han llegado
			peticion->request = (char *) calloc(sizeof(char), hlf_server->count_new);
			peticion->chunks = 0;
			if(peticion->request == NULL){
				fprintf(stderr, "ERROR WHILE ALLOCATING FOR REQUEST\n");
			}
			peticion->response = NULL;
			//El numero de paquete
			peticion->n_request_pkt = packets;
			peticion->request_bytes = hlf_server->count_new;
			strncpy(peticion->request, hlf_server->data, hlf_server->count_new);


			g_hash_table_insert(table, hashkey, hashvalue);
			

			if(gkey != NULL)
				free(gkey);
			
			strcpy (buf, adres (a_tcp->addr, "==>")); // we put conn params into buf

		}//FIN DE BLOQUE TCP DATA PETICION
		//Liberar paquete http
		http_free_packet(&http);
		//FIN DE BLOQUE TCP DATA
	}else{
		// fprintf(stream_out, COLOUR_RED "Que es esto?\t" COLOUR_NONE);
		// fprintf(stream_out, "%s:%u\t", int_ntoa (a_tcp->addr.daddr), a_tcp->addr.dest);
		// fprintf(stream_out, "%s:%u ", int_ntoa (a_tcp->addr.saddr), a_tcp->addr.source);
		// fprintf(stream_out, "\t%s\n", received_time);
	}
	
	//fprintf(stream_out, "%s\n", buf);
	free(received_time);
	//nids_discard(a_tcp, 0);
	
	//if(a_tcp->nids_state == NIDS_DATA){

	//}

  g_mutex_unlock (table_mutex);
  return;
}

int main(int argc, char *argv[]){
	

  stream_out = stdout;

  if(argc<3){
  	how_to_use(argv[0]);
  	return 1;
  }if(argc==4){
  	file_out = fopen(argv[3], "w");
  	stream_out = file_out;
  }

  // here we can alter libnids params, for instance:
	nids_params.filename = argv[1];
	nids_params.pcap_filter = argv[2];
	nids_params.device = NULL; 

  //SIZE OF PCAP FILE
  FILE* file_pcap = NULL;
  file_pcap = fopen(argv[1], "rb");

  struct timeval t, t2;  
  gettimeofday(&t, NULL);
  fseek(file_pcap, 0L, SEEK_END);
  gettimeofday(&t2, NULL);
  pcap_size = ftell(file_pcap);
  rewind(file_pcap); 
  fclose(file_pcap);
  long microsegundos = ((t2.tv_usec - t.tv_usec)  + ((t2.tv_sec - t.tv_sec) * 1000000.0f));
  fprintf(stderr, "SIZE: %ld, Time: (%ld)\n", pcap_size, microsegundos);
  //END SIZE OF PCAP FILE

  table = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, funcionLiberacion);
  if(table == NULL){
  	fprintf(stream_out, "Error al crear tabla hash.");
  	fclose(file_out);
  	return -1;
  }

  if (!nids_init ()){
  	fprintf(stream_out,"Error nids_init. %s\n",nids_errbuf);
	g_hash_table_destroy(table);
	fclose(file_out);
  	return -3;
  }

  // //inicializamos el soporte para hilos en glib
  if (!g_thread_supported ()) g_thread_init (NULL);

   g_assert (table_mutex == NULL);
   table_mutex = g_mutex_new ();

  //reservamos memoria para el hilo de manera dinámica
  recolector = (GThread *) malloc(sizeof(GThread));
  if(recolector == NULL) return -2;
  progreso = (GThread *) malloc(sizeof(GThread));
  if(progreso == NULL) return -2;

  //creamos los hilos
  recolector = g_thread_create( (GThreadFunc)recolector_de_basura, NULL , TRUE, NULL);
  progreso = g_thread_create( (GThreadFunc)barra_de_progreso, NULL , TRUE, NULL);

  // nids_register_ip(ip_func);
  // nids_run();
  // nids_unregister_ip(ip_func);

  gettimeofday(&start, NULL);
  running = 1;
  nids_register_tcp (tcp_callback);
  nids_run ();
  running = 0;
  nids_unregister_tcp(tcp_callback);


  loadBar(pcap_size, pcap_size, pcap_size, 50);
  fprintf(stderr,"\n");
  kill(getpid(), SIGALRM);

  g_thread_join(recolector);
  free(recolector);

  //destruimos el hilo
  g_thread_join(progreso);
  if(file_out != NULL){
  	fclose(file_out);
  }

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
	free(hashvalue->array);

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
