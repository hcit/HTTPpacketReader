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

#include "../libnids-1.24/src/nids.h"
#include "../colours.h"

#define STREAM_OUT stdout


static int packets = 0;

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

/*
enum {
  TCP_ESTABLISHED = 1,
  TCP_SYN_SENT,  //2
  TCP_SYN_RECV,  //3
  TCP_FIN_WAIT1, //4
  TCP_FIN_WAIT2, //5
  TCP_TIME_WAIT, //6
  TCP_CLOSE,     //7
  TCP_CLOSE_WAIT,//8
  TCP_LAST_ACK,  //9
  TCP_LISTEN,    //10
  TCP_CLOSING    //11	// now a valid state
};*/


void tcp_callback (struct tcp_stream *a_tcp, void ** this_time_not_needed) {

	char *received_time = NULL;


	packets++;

	received_time = timeval_to_char(nids_last_pcap_header->ts);
	if(received_time == NULL){
		return;
	}


	if(a_tcp->nids_state == NIDS_EXITING) {
		//fprintf(STREAM_OUT, COLOUR_RED "\nNIDS is closing!\n" COLOUR_NONE);
	}else if(a_tcp->nids_state == NIDS_JUST_EST) {
		// connexion described by a_tcp is established
		// here we decide, if we wish to follow this stream
		// sample condition: if (a_tcp->addr.dest!=23) return;
		// in this simple app we follow each stream, so..
      a_tcp->client.collect++; // we want data received by a client
      a_tcp->server.collect++; // and by a server, too
      a_tcp->server.collect_urg++;
      a_tcp->client.collect_urg++;
		fprintf(STREAM_OUT, COLOUR_B_GREEN "#%d\tSYN\t%d\t" COLOUR_NONE, packets, a_tcp->client.state);
		fprintf(STREAM_OUT, "%s", adres(a_tcp->addr, "\t"));
		fprintf(STREAM_OUT, "\t%s\n", received_time);
	}else if(a_tcp->nids_state == NIDS_RESET) {
		fprintf(STREAM_OUT, COLOUR_B_YELLOW "#%d\tRST\t%d\t" COLOUR_NONE, packets, a_tcp->client.state);
		fprintf(STREAM_OUT, "%s", adres(a_tcp->addr, "\t"));
		fprintf(STREAM_OUT, "\t%s\n", received_time);
	}else if(a_tcp->nids_state == NIDS_CLOSE || a_tcp->nids_state == NIDS_EXITING) {

		fprintf(STREAM_OUT, COLOUR_B_RED "#%d\tFIN%d\t\t" COLOUR_NONE, packets, a_tcp->client.state);
		fprintf(STREAM_OUT, "%s\n", adres(a_tcp->addr, "\t"));
	}else if(a_tcp->nids_state == NIDS_DATA) { 	//LLEGA PAQUETE TCP CON PAYLOAD
		fprintf(STREAM_OUT, COLOUR_B_YELLOW "#%d\tDATA%d\t\t" COLOUR_NONE, packets, a_tcp->client.state);
		fprintf(STREAM_OUT, "%s", adres(a_tcp->addr, "\t"));
		fprintf(STREAM_OUT, "\t%s\n", received_time);
	}else{
		fprintf(STREAM_OUT, COLOUR_B_YELLOW "#%d\tHOLA !\t%d\t" COLOUR_NONE, packets, a_tcp->client.state);
		fprintf(STREAM_OUT, "%s", adres(a_tcp->addr, "\t"));
		fprintf(STREAM_OUT, "\t%s\n", received_time);
	}
	
	//fprintf(STREAM_OUT, "%s\n", buf);
	free(received_time);
	//nids_discard(a_tcp, 0);
	
  return;
}

// void ip_func(struct ip * a_packet, int len){

// 	fprintf(STREAM_OUT, "paqueteeeeeeeee\n");

// 	return;
// }

int main(int argc, char *argv[]){
	
  // here we can alter libnids params, for instance:

	nids_params.filename = argv[1];
	nids_params.pcap_filter = argv[2];
	nids_params.device = NULL; 

  if(argc!=3){
  	how_to_use(argv[0]);
  	return 1;
  }

  


  if (!nids_init ()){
  	fprintf(STREAM_OUT,"Error nids_init. %s\n",nids_errbuf);
  	return -2;
  }

  // nids_register_ip(ip_func);
  // nids_run();
  // nids_unregister_ip(ip_func);

  nids_register_tcp (tcp_callback);
  nids_run ();
  nids_unregister_tcp(tcp_callback);

  return 0;

}