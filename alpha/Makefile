CC = gcc -O2 -g -Wall -pthread
#CFLAGS		= -g -O2 -D_BSD_SOURCE 
COLOURFLAGS = -D _colours
LDFLAGS		= 

GLIB =  `pkg-config --cflags --libs glib-2.0`

#PCAP_CFLAGS	= -I/usr/include/pcap
PCAPLIB		= -lpcap

#LNET_CFLAGS	= -D_BSD_SOURCE -D__BSD_SOURCE -D__FAVOR_BSD -DHAVE_NET_ETHERNET_H
LNETLIB		= libnet-1.1.6/src/.libs/libnet.a
#-lnet

#LIBS_CFLAGS	=  $(PCAP_CFLAGS) $(LNET_CFLAGS)
LIBS_SRC	= libnids-1.24/src/libnids.a
LIBS		= $(PCAPLIB) $(LNETLIB) -lgthread-2.0 

all: httpDissector

tslist.o: tslist.c
	$(CC) -c tslist.c -o tslist.o
alist.o: alist.c
	$(CC) -c alist.c -o alist.o
http.o: http.c
	$(CC) -c http.c -o http.o
#http_hash: http_hash.c
#	$(CC) $(GLIB) http_hash.c -o http_hash
httpDissector: httpDissector.c http.o alist.o
	$(CC) -c $(CFLAGS) httpDissector.c -o httpDissector.o $(GLIB) $(LIBS)
	$(CC) httpDissector.o http.o alist.o  -o httpDissector $(LIBS_SRC) $(GLIB) $(LIBS)
colour_httpDissector: httpDissector.c http.o alist.o
	$(CC) -c $(COLOURFLAGS) httpDissector.c -o httpDissector.o $(GLIB) $(LIBS)
	$(CC) httpDissector.o http.o alist.o -o httpDissector $(LIBS_SRC) $(GLIB) $(LIBS)
clean:	
	rm -f *.o tslist alist http httpDissector 
