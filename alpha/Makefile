CC = gcc -g -Wall
#CFLAGS		= -g -O2 -D_BSD_SOURCE
LDFLAGS		= 

GLIB =  `pkg-config --cflags --libs glib-2.0`

#PCAP_CFLAGS	= -I/usr/include/pcap
PCAPLIB		= -lpcap

#LNET_CFLAGS	= -D_BSD_SOURCE -D__BSD_SOURCE -D__FAVOR_BSD -DHAVE_NET_ETHERNET_H
LNETLIB		= -lnet

#LIBS_CFLAGS	= -I/libnids $(PCAP_CFLAGS) $(LNET_CFLAGS)
LIBS		= -L../src -lnids $(PCAPLIB) $(LNETLIB) -lgthread-2.0 -lnsl

all: hope

tslist.o: tslist.c
	$(CC) -c tslist.c -o tslist.o
alist.o: alist.c
	$(CC) -c alist.c -o alist.o
http.o: http.c
	$(CC) -c http.c -o http.o
#http_hash: http_hash.c
#	$(CC) $(GLIB) http_hash.c -o http_hash
hope: hope.c http.o alist.o tslist.o
	$(CC) -c hope.c -o hope.o $(GLIB) $(LIBS)
	$(CC) hope.o http.o alist.o tslist.o -o hope $(GLIB) $(LIBS)
clean:	
	rm -f *.o tslist alist http hope 
