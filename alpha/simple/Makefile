CC = gcc -g -Wall 
#CFLAGS		= -g -O2 -D_BSD_SOURCE
COLOURFLAGS = -D _colours
LDFLAGS		= 

GLIB =  `pkg-config --cflags --libs glib-2.0`

#PCAP_CFLAGS	= -I/usr/include/pcap
PCAPLIB		= -lpcap

#LNET_CFLAGS	= -D_BSD_SOURCE -D__BSD_SOURCE -D__FAVOR_BSD -DHAVE_NET_ETHERNET_H
LNETLIB		= ../libnet-1.1.6/src/.libs/libnet.a
#-lnet

#LIBS_CFLAGS	=  $(PCAP_CFLAGS) $(LNET_CFLAGS)
LIBS_SRC	= ../libnids-1.24/src/libnids.a
LIBS		= $(PCAPLIB) $(LNETLIB) -lgthread-2.0 

all: hope

hope: hope.c
	$(CC) -c $(CFLAGS) hope.c -o hope.o $(LIBS)
	$(CC) hope.o -o hope $(LIBS_SRC) $(LIBS)
colour_hope: hope.c http.o alist.o
	$(CC) -c $(COLOURFLAGS) hope.c -o hope.o $(LIBS)
	$(CC) hope.o -o hope $(LIBS_SRC) $(LIBS)
clean:	
	rm -f *.o hope 
