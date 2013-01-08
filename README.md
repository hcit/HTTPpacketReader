#HTTP packet reader   
***    
## What is this project about?

This is a job for the High Performance Computing and Networking research group at the **Universidad Autonoma de Madrid**
The aim of the application is to show the response times of HTTP requests.
Afterwards these data are plotted to analyze the HTTP traffic and improve its behaviour.

## Does it use an external libraries?
Yes, some of them indeed.
This application uses glibC and [libnids](http://libnids.sourceforge.net) libraries to make the development easier to do.

## How could I get in touch with you?
You can send me an email to this address: carlosvega@gmx.es

## Dependencies

It uses libnids, libnet, libpcap and glibc libraries.

Libnids and libnet are included with the installer.

If you use __Fedora__ you need make sure these packets are installed:
- make
- gcc
- glib2-devel libpcacp-devel
- And it would be fine if you also install kernel-devel and kernel-headers

If you use __Ubuntu__ you need make sure these packets are installed:
- libpcap-dev
- libglib2.0-dev
 
Dependency tree

            hope
             ||
      glibc——||——libnids
                   ||
          libpcap——||——libnet
                   ||

If you want the shell line to install these packets use this one:
sudo yum install kernel-devel kernel-headers make gcc glib2-devel libpcacp-devel

## Installation
I have created an installer. These are the instructions:

1. Check if you fulfill the dependencies requirements at the depenencies chapter above.
2. You just need to download installer.7z (7z have a really high compression ratio, you must try it!)
3. Uncompress it
4. Do sh install.sh
5. ./hope and follow the instructions


### Change log
 - Now it prints the request and response in pairs, as shows below, even if there is another request before the response for the first request:  <br/>
  ``#2 GET	192.168.1.136:58916	192.168.1.22:80	2012-09-26 17:06:41 662744``
  ``#3	DATA 192.168.1.236.22:80	192.168.1.136:58916 	2012-09-26 17:06:41 965271	0.302527``
 - Small changes
 - I've created an installer, see installation chapter above.

### Problems to solve
 - For some reason libnids library doesn't call the TCP callback function when a DATA packet arrives. <br/>
 I don't know if is it a PCAP file problem or just something I'm doing wrong. Still working on it.

### To do

 - Change the name of the main executable.
 - Fix the above problems.


I got to lunch, see you later.
