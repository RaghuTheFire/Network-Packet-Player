#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

void send_packet(pcap_t * handle,
  const u_char * packet, int size) 
  {
  int bytes = pcap_sendpacket(handle, packet, size);
  if (bytes == -1) 
  {
    fprintf(stderr, "Error sending packet: %s\n", pcap_geterr(handle));
  }
}

int main(int argc, char * argv[]) 
{
  if (argc != 2) 
  {
    fprintf(stderr, "Usage: %s <pcap_file>\n", argv[0]);
    return 1;
  }

  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t * handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) 
  {
    fprintf(stderr, "Error opening device: %s\n", errbuf);
    return 1;
  }

  pcap_t * pcap = pcap_open_offline(argv[1], errbuf);
  if (pcap == NULL) 
  {
    fprintf(stderr, "Error opening pcap file: %s\n", errbuf);
    pcap_close(handle);
    return 1;
  }

  struct pcap_pkthdr header;
  const u_char * packet;
  while ((packet = pcap_next(pcap, & header)) != NULL) 
  {
    send_packet(handle, packet, header.caplen);
    usleep(header.ts.tv_usec);
  }

  pcap_close(pcap);
  pcap_close(handle);
  return 0;
}
