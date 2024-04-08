// clang pcap.c -lpcap && sudo ./a.out 

#include <stdio.h>
#include <pcap.h>
#include "colors.h"
#include "structs.h"

/* ethernet headers are always exactly 14 bytes */
#define SIZE_ETHERNET 14

const struct sniff_ethernet *ethernet; /* The ethernet header */
const struct sniff_ip *ip; /* The IP header */
const struct sniff_tcp *tcp; /* The TCP header */
const char *payload; /* Packet payload */

u_int size_ip;
u_int size_tcp;

// struct pcap_pkthdr {
// 	struct timeval ts; /* time stamp */
// 	bpf_u_int32 caplen; /* length of portion present */
// 	bpf_u_int32 len; /* length this packet (off wire) */
// }; // contains information about when the packet was sniffed, how large it is, etc

// callback function format
// args = last arg of pcap_loop
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    ethernet = (struct sniff_ethernet*)(packet);
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip)*4;
    if (size_ip < 20) {
        printf("   * Invalid IP header length: %u bytes\n", size_ip);
        return;
    }
    tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp)*4;
    if (size_tcp < 20) {
        printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
        return;
    }
    payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	printf("Jacked a packet with length of [%d]\n", header->len);

}
//packet = points to the first byte of the actual packet sniffed

int main(int argc,char **argv)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *interfaces;
    pcap_if_t *tmp;
    char      dev[] = "enp0s3";
    int i = 0;
    struct bpf_program fp;		    // compiled filter expression
    char filter_exp[] = "tcp";	// filter expression
    bpf_u_int32 mask;		        // The netmask of our sniffing device
    bpf_u_int32 net;		        // he IP of our sniffing device   

    // prepare sniffer
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) // to get network mask needed for the filter
    {
        fprintf(stderr, "Can't get netmask for device %s\n", dev);
        net = 0; // IPV4 ANDed with network mask, so it contains only the network part of the address
        mask = 0;
    }
    printf(C_G_RED"[QUICK DEBUG] net: %d"C_RES"\n", net);
    printf(C_G_RED"[QUICK DEBUG] mask: %d"C_RES"\n", mask);
    // devices list
    if (pcap_findalldevs(&interfaces, errbuf)==-1)
    {
        printf("\nerror in pcap findall devs");
        return -1;   
    }
    printf("\nthe interfaces present on the system are:");
    for (tmp = interfaces; tmp; tmp = tmp->next)
    {
        printf("\n%d  :  %s", i++, tmp->name);
    }
    printf("\n");
    // choose device
    // pcap_t *pcap_open_live(char *device, int snaplen, int promisc, int to_ms, char *ebuf)
    pcap_t *handle; // Session handle
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf); // promiscuous mode // sniff until error ad store it in errbuf
    printf(C_G_RED"[QUICK DEBUG] BUFSIZ: %d"C_RES"\n", BUFSIZ);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }
    // filter
    // int pcap_compile(pcap_t *p, struct bpf_program *fp, char *str, int optimize, bpf_u_int32 netmask)
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }

	pcap_dispatch(handle, 10, got_packet, NULL);
	printf("\nCapture complete.\n");
	pcap_close(handle);
    return 0;
}


    // int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user)
    // p = session handle
    // cnt = nb of packets before returning
    // callback = handler when filter sniff
    // user = NULL or specific arguments we want to send to callback (typecast them to u_char)
    // calls callback function when a packet corresponfing to filter is sniffed
