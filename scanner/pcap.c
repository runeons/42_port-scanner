// clang pcap.c -lpcap && sudo ./a.out 
// sudo tcpdump host 1.1.1.1

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include "colors.h"
#include "structs.h"

/* ethernet headers are always exactly 14 bytes */
#define SIZE_ETHERNET 14

const struct sniff_ethernet *ethernet;  /* The ethernet header */
const struct sniff_ip       *ip;        /* The IP header */
const struct sniff_tcp      *tcp;       /* The TCP header */
const u_char                *payload;   /* Packet payload */

u_int size_ip;
u_int size_tcp;

// struct pcap_pkthdr
// {
// 	struct timeval ts; /* time stamp */
// 	bpf_u_int32 caplen; /* length of portion present */
// 	bpf_u_int32 len; /* length this packet (off wire) */
// }; // contains information about when the packet was sniffed, how large it is, etc


void warning_str(char *msg, char *error)
{
    printf(C_G_MAGENTA"[WARNING]"C_RES" %s %s\n", msg, error);
}

void warning_int(char *msg, int nb)
{
    printf(C_G_MAGENTA"[WARNING]"C_RES" %s %d\n", msg, nb);
}

void print_info(char *msg)
{
    printf(C_G_BLUE"[INFO]"C_RES" %s\n", msg);
}

void exit_error(char *msg, char *error)
{
    printf(C_G_RED"[ERROR]"C_RES" %s %s\n", msg, error);
    exit(1);
}

void debug_interfaces(pcap_if_t *interfaces)
{
    pcap_if_t   *tmp;
    int         i = 0;

    printf(C_G_YELLOW"[INTERFACES]"C_RES"\n");
    for (tmp = interfaces; tmp; tmp = tmp->next)
        printf("%d: %s\n", i++, tmp->name);
    printf("\n");
}

void debug_net_mask(bpf_u_int32 net, bpf_u_int32 mask)
{
    printf(C_G_RED"[NET ] %d = %x"C_RES"\n", net, net);
    printf(C_G_RED"[MASK] %d = %x"C_RES"\n", mask, mask);
    printf("\n");
}

// callback function format
void retrieve_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) // args = last arg of pcap_loop
{
    ethernet    = (struct sniff_ethernet*)(packet);
    ip          = (struct sniff_ip*)(packet + SIZE_ETHERNET);   // 14
    size_ip     = IP_HL(ip) * 4;                                // 5 * 4
    if (size_ip < 20)
    {
        warning_int("Invalid IP header length: (bytes)", size_ip);
        return;
    }
    tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp) * 4;
    if (size_tcp < 20)
    {
        warning_int("Invalid TCP header length: (bytes)", size_tcp);
        return;
    }
    payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
    printf(C_G_GREEN"[%d] "C_RES"Retrieved packet\n", header->len);
	printf("PAYLOAD [%s]\n", payload); // need to print as hex

}
// packet = points to the first byte of the actual packet sniffed

int main(int argc,char **argv)
{
    pcap_if_t           *interfaces;
    char                device[] = "enp0s3";
    char                filter[] = "host 1.1.1.1";	    // filter expression
    struct bpf_program  fp;		                        // compiled filter expression
    char                err_buf[PCAP_ERRBUF_SIZE];
    bpf_u_int32         mask;		                    // The netmask of our sniffing device
    bpf_u_int32         net;		                    // The IP of our sniffing device   

    // prepare sniffer
    if (pcap_lookupnet(device, &net, &mask, err_buf) == -1) // to get network mask needed for the filter
    {
        warning_str("Network mask for device:", device); // A quoi sert le network mask ? de quelle adresse net est-il ?
        net = 0; // IPV4 ANDed with network mask, so it contains only the network part of the address
        mask = 0;
    }

    debug_net_mask(net, mask);
    if (pcap_findalldevs(&interfaces, err_buf)==-1)                  // devices list
        exit_error("Finding devices", err_buf);
    debug_interfaces(interfaces);

    pcap_t *handle; // Session handle
    if ((handle = pcap_open_live(device, BUFSIZ, 1, 1000, err_buf)) == NULL)        // choose device // promiscuous mode // sniff until error and store it in err_buf // pcap_t *pcap_open_live(char *device, int snaplen, int promisc, int to_ms, char *ebuf)
        exit_error("Opening device:", err_buf);
    if (pcap_compile(handle, &fp, filter, 0, net) == -1)        // filter // int pcap_compile(pcap_t *p, struct bpf_program *fp, char *str, int optimize, bpf_u_int32 netmask)
        exit_error("Parsing filter:", pcap_geterr(handle));
    if (pcap_setfilter(handle, &fp) == -1)
        exit_error("Compiling filter:", pcap_geterr(handle));
	pcap_dispatch(handle, 10, retrieve_packet, NULL);
	print_info("Capture completed");
	pcap_close(handle);
    return 0;
}


    // int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user)
    // p = session handle
    // cnt = nb of packets before returning
    // callback = handler when filter sniff
    // user = NULL or specific arguments we want to send to callback (typecast them to u_char)
    // calls callback function when a packet corresponfing to filter is sniffed
