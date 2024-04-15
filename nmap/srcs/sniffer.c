#include "ft_nmap.h"

void    prepare_sniffer(pcap_t **handle)
{
    pcap_if_t           *interfaces;
    char                device[] = "enp0s3";
    char                filter[] = "src host 1.1.1.1";
    struct bpf_program  compiled_filter;
    char                err_buf[PCAP_ERRBUF_SIZE];          // 256 from pcap.h
    bpf_u_int32         dev_mask;		                    // The netmask of our sniffing device
    bpf_u_int32         net_mask;		                    // The IP of our sniffing device   

    if (pcap_lookupnet(device, &net_mask, &dev_mask, err_buf) == -1) // get network mask needed for the filter
    {
        warning_str("No network mask for device:", device);
        net_mask = 0;
        dev_mask = 0;
    }
    // debug_net_mask(net_mask, dev_mask);
    if (pcap_findalldevs(&interfaces, err_buf) == -1)
        exit_error_str("Finding devices", err_buf);
    // debug_interfaces(interfaces);
    if ((*handle = pcap_open_live(device, BUFSIZ, PROMISCUOUS, 1000, err_buf)) == NULL)  // sniff device until error and store it in err_buf
        exit_error_str("Opening device:", err_buf);
    if (pcap_compile(*handle, &compiled_filter, filter, 0, net_mask) == -1)
        exit_error_str("Parsing filter:", pcap_geterr(*handle));
    if (pcap_setfilter(*handle, &compiled_filter) == -1)
        exit_error_str("Compiling filter:", pcap_geterr(*handle));
}

const struct iphdr          *ip_h;
const struct icmphdr        *icmp_h;
const char                  *icmp_payload;

void    retrieve_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) // args = last arg of pcap_loop
{
    (void)args;
    (void)header;
    ip_h            = (struct iphdr *)          (packet + ETH_H_LEN);                           // packet + 14
    icmp_h          = (struct icmphdr *)        (packet + ETH_H_LEN + IP_H_LEN);                // packet + 14 + 20
    icmp_payload    = (char *)                  (packet + ETH_H_LEN + IP_H_LEN + ICMP_H_LEN);   // packet + 14 + 20 + 8
    // printf(C_G_RED"[QUICK DEBUG] icmp_h->type: %hhu"C_RES"\n", icmp_h->type);
    if (icmp_h->type != ICMP_ECHO_REPLY)
        warning_int("Invalid ICMP type: (bytes)", icmp_h->type);
    else
    {
        print_info_int("Retrieved packet", g_retrieve);
        // printf(C_G_MAGENTA"[INFO]"C_RES" Retrieved packet "C_G_GREEN"[%d]"C_RES"\n", g_retrieve);
        // printf(C_G_MAGENTA"[INFO]"C_RES" Retrieved packet of size "C_G_GREEN"[%d]"C_RES" with type "C_G_GREEN"[%d]"C_RES" and code "C_G_GREEN"[%d]"C_RES"\n", header->len, icmp_h->type, icmp_h->code);
        // printf(C_G_MAGENTA"[INFO]"C_RES"PAYLOAD [%s]\n", icmp_payload);
        g_retrieve++;
    }
}

void    sniff_packets(pcap_t *handle)
{
    printf(C_G_YELLOW"[INFO]"C_RES" Ready to sniff...\n");
    pcap_dispatch(handle, 0, retrieve_packet, NULL);
	print_info("Capture completed");
	pcap_close(handle);
}
