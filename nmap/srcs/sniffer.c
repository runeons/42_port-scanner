#include "ft_nmap.h"

void    prepare_sniffer(t_data *dt)
{
    pcap_if_t           *interfaces;
    struct bpf_program  compiled_filter;
    char                err_buf[PCAP_ERRBUF_SIZE];          // 256 from pcap.h
    bpf_u_int32         dev_mask;		                    // The netmask of our sniffing device
    bpf_u_int32         net_mask;		                    // The IP of our sniffing device   

    if (!(dt->sniffer.device = ft_strdup("enp0s3")))
        exit_error("Malloc failure.");
    if (!(dt->sniffer.filter = ft_strdup("src host 1.1.1.1")))
        exit_error("Malloc failure.");
    if (pcap_lookupnet(dt->sniffer.device, &net_mask, &dev_mask, err_buf) == -1) // get network mask needed for the filter
    {
        warning_str("No network mask for device:", dt->sniffer.device);
        net_mask = 0;
        dev_mask = 0;
    }
    // debug_net_mask(net_mask, dev_mask);
    if (pcap_findalldevs(&interfaces, err_buf) == -1)
        exit_error_str("Finding devices", err_buf);
    // debug_interfaces(interfaces);
    if ((dt->sniffer.handle = pcap_open_live(dt->sniffer.device, BUFSIZ, PROMISCUOUS, 1000, err_buf)) == NULL)  // sniff device until error and store it in err_buf
        exit_error_str("Opening device:", err_buf);
    if (pcap_compile(dt->sniffer.handle, &compiled_filter, dt->sniffer.filter, 0, net_mask) == -1)
        exit_error_str("Parsing filter:", pcap_geterr(dt->sniffer.handle));
    if (pcap_setfilter(dt->sniffer.handle, &compiled_filter) == -1)
        exit_error_str("Compiling filter:", pcap_geterr(dt->sniffer.handle));
    pcap_freealldevs(interfaces);
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
}
