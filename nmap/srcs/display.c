#include "../includes/ft_nmap.h"

void    display_hex_packet(unsigned char *bytes, int size)
{
    for (int i = 0; i < size; i = i + 2)
    {
        if ((i + 1) < size)
        {
            printf("%02x%02x ", bytes[i], bytes[i + 1]);
            if ((i + 2) % 16 == 0)
                printf("\n");
        }
    }
    printf("\n");
}

void    display_icmp_packet(t_packet packet)
{
    unsigned char *bytes = (unsigned char *)&packet.packet(icmp);
    display_hex_packet(bytes, ICMP_LEN);
}

void    display_tcp_packet(t_packet packet)
{
    unsigned char *bytes = (unsigned char *)&packet.packet(tcp);
    display_hex_packet(bytes, 64);
}


void    display_tcphdr(const struct tcphdr *tcp_header)
{
    printf("TCP Header:\n");
    printf("  Source port:  %u\n", ntohs(tcp_header->source));
    printf("  Dest port:    %u\n", ntohs(tcp_header->dest));
    printf("  Sequence:     %u\n", ntohl(tcp_header->seq));
    printf("  Ack num:      %u\n", ntohl(tcp_header->ack_seq));
    printf("  Data offset:  %u\n", tcp_header->doff * 4); // En octets
    printf("  Flags: \n");
    printf("        URG: %u\n", (tcp_header->th_flags & TH_URG)  ? 1 : 0);
    printf("        ACK: %u\n", (tcp_header->th_flags & TH_ACK)  ? 1 : 0);
    printf("        PSH: %u\n", (tcp_header->th_flags & TH_PUSH) ? 1 : 0);
    printf("        RST: %u\n", (tcp_header->th_flags & TH_RST)  ? 1 : 0);
    printf("        SYN: %u\n", (tcp_header->th_flags & TH_SYN)  ? 1 : 0);
    printf("        FIN: %u\n", (tcp_header->th_flags & TH_FIN)  ? 1 : 0);
    printf("  Window size:  %u\n", ntohs(tcp_header->window));
    printf("  Checksum:     0x%04x\n", ntohs(tcp_header->check));
    printf("  Urg pointer:  %u\n", ntohs(tcp_header->urg_ptr));
}
