#include "../includes/ft_nmap.h"

// char    *addr_to_str(int addr)
// {
//     char res[MAX_IP_LEN];
    
//     sprintf(res, "%u.%u.%u.%u", addr & 0xFF, (addr >> 8) & 0xFF, (addr >> 16) & 0xFF, (addr >> 24) & 0xFF);
//     return (ft_strdup(res));
// }

// unsigned int    get_flags(unsigned int frag_off)
// {
//     unsigned int flags = 0;

//     flags = (ntohs(frag_off) & IP_FLAGS_MASK) >> IP_OFFSET_SHIFT;
//     if (DEBUG == 1)
//         printf(C_G_RED"flags: %04x"C_RES"\n", flags);
//     return (flags);
// }

// unsigned int    get_offset(unsigned int frag_off)
// {
//     unsigned int offset = 0;

//     offset = ntohs(frag_off) & IP_OFFSET_MASK;
//     if (DEBUG == 1)
//         printf(C_G_RED"offset: %04x"C_RES"\n", offset);
//     return (offset);
// }

// void    display_ip_header(unsigned char *bytes_ip)
// {
//     struct iphdr    *ip = (struct iphdr *)(bytes_ip);

//     printf("IP Hdr Dump:\n");
//     for (int i = 0; i < IP_HEADER_LEN; i = i + 2)
//         printf(" %02X%02X", bytes_ip[i], bytes_ip[i + 1]);
//     printf("\n");
//     printf("%2s %2s %3s %4s %4s %3s %4s %3s %3s %4s %12s %12s %s\n", "Vr","HL","TOS","Len","ID","Flg","off","TTL","Pro","cks","Src","Dst","Data");
//     printf("%2x %2x %3x %04x %4x %3x %04x %03x %03x %4x %12s %12s\n", ip->version, ip->ihl, ip->tos, htons(ip->tot_len), ip->id, get_flags(ip->frag_off), get_offset(ip->frag_off), ip->ttl, ip->protocol, htons(ip->check), addr_to_str(ip->saddr), addr_to_str(ip->daddr));

// }

// void    display_icmp_header(t_data *dt, unsigned char *bytes)
// {
//     struct icmphdr  *icmp_in_payload = (struct icmphdr *)(bytes + IP_HEADER_LEN + ICMP_HEADER_LEN);

//     printf("ICMP: type %d, code %d, size %d, id 0x%04x, seq 0x%04d\n", icmp_in_payload->type, icmp_in_payload->code, dt->one_seq.bytes, htons(icmp_in_payload->un.echo.id), icmp_in_payload->un.echo.sequence);
// }
#define IP_HEADER_LEN          20
#define ICMP_HEADER_LEN        8

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
    display_hex_packet(bytes, 64);
}


// void    display_icmp_packet(t_packet packet)
// {
//     printf("%d bytes from %s\n", packet.size, addr_to_str(packet.packet.ip->saddr));
//     // debug_packet(&packet.final_packet);
//     unsigned char *bytes = (unsigned char *)packet.packet.icmp;
//     display_ip_header(bytes + ICMP_HEADER_LEN);
//     display_icmp_header(dt, bytes);
// }