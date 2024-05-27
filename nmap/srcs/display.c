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
