#include "ft_nmap.h"

void    debug_icmp_packet(t_packet packet)
{
    printf("       sizeof(packet): %lu\n", sizeof(packet));
    printf("       packet.payload: %s\n", packet.payload);
    printf("       sizeof(packet.payload): %lu\n", sizeof(packet.payload));
    printf("       packet.h.type: %d\n", packet.h.type);
    printf("       packet.h.code: %d\n", packet.h.code);
    printf("       packet.h.checksum: %d\n", packet.h.checksum);
    printf("       packet.h.un.echo.id: %d\n", packet.h.un.echo.id);
    printf("       packet.h.un.echo.sequence: %d\n", packet.h.un.echo.sequence);
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

void debug_net_mask(bpf_u_int32 net_mask, bpf_u_int32 dev_mask)
{
    printf(C_G_RED"[NET_MASK] %d = %x"C_RES"\n", net_mask, net_mask);
    printf(C_G_RED"[DEV_MASK] %d = %x"C_RES"\n", dev_mask, dev_mask);
    printf("\n");
}
