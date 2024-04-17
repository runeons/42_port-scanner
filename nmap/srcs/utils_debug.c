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

void    debug_interfaces(pcap_if_t *interfaces)
{
    pcap_if_t   *tmp;
    int         i = 0;

    printf(C_G_YELLOW"[INTERFACES]"C_RES"\n");
    for (tmp = interfaces; tmp; tmp = tmp->next)
        printf("%d: %s\n", i++, tmp->name);
    printf("\n");
}

void    debug_net_mask(bpf_u_int32 net_mask, bpf_u_int32 dev_mask)
{
    printf(C_G_RED"[NET_MASK] %d = %x"C_RES"\n", net_mask, net_mask);
    printf(C_G_RED"[DEV_MASK] %d = %x"C_RES"\n", dev_mask, dev_mask);
    printf("\n");
}

void    debug_addrinfo(struct addrinfo ai)
{
    if (DEBUG == 1)
    {
        printf(C_G_GRAY"[DEBUG] addrinfo"C_RES"\n");
        printf("        ai_family: %d\n",   ai.ai_family);
        printf("        ai_socktype: %d\n", ai.ai_socktype);
        printf("        ai_addr: %s\n",     inet_ntoa(((struct sockaddr_in *)ai.ai_addr)->sin_addr));
        printf(C_G_GRAY"-------"C_RES"\n");
    }
}

void    debug_sockaddr_in(struct sockaddr_in addr)
{
    if (DEBUG == 1)
    {
        printf(C_G_GRAY"[DEBUG] sockaddr_in"C_RES"\n");
        printf("        sin_family: %d\n",              addr.sin_family);
        printf("        sin_port: %d\n",                addr.sin_port);
        printf("        sin_addr.s_addr: %s (%d)\n",    inet_ntoa(addr.sin_addr), addr.sin_addr.s_addr);
        printf(C_G_GRAY"-------"C_RES"\n");
    }
}

void    debug_scan(t_scan scan)
{
    if (DEBUG == 1)
    {
        printf(C_G_BLUE"[DEBUG] scan"C_RES"\n");
        printf("        scan_type   %d\n", scan.scan_type);
        printf("        response    %d\n", scan.response);
        printf("        conclusion  %d\n", scan.conclusion);
        printf(C_G_BLUE"-------"C_RES"\n");
    }
}

void    debug_scan_tracker(t_scan_tracker scan_tracker)
{
    if (DEBUG == 1)
    {
        printf(C_G_RED"[DEBUG] scan_tracker"C_RES"\n");
        printf("        count_sent  %d\n", scan_tracker.count_sent);
        printf("        max_send    %d\n", scan_tracker.max_send);
        debug_scan(scan_tracker.scan);
        printf(C_G_RED"-------"C_RES"\n");
    }
}

void    debug_port(t_port port)
{
    if (DEBUG == 1)
    {
        printf(C_G_GREEN"[DEBUG] port %d"C_RES"\n", port.port_id);
        printf("        port_id     %d\n", port.port_id);
        printf("        conclusion  %d\n", port.conclusion);
        for (int i = 0; i < g_scans_nb; i++)
            debug_scan_tracker(port.scan_trackers[i]);
        printf(C_G_GREEN"-------"C_RES"\n");
    }
}

void    debug_one_port(void *content)
{
    if (content)
    {
        t_port *p = (t_port *)content;
        debug_port(*p);
    }
}

void    debug_host(t_host host)
{
    if (DEBUG == 1)
    {
        printf(C_G_CYAN"[DEBUG] host %s"C_RES"\n", host.input_dest);
        printf("        input_dest          %s\n", host.input_dest);
        printf("        resolved_address    %s\n", host.resolved_address);
        printf("        resolved_hostname   %s\n", host.resolved_hostname);
        printf("        dst_port            %d\n", host.dst_port);
        debug_sockaddr_in(host.target_address);
        ft_lst_iter_content(host.ports, debug_one_port);
        printf(C_G_CYAN"-------"C_RES"\n");
    }
}

void    debug_queue(t_data dt)
{
    if (DEBUG == 1)
    {
        printf(C_G_GREEN"[DEBUG] queue %d"C_RES"\n", ft_lst_size((dt.queue)));
        printf(C_G_GREEN"-------"C_RES"\n");
    }
}
