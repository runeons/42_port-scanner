#include "../includes/ft_nmap.h"

void    debug_icmp_packet(t_packet packet)
{
    if (DEBUG_NET == 1)
    {
        printf("       sizeof(packet): %lu\n", packet.size);
        printf("       packet.payload: %s\n", packet.packet(icmp).payload);
        printf("       sizeof(packet.payload): %lu\n", sizeof(packet.packet(icmp).payload));
        printf("       packet.h.type: %d\n", packet.packet(icmp).h.type);
        printf("       packet.h.code: %d\n", packet.packet(icmp).h.code);
        printf("       packet.h.checksum: %d\n", packet.packet(icmp).h.checksum);
        printf("       packet.h.un.echo.id: %d\n", packet.packet(icmp).h.un.echo.id);
        printf("       packet.h.un.echo.sequence: %d\n", packet.packet(icmp).h.un.echo.sequence);
    }
}

void    debug_interfaces(pcap_if_t *interfaces)
{
    pcap_if_t   *tmp;
    int         i = 0;

    if (DEBUG_NET == 1)
    {
        printf(C_G_YELLOW"[DEBUG] interfaces"C_RES"\n");
        for (tmp = interfaces; tmp; tmp = tmp->next)
            printf("        %d: %s\n", i++, tmp->name);
        printf(C_G_YELLOW"-------"C_RES"\n");
    }
}

void    debug_net_mask(bpf_u_int32 net_mask, bpf_u_int32 dev_mask)
{
    if (DEBUG_NET == 1)
    {
        printf(C_G_YELLOW"[DEBUG] masks"C_RES"\n");
        printf("        net_mask: %d = %x\n", net_mask, net_mask);
        printf("        dev_mask: %d = %x\n", dev_mask, dev_mask);
        printf(C_G_YELLOW"-------"C_RES"\n");
    }
}

void    debug_addrinfo(struct addrinfo ai)
{
    if (DEBUG_NET == 1)
    {
        printf(C_G_GRAY"[DEBUG] addrinfo"C_RES"\n");
        printf("        ai_family       %d\n", ai.ai_family);
        printf("        ai_socktype     %d\n", ai.ai_socktype);
        printf("        ai_addr         %s\n", inet_ntoa(((struct sockaddr_in *)ai.ai_addr)->sin_addr));
        printf(C_G_GRAY"-------"C_RES"\n");
    }
}

void    debug_sockaddr_in(struct sockaddr_in addr)
{
    if (DEBUG_NET == 1)
    {
        printf(C_G_GRAY"[DEBUG] sockaddr_in"C_RES"\n");
        printf("        sin_family          %d\n", addr.sin_family);
        printf("        sin_port            %d\n", addr.sin_port);
        printf("        sin_addr.s_addr     %s (%d)\n", inet_ntoa(addr.sin_addr), addr.sin_addr.s_addr);
        printf(C_G_GRAY"-------"C_RES"\n");
    }
}

void    debug_scan(t_scan scan)
{
    if (DEBUG_STRUCT == 1)
    {
        printf(C_G_BLUE"[DEBUG] scan"C_RES"\n");
        printf("        scan_type   %s\n", scan_type_string(scan.scan_type));
        printf("        response    %s\n", response_string(scan.response));
        printf("        conclusion  %s\n", conclusion_string(scan.conclusion));
        printf(C_G_BLUE"-------"C_RES"\n");
    }
}

void    debug_task(t_task task)
{
    if (DEBUG_STRUCT == 1)
    {
        printf(C_G_YELLOW"[DEBUG] task"C_RES"\n");
        printf("        id                  %d\n", task.scan_tracker_id);
        printf("        task_type           %s\n", task_type_string(task.task_type));
        if (task.task_type == T_SEND)
        {
            printf("        scan_type           %s\n", scan_type_string(task.scan_type));
            printf("        dst_port            %d\n", task.dst_port);
            printf("        target_address      %s\n", inet_ntoa(task.target_address.sin_addr));
        }
        printf(C_G_YELLOW"-------"C_RES"\n");
    }
}

void    debug_scan_tracker(t_scan_tracker scan_tracker)
{
    if (DEBUG_STRUCT == 1)
    {
        printf(C_G_RED"[DEBUG] scan_tracker"C_RES"\n");
        printf("        count_sent  %d\n", scan_tracker.count_sent);
        printf("        max_retries    %d\n", scan_tracker.max_retries);
        debug_scan(scan_tracker.scan);
        printf(C_G_RED"-------"C_RES"\n");
    }
}

void    debug_port(t_port port)
{
    if (DEBUG_STRUCT == 1)
    {
        printf(C_G_GREEN"[DEBUG] port %d"C_RES"\n", port.port_id);
        printf("        port_id     %d\n", port.port_id);
        printf("        conclusion_tcp  %s\n", conclusion_string(port.conclusion_tcp));
        printf("        conclusion_udp  %s\n", conclusion_string(port.conclusion_udp));
        for (int i = 0; i < g_scan_types_nb; i++)
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
    if (DEBUG_STRUCT == 1)
    {
        printf(C_G_CYAN"[DEBUG] host %s"C_RES"\n", host.input_dest);
        printf("        input_dest          %s\n", host.input_dest);
        printf("        resolved_address    %s\n", host.resolved_address);
        printf("        resolved_hostname   %s\n", host.resolved_hostname);
        debug_sockaddr_in(host.target_address);
        ft_lst_iter_content(host.ports, debug_one_port);
        printf(C_G_CYAN"-------"C_RES"\n");
    }
}

void    debug_queue()
{
    if (DEBUG_QUEUE == 1)
    {
        if (ft_lst_size(g_queue) != 0)
        {
            printf(C_G_GREEN"[DEBUG] g_queue %d"C_RES"\n", ft_lst_size(g_queue));
            printf(C_G_GREEN"-------"C_RES"\n");
        }
    }
}

void    debug_end(t_data dt)
{
    if (DEBUG_END == 1 && dt.host.input_dest)
    {
        printf(C_G_GRAY"[DEBUG] ft_nmap done: 1 IP address (%s)"C_RES"\n", dt.host.input_dest);
            printf("        total_queued        %d\n", g_queued);
            printf("        total_sent          %d\n", g_sent);
            printf("        total_retrieved     %d\n", g_retrieved);
        printf(C_G_GRAY"-------"C_RES"\n");
    }
}