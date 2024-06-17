#include "../includes/ft_nmap.h"
#include <utils_services_list.h>

static void     print_separator_line(int padding)
{
    printf("+-----------+");
    for (int i = 0; i <= padding + 1; i++)
        printf("-");
    printf("+------------------------");
    printf("+----------------+\n");
}

static void     print_empty_line(int padding)
{
    printf("|           |");
    for (int i = 0; i <= padding + 1; i++)
        printf(" ");
    printf("|                        ");
    printf("|                |\n");
}

static void     print_header(int padding)
{
    print_separator_line(padding);
    printf("| %-9s | %-*s | %-22s | %-14s |\n", "PORT", padding, "RESULTS", "SERVICE", "CONCLUSION");
    print_separator_line(padding);
}

static char     *get_service(int port_id, e_protocol protocol)
{
    for (size_t i = 0; i < (sizeof(all_services) / sizeof(all_services[0])); i++)
    {
        if (all_services[i].port_id == port_id && all_services[i].protocol == protocol)
            return (all_services[i].name);
    }
    return "unassigned";
}

static char     *get_udp_service(int port_id)
{
    return (get_service(port_id, P_UDP));
}

static char     *get_tcp_service(int port_id)
{
    return (get_service(port_id, P_TCP));
}

static int      get_results_padding()
{
    int tcp_scans_nb    = 0;

    if (g_scan_types_nb == 6)
        tcp_scans_nb = 5;
    else
        tcp_scans_nb = g_scan_types_nb;
    return (20 * tcp_scans_nb);

}

static e_protocol      get_protocol(t_scan scan)
{
    if (scan.scan_type == UDP)
        return P_UDP;
    else if (scan.scan_type == UNKNOWN)
        return P_UNKNOWN;
    else if (scan.scan_type == ICMP) // TEST
        return P_ICMP;
    else
        return P_TCP;
}

static void     init_results_buffer(char **tcp_results, char **udp_results, int padding)
{
    if (!(*tcp_results = mmalloc(sizeof(char) * padding + 1))) // TO PROTECT
        exit_error_free("ft_nmap: malloc failure\n");
    if (!(*udp_results = mmalloc(sizeof(char) * padding + 1))) // TO PROTECT
        exit_error_free("ft_nmap: malloc failure\n");
    ft_memset(*tcp_results, 0, padding);
    ft_memset(*udp_results, 0, padding);
}

static int          fill_results_buffer(t_scan scan, char **results_buffer, int pos, int padding)
{
    return (snprintf(*results_buffer + pos, padding + 1 - pos,  "%s(%s) ", scan_type_string(scan.scan_type), conclusion_string(scan.conclusion)));
}

static void         print_filled_line(t_port *port, char *results, int padding, e_protocol protocol)
{
    if (protocol == P_TCP)
        printf("| %5d/tcp | %-*s | %-22s | %-14s |\n", port->port_id, padding, results, get_tcp_service(port->port_id), conclusion_string(port->conclusion_tcp));
    else if (protocol == P_UDP)
        printf("| %5d/udp | %-*s | %-22s | %-14s |\n", port->port_id, padding, results, get_udp_service(port->port_id), conclusion_string(port->conclusion_tcp));
    else
        printf(C_B_RED"[SHOULD NOT APPEAR] unexpected protocol"C_RES"\n");
}

static void         display_each_protocol(t_lst *curr_port, int padding)
{
        int pos_tcp      = 0;
        int pos_udp      = 0;
        char *tcp_results;
        char *udp_results;
        
        init_results_buffer(&tcp_results, &udp_results, padding);
        t_port *port = curr_port->content;
        for (int i = 0; i < g_scan_types_nb; i++)
        {
            if (port == NULL || &(port->scan_trackers[i]) == NULL)
                exit_error_free("ft_nmap: unexpected memory access\n");
            t_scan scan = (port->scan_trackers[i]).scan;
            if (get_protocol(scan) == P_TCP)
                pos_tcp += fill_results_buffer(scan, &tcp_results, pos_tcp, padding);
            else if (get_protocol(scan) == P_UDP)
                pos_udp += fill_results_buffer(scan, &udp_results, pos_udp, padding);
            else
                printf(C_B_RED"[SHOULD NOT APPEAR] unexpected protocol"C_RES"\n");
            // printf(C_B_RED"%s"C_RES"\n", reason_string(scan.response));
        }
        if (pos_tcp != 0)
            print_filled_line(port, tcp_results, padding, P_TCP);
        if (pos_udp != 0)
            print_filled_line(port, udp_results, padding, P_UDP);
        print_empty_line(padding);
}

void            display_conclusions(t_data *dt)
{
    t_lst *curr_port    = dt->host.ports;
    int padding         = 0;
    
    padding = get_results_padding();
    print_header(padding);
    while (curr_port != NULL)
    {
        display_each_protocol(curr_port, padding);
        curr_port = curr_port->next;
    }
    print_separator_line(padding);
}
