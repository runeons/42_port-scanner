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

void            display_conclusions(t_data *dt) // COULD CLEAN
{
    t_lst *curr_port    = dt->host.ports;
    int padding         = 0;
    
    padding = get_results_padding();
    print_header(padding);
    while (curr_port != NULL)
    {
        int pos_tcp      = 0;
        int pos_udp      = 0;
        char *tcp_buffer = mmalloc(sizeof(char) * padding + 1); // TO PROTECT
        char *udp_buffer = mmalloc(sizeof(char) * padding + 1); // TO PROTECT
        ft_memset(tcp_buffer, 0, padding);
        ft_memset(udp_buffer, 0, padding);
        t_port *port = curr_port->content;
        for (int i = 0; i < g_scan_types_nb; i++)
        {
            t_scan_tracker *tracker = &(port->scan_trackers[i]);
            if (tracker == NULL) // TO PROTECT
                printf(C_B_RED"[SHOULD NOT APPEAR] Empty tracker"C_RES"\n");
            if (tracker->scan.scan_type != UDP)
                pos_tcp += snprintf(tcp_buffer + pos_tcp, padding + 1 - pos_tcp,  "%s(%s) ", scan_type_string(tracker->scan.scan_type), conclusion_string(tracker->scan.conclusion));
            else
                pos_udp += snprintf(udp_buffer, padding + 1,  "%s(%s) ", scan_type_string(tracker->scan.scan_type), conclusion_string(tracker->scan.conclusion));
            // printf(C_B_RED"%s"C_RES"\n", reason_string(tracker->scan.response));
        }
        if (pos_tcp != 0)
            printf("| %5d/tcp | %-*s | %-22s | %-14s |\n", port->port_id, padding, tcp_buffer, get_tcp_service(port->port_id), conclusion_string(port->conclusion_tcp));
        if (pos_udp != 0)
            printf("| %5d/udp | %-*s | %-22s | %-14s |\n", port->port_id, padding, udp_buffer, get_udp_service(port->port_id), conclusion_string(port->conclusion_udp));
        curr_port = curr_port->next;
        print_empty_line(padding);
    }
    print_separator_line(padding);
}
