#include "../includes/ft_nmap.h"
#include <services_list.h>

void display_host_init(t_host *host, int no_dns)
{
    
    printf("Nmap scan report for %s (%s)\n", host->input_dest, host->resolved_address);
    //printf("Host is up (0.00035s latency).\n", );
    //printf("Other addresses for google.fr (not scanned): 2a00:1450:4007:819::2003\n", );
    if (no_dns == FALSE)
        printf("rDNS record for %s: %s\n", host->resolved_address, host->resolved_hostname);
    printf("\n");
}

void display_nmap_end(t_data *dt, int hosts_nb)
{
    struct timeval      end_tv;
    struct timeval      tz;
    int                 time = 0;

    if (gettimeofday(&end_tv, &tz) != 0)
        exit_error("ft_nmap: cannot retrieve time\n"); // CLOSE ?
    time = (end_tv.tv_sec - dt->init_tv.tv_sec) * 1000000 + end_tv.tv_usec - dt->init_tv.tv_usec;
    printf("Nmap done: %d hosts scanned in %.2f seconds\n", hosts_nb, (float)time / 1000000);
}

void display_current_daytime()
{
    struct timeval  tv;
    struct tm       *tm_info;
    char            buffer[32];

    ft_memset(buffer, 0, 32);
    gettimeofday(&tv, NULL);
    tm_info = localtime(&tv.tv_sec); // bonus function only
    snprintf(buffer, sizeof(buffer), "%04d-%02d-%02d %02d:%02d %s",
                tm_info->tm_year + 1900,
                tm_info->tm_mon + 1,
                tm_info->tm_mday,
                tm_info->tm_hour,
                tm_info->tm_min,
                tm_info->tm_zone);
    printf("%s\n", buffer);
}

void display_nmap_init(t_data *dt)
{
    (void)dt;
    printf("Starting ft_nmap at ");
    display_current_daytime();
}

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

char *get_service(int port_id, e_protocol protocol)
{
    for (size_t i = 0; i < (sizeof(all_services) / sizeof(all_services[0])); i++)
    {
        if (all_services[i].port_id == port_id && all_services[i].protocol == protocol)
            return (all_services[i].name);
    }
    return "unassigned";
}

char            *get_udp_service(int port_id)
{
    return (get_service(port_id, P_UDP));
}

char            *get_tcp_service(int port_id)
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
void            display_conclusions(t_data *dt)
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
