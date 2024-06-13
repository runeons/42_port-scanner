#include "../includes/ft_nmap.h"

void display_host_init(t_host *host)
{
    
    printf("Nmap scan report for %s (%s)\n", host->input_dest, host->resolved_address);
    //printf("Host is up (0.00035s latency).\n", );
    //printf("Other addresses for google.fr (not scanned): 2a00:1450:4007:819::2003\n", );
    printf("rDNS record for %s: %s\n", host->resolved_address, host->resolved_hostname);
    printf("\n");
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

static void     print_separator_line()
{
    printf("+-----------+");
    for (int i = 0; i <= MAX_RESULTS_LEN + 1; i++)
        printf("-");
    printf("+----------------+\n");
}

static void     print_empty_line()
{
    printf("|           |");
    for (int i = 0; i <= MAX_RESULTS_LEN + 1; i++)
        printf(" ");
    printf("|                |\n");
}

static void     print_header()
{
    print_separator_line();
    printf("| %-9s | %-*s | %-14s |\n", "PORT", MAX_RESULTS_LEN, "RESULTS", "CONCLUSION");
    print_separator_line();
}

void            display_conclusions(t_data *dt)
{
    t_lst *curr_port = dt->host.ports;
    print_header();
    while (curr_port != NULL)
    {
        int pos_tcp      = 0;
        int pos_udp      = 0;
        char tcp_buffer[MAX_RESULTS_LEN] = "";
        char udp_buffer[MAX_RESULTS_LEN] = "";
        ft_memset(tcp_buffer, 0, MAX_RESULTS_LEN);
        ft_memset(udp_buffer, 0, MAX_RESULTS_LEN);
        t_port *port = curr_port->content;
        for (int i = 0; i < g_scan_types_nb; i++)
        {
            t_scan_tracker *tracker = &(port->scan_trackers[i]);
            if (tracker == NULL) // TO PROTECT
                printf(C_B_RED"[SHOULD NOT APPEAR] Empty tracker"C_RES"\n");
            if (tracker->scan.scan_type != UDP)
                pos_tcp += snprintf(tcp_buffer + pos_tcp, sizeof(tcp_buffer) - pos_tcp,  "%s(%s) ", scan_type_string(tracker->scan.scan_type), conclusion_string(tracker->scan.conclusion));
            else
                pos_udp += snprintf(udp_buffer, sizeof(udp_buffer),  "%s(%s) ", scan_type_string(tracker->scan.scan_type), conclusion_string(tracker->scan.conclusion));
        }
        if (pos_tcp != 0)
            printf("| %5d/tcp | %-*s | %-14s |\n", port->port_id, MAX_RESULTS_LEN, tcp_buffer, conclusion_string(port->conclusion_tcp));
        if (pos_udp != 0)
            printf("| %5d/udp | %-*s | %-14s |\n", port->port_id, MAX_RESULTS_LEN, udp_buffer, conclusion_string(port->conclusion_udp)); // conclusion to split in udp and tcp
        curr_port = curr_port->next;
        print_empty_line();
    }
    print_separator_line();
}
