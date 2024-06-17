#include "../includes/ft_nmap.h"

int             resolve_address(t_host *host) // check that dest exists and resolve address if input == hostname
{
    struct addrinfo     *resolved_add;
    struct addrinfo     *tmp;
    int s = 1;

    if ((s = getaddrinfo(host->input_dest, NULL, NULL, &resolved_add)) != 0){
        fprintf(stderr, "ft_nmap: unknown host <%s>  %s\n", host->input_dest, gai_strerror(s));
        return 0;
    }
    // debug_addrinfo(*resolved_add);
    tmp = resolved_add;
    while (tmp != NULL)
    {
        if ((struct sockaddr_in *)tmp->ai_addr)
            host->resolved_address = ft_strdup(inet_ntoa(((struct sockaddr_in *)tmp->ai_addr)->sin_addr));
        if (host->resolved_address == NULL)
            exit_error("ft_nmap: malloc failure.\n");
        tmp = tmp->ai_next;
        break; // useful if many
    }
    freeaddrinfo(resolved_add);
    return 1;
}

int             resolve_hostname(t_host *host) // useful only when input_dest is ip address (vs. hostname)
{
    char    hostname[MAX_HOSTNAME_LEN];

    ft_bzero(hostname, MAX_HOSTNAME_LEN);
    if (inet_pton(AF_INET, host->resolved_address, &(host->target_address.sin_addr)) <= 0){
        fprintf(stderr, "ft_nmap: address error: Invalid IPv4 address <%s>.\n", host->input_dest);
        return 0;
    }
    if (getnameinfo((struct sockaddr*)&(host->target_address), sizeof(host->target_address), hostname, sizeof(hostname), NULL, 0, 0) != 0){
        fprintf(stderr, "ft_nmap: address error: The hostname could not be resolved <%s>.\n",  host->input_dest);
        return 0;
    }
    else
    {
        host->resolved_hostname = ft_strdup(hostname);
        if (host->resolved_hostname == NULL)
            exit_error("ft_nmap: malloc failure.\n");
    }
    return 1;
}

static void      init_scan_tracker(t_scan_tracker *scan_tracker, e_scan_type scan_type, uint16_t dst_port)
{
    scan_tracker->id                  = g_scan_tracker_id++;
    scan_tracker->scan.scan_type      = scan_type;
    scan_tracker->scan.response       = IN_PROGRESS;
    scan_tracker->scan.conclusion     = NOT_CONCLUDED; 
    scan_tracker->count_sent          = 0;
    scan_tracker->max_send            = MAX_SEND;
    scan_tracker->dst_port            = dst_port;
    scan_tracker->src_port            = ((getpid() + g_sequence++) & 0xffff) | 0x8000;
    gettimeofday(&scan_tracker->last_send, NULL);
}

static t_port    *create_port(int port_id, e_scan_type *unique_scans)
{
    t_port  *port = NULL;

    port = mmalloc(sizeof(t_port));
    if (port == NULL)
        exit_error("ft_nmap: malloc failure.");
    port->port_id           = port_id;
    port->conclusion_udp        = NOT_CONCLUDED;
    port->conclusion_tcp        = NOT_CONCLUDED;
    if (!(port->scan_trackers = mmalloc(sizeof(t_scan_tracker) * g_scan_types_nb)))
        exit_error("ft_nmap: malloc failure.");
    for (int i = 0; i < g_scan_types_nb; i++)
        init_scan_tracker(&port->scan_trackers[i], unique_scans[i], port->port_id);
    // debug_scan_tracker(port->scan_trackers[0]);
    return port;
}

static void     add_port(t_host *host, int port_id, e_scan_type *unique_scans)
{
    t_port *port;

    port = create_port(port_id, unique_scans);
    ft_lst_add_node_back(&host->ports, ft_lst_create_node(port));
    // debug_port(*port);
}

int             fill_host(t_data *dt, char *curr_arg)
{
    if (dt)
    {
        dt->host.input_dest = curr_arg;
        if (!resolve_address(&dt->host))
            return 0;
        if (!resolve_hostname(&dt->host))
            return 0;
        for (uint16_t *port_id = dt->first_port; port_id <= dt->last_port; port_id++)
            add_port(&dt->host, *port_id, dt->unique_scans);
    }
    return 1;
}

void            init_host(t_host *host)
{
    host->input_dest                        = "";
    host->resolved_address                  = NULL;
    host->resolved_hostname                 = "";
    ft_memset(&(host->target_address), 0, sizeof(struct sockaddr_in));
    host->target_address.sin_family         = AF_INET;
    host->target_address.sin_port           = 0;
    host->target_address.sin_addr.s_addr    = INADDR_ANY;
    host->ports                             = NULL;
    host->approx_rtt_upper_bound            =  5000;  // 5 seconds
    ft_bzero(&host->ma, sizeof(t_mavg));
}

static void     init_data_struct(t_data *dt, t_parsed_cmd *parsed_cmd)
{
    dt->act_options         = parsed_cmd->act_options;
    dt->src_port            = (getpid() & 0xffff) | 0x8000; // base port 
    ft_memset(&(dt->src_address),  0, sizeof(struct sockaddr_in));
    dt->src_address.sin_family        = AF_INET;
    dt->src_address.sin_addr.s_addr   = INADDR_ANY;
    dt->src_address.sin_port          = htons(dt->src_port);
    ft_memset(dt->fds, 0, sizeof(dt->fds));
    //dt->fds[0].events       = POLLOUT;
    // dt->queue            = NULL;
    dt->threads             = THREADS_NB;
    dt->no_dns              = FALSE;
    dt->reason              = FALSE;
    ft_memset(&dt->host, 0, sizeof(dt->host));
    init_host(&dt->host);
    dt->first_port          = NULL;
    dt->last_port           = NULL;
    ft_memset(&dt->unique_scans, 0, sizeof(dt->unique_scans));
    ft_memset(&dt->sniffer, 0, sizeof(dt->sniffer));
    dt->sniffer.handle      = NULL;          
    dt->sniffer.device      = NULL;          
    dt->sniffer.filter      = NULL;
}

void            init_data(t_data *dt, t_parsed_cmd *parsed_cmd)
{
    init_data_struct(dt, parsed_cmd);
    init_options_params(dt);
}
