#include "../includes/ft_nmap.h"

static void     *worker_function(void *dt)
{
    info(C_THREADS, "Starting new thread\n");
    while (g_remaining_scans > 0)
    {
        debug_queue();
        t_task *task = dequeue_task();
        if (task == NULL)
            continue;
        info(C_TASKS, "Dequeued task %d\n", task->scan_tracker_id);
        debug_task(*task);
        handle_task((t_data *)dt, task);
    }
    info(C_THREADS, "Worker return\n");
    pcap_breakloop(((t_data *)dt)->sniffer.handle);
    return (NULL);
}

static void    monitor_fds_to_sniff(t_data *dt)
{
    int         r = 0;

    info(C_GENERIC, "Waiting on poll()...\n");
    r = poll(dt->fds, NFDS, POLL_TIMEOUT);
    if (r < 0)
        exit_error_full_free(dt, "Poll failure.\n");
    if (r == 0)
        exit_error_full_free(dt, "Poll timed out.\n");
    sniff_packets(dt->sniffer.handle, dt);
}

static void     ending_main_thread(t_data *dt)
{
    info(C_THREADS, "Ending main thread\n");
    display_conclusions(dt);
    alarm(0);
    debug_host(dt->host);
    debug_end(*dt);
    pcap_close(dt->sniffer.handle);
    dt->sniffer.handle = NULL;
}

static void     nmap_init(t_data *dt, char *interface_name)
{
    // debug_host(dt->host);
    display_host_init(&dt->host, dt->no_dns);
    init_queue(dt);
    init_sniffer(dt, &dt->sniffer, interface_name);
    init_handle(&dt->sniffer);
    alarm(dt->probes_delay);
}

static int      get_source_numeric_ip(pcap_if_t *interfaces)
{
    pcap_addr_t *addr;

    for (addr = interfaces->addresses; addr != NULL; addr = addr->next)
    {
        if (addr->addr != NULL)
        {
            if (addr->addr->sa_family == AF_INET)
            {
                struct sockaddr_in *sa = (struct sockaddr_in *)addr->addr;
                return (sa->sin_addr.s_addr);
            }
        }
    }
    return (-1);
}

static pcap_if_t    *lookup_loopback(pcap_if_t *interfaces){
    pcap_if_t   *tmp;

    for (tmp = interfaces; tmp; tmp = tmp->next)
        if (strcmp(tmp->name, "lo") == 0)
            return tmp;
    return NULL;
}

static void     init_interface(uint8_t target_is_localhost, char *first_interface_name, int *numeric_src_ip)
{
    pcap_if_t           *interfaces = NULL;
    pcap_if_t           *select_interface = NULL;

    interfaces = find_devices();
    debug_interfaces(interfaces);
    if (!target_is_localhost)
        select_interface = interfaces;
    else
        select_interface = lookup_loopback(interfaces);
    assert(select_interface && "selected interface is NULL");
    *numeric_src_ip = get_source_numeric_ip(select_interface);
    ft_strcpy(first_interface_name,  select_interface->name);
    pcap_freealldevs(interfaces);
    assert(*numeric_src_ip != -1 && "numeric src ip is -1");
}

void    nmap(t_data *dt, char *target)
{
    int         numeric_src_ip;
    char        interface_name[255];
    pthread_t   workers[dt->threads];

    init_socket(dt);
    if (!fill_host(dt, target))
        goto clean_ret;
    if (ft_strcmp(dt->host.resolved_hostname, "localhost") == 0)
        dt->target_is_localhost = 1;
    init_interface(dt->target_is_localhost, interface_name, &numeric_src_ip);
    dt->src_ip = numeric_src_ip;
    nmap_init(dt, interface_name);
    for (int i = 0; i < dt->threads; i++)
        pthread_create(&workers[i], NULL, worker_function, dt);
    info(C_THREADS, "Starting main thread\n");
    while (g_remaining_scans > 0)
        monitor_fds_to_sniff(dt);
    for (int i = 0; i < dt->threads; i++)
    {
        info(C_THREADS, "End thread %d\n", i);
        pthread_join(workers[i], NULL);
    }
    ending_main_thread(dt);
    dt->hosts_nb++;
    clean_ret:
    close_all_sockets(dt);
}

void            nmap_multiple_hosts(t_data *dt, t_parsed_cmd parsed_cmd)
{
    char        *line[255];
    int         err = 0;
    t_option    *file_option = get_option(parsed_cmd.act_options, 'f');

    dt->file = fopen(file_option->param, "r");
    if (!dt->file)
        exit_error_full_free(dt, "fopen: %s\n", strerror(errno));
    while ((err = get_next_line(dt->file->_fileno, line)) >= 0)
    {
        if (err == 0 && *line[0] == '\0')
            break;
        nmap(dt, *line);
    }
    if (err == -1)
        exit_error_full_free(dt, "get_next_line: %s\n", strerror(errno));
    close_file(&dt->file);
}
