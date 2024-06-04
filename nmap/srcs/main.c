#include "../includes/ft_nmap.h"

// cf. ft_nmap.h for details
t_lst *g_queue         = NULL;
int g_scan_types_nb    = 0;
int g_remaining_scans  = 0;
int g_scan_tracker_id  = 0;
int g_sequence         = 0;
int g_retrieved        = 0;
int g_sent             = 0;
int g_queued           = 0;
int g_verbose          = FALSE;

static int get_source_numeric_ip(pcap_if_t *interfaces){
    pcap_addr_t *addr;

    for (addr = interfaces->addresses; addr != NULL; addr = addr->next) {
        if (addr->addr != NULL) {
            if (addr->addr->sa_family == AF_INET) {
                struct sockaddr_in *sa = (struct sockaddr_in *)addr->addr;
                return sa->sin_addr.s_addr;
            }
        }
    }
    return -1;
}

static void    close_all_sockets(t_data *dt){
    for (int i = 0; i < SOCKET_POOL_SIZE; i++){
        close(dt->icmp_socket_pool[i]);
    }
    for (int i = 0; i < SOCKET_POOL_SIZE; i++){
        close(dt->udp_socket_pool[i]);
    }
    for (int i = 0; i < SOCKET_POOL_SIZE; i++){
        close(dt->tcp_socket_pool[i]);
    }
}

static void    option_h()
{
    display_help();
    free_all_malloc();
    exit(0);
}

static void    parse_input(t_parsed_cmd *parsed_cmd, int ac, char **av)
{
    if (ac < 2)
        option_h();
    *parsed_cmd = parse_options(ac, av);
    if (DEBUG_PARSING)
        debug_activated_options(parsed_cmd->act_options);
}

void    *worker_function(void *dt)
{
    print_info_thread("STARTING NEW THREAD");
    while (g_remaining_scans != 0)
    {
        //debug_queue();
        t_task *task = dequeue_task();
        if (task == NULL)
            continue;
        print_info_task("Dequeued task", task->scan_tracker_id);
        handle_task((t_data *)dt, task);
    }
    print_info_thread("WORKER RETURN");
    pcap_breakloop(((t_data *)dt)->sniffer.handle);
    return NULL;
}

void    nmap(t_data *dt)
{
    pthread_t   workers[dt->threads];
    int         r = 0;
    
    for (int i = 0; i < dt->threads; i++)
        pthread_create(&workers[i], NULL, worker_function, dt);
    print_info_thread("STARTING MAIN THREAD");
    while (g_remaining_scans != 0)
    {
        printf(C_G_BLUE"[INFO]"C_RES"     Waiting on poll()...\n");
        r = poll(dt->fds, NFDS, POLL_TIMEOUT);
        if (r < 0)
            exit_error("Poll failure.");
        if (r == 0)
            exit_error("Poll timed out.");
        sniff_packets(dt->sniffer.handle, dt);
    }
    for (int i = 0; i < dt->threads; i++)
    {
        print_info_task("END THREAD", i);
        pthread_join(workers[i], NULL);
    }
    print_info_thread("ENDING MAIN THREAD");
}

int     main(int ac, char **av)
{
    int             file_input;
    int             one_target;
    int             numeric_src_ip;
    t_data          dt;
    t_parsed_cmd    parsed_cmd;
    pcap_if_t       *interfaces = NULL;
    char            filter[sizeof("src host xxx.xxx.xxx.xxx")];

    parse_input(&parsed_cmd, ac, av);

    if (is_activated_option(parsed_cmd.act_options, 'h'))
        option_h();
    file_input = is_activated_option(parsed_cmd.act_options, 'f');
    one_target = ft_lst_size(parsed_cmd.not_options);

    if ((!file_input && one_target != 1)  || (file_input && one_target >=1))
        exit_error("ft_nmap: usage error: You can only supply either a file or a single target address as inputs");

    interfaces = find_devices();
    debug_interfaces(interfaces);
    numeric_src_ip = get_source_numeric_ip(interfaces);
    printf("%d\n", numeric_src_ip);
    assert( numeric_src_ip != -1 && "numeric src ip is -1");

    if (is_activated_option(parsed_cmd.act_options, 'f'))
    {
        t_option *file_option = get_option(parsed_cmd.act_options, 'f');
        FILE *file = fopen(file_option->param, "r");
        if (!file)
        {
            perror("fopen: error");
            exit(1);
        }
        char *line[255];
        int err = 0;
        while ((err = get_next_line(file->_fileno, line)) >= 0){
            if (err == 0 && *line[0] == '\0')
                break;

            init_data(&dt, &parsed_cmd);
            init_socket(&dt);
            fill_host(&dt, *line);
            debug_host(dt.host);
            dt.src_ip = numeric_src_ip;
            init_queue(&dt);
            sprintf(filter, "src host %s", dt.host.resolved_address);
            init_sniffer(&dt.sniffer, interfaces->name, filter);
            init_handle(&dt.sniffer);

            nmap(&dt);

            debug_host(dt.host);
            debug_end(dt);
            pcap_close(dt.sniffer.handle);
            close_all_sockets(&dt);
        }
        if (err == -1){
            fprintf(stderr, "get_next_line: error\n");
            exit(err);
        }
        fclose(file);
    } else {
        init_data(&dt, &parsed_cmd);
        init_socket(&dt);
        fill_host(&dt, parsed_cmd.not_options->content);
        debug_host(dt.host);
        dt.src_ip = numeric_src_ip;
        init_queue(&dt);
        sprintf(filter, "src host %s", dt.host.resolved_address);
        init_sniffer(&dt.sniffer, interfaces->name, filter);
        init_handle(&dt.sniffer);

        nmap(&dt);

        debug_host(dt.host);
        debug_end(dt);
        pcap_close(dt.sniffer.handle);
        close_all_sockets(&dt);
    }
    pcap_freealldevs(interfaces);
    free_all_malloc();
    return (0);
}
