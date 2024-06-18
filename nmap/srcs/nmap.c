#include "../includes/ft_nmap.h"

static void     close_all_sockets(t_data *dt)
{
    for (int i = 0; i < SOCKET_POOL_SIZE; i++)
        close(dt->icmp_socket_pool[i]);
    for (int i = 0; i < SOCKET_POOL_SIZE; i++)
        close(dt->udp_socket_pool[i]);
    for (int i = 0; i < SOCKET_POOL_SIZE; i++)
        close(dt->tcp_socket_pool[i]);
}

static void     *worker_function(void *dt)
{
    print_info_thread("STARTING NEW THREAD");
    while (g_remaining_scans > 0)
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
    return (NULL);
}

static void    monitor_fds_to_sniff(t_data *dt)
{
    int         r = 0;

    printf(C_G_BLUE"[INFO]"C_RES"     Waiting on poll()...\n");
    r = poll(dt->fds, NFDS, POLL_TIMEOUT);
    if (r < 0)
        exit_error("Poll failure.");
    if (r == 0)
        exit_error("Poll timed out.");
    sniff_packets(dt->sniffer.handle, dt);
    // fprintf(stderr, "WAIT TO JOIN\n");
}

static void    ending_main_thread(t_data *dt)
{
    print_info_thread("ENDING MAIN THREAD");
    display_conclusions(dt);
    alarm(0);
    debug_host(dt->host);
    debug_end(*dt);
    pcap_close(dt->sniffer.handle);
}

void    nmap(char *target, char *interface_name, int numeric_src_ip, t_data *dt)
{
    pthread_t   workers[dt->threads];

    init_socket(dt);
    dt->src_ip = numeric_src_ip;
    if (!fill_host(dt, target))
        goto clean_ret;
    // debug_host(dt->host);
    display_nmap_init(dt);
    display_host_init(&dt->host, dt->no_dns);
    init_queue(dt);
    init_sniffer(dt, &dt->sniffer, interface_name);
    init_handle(&dt->sniffer);
    alarm(1);
    for (int i = 0; i < dt->threads; i++)
        pthread_create(&workers[i], NULL, worker_function, dt);
    print_info_thread("STARTING MAIN THREAD");
    while (g_remaining_scans > 0)
        monitor_fds_to_sniff(dt);
    for (int i = 0; i < dt->threads; i++)
    {
        print_info_task("END THREAD", i);
        pthread_join(workers[i], NULL);
    }
    ending_main_thread(dt);
    clean_ret:
    close_all_sockets(dt);
}

void            nmap_multiple_hosts(t_data *dt, t_parsed_cmd parsed_cmd, char *first_interface_name, int numeric_src_ip)
{
    char        *line[255];
    int         err = 0;
    t_option    *file_option = get_option(parsed_cmd.act_options, 'f');

    FILE *file = fopen(file_option->param, "r");
    if (!file)
        exit_error_free("ft_nmap: fopen: %s\n", strerror(errno));
    while ((err = get_next_line(file->_fileno, line)) >= 0)
    {
        if (err == 0 && *line[0] == '\0')
            break;
        nmap(*line, first_interface_name, numeric_src_ip, dt);
        dt->hosts_nb++;
    }
    if (err == -1)
        exit_error_free("ft_nmap: get_next_line: %s\n", strerror(errno)); // TO TRY OUT
    fclose(file);
}
