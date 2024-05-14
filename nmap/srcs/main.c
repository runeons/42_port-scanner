#include "../includes/ft_nmap.h"

// cf. ft_nmap.h for details
t_lst *g_queue         = NULL;
int g_scan_types_nb    = 0;
int g_remaining_scans  = 0;
int g_scan_tracker_id  = 0;
int g_socket           = 0;
int g_sequence         = 0;
int g_retrieved        = 0;
int g_sent             = 0;
int g_queued           = 0;
int g_verbose          = FALSE;

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
    int         r;
        
    r = 0;
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
    t_data          dt;
    t_parsed_cmd    parsed_cmd;
    pcap_if_t       *interfaces = NULL;
    char            filter[sizeof("src host xxx.xxx.xxx.xxx")];

    parse_input(&parsed_cmd, ac, av);
    if (is_activated_option(parsed_cmd.act_options, 'h'))
        option_h();
    init_data(&dt, &parsed_cmd);
    init_socket(&dt);
    fill_host(&dt, parsed_cmd.not_options->content);
    debug_host(dt.host);
    init_queue(&dt.host);
    interfaces = find_devices();
    debug_interfaces(interfaces);
    sprintf(filter, "src host %s", dt.host.resolved_address);
    init_sniffer(&dt.sniffer, interfaces->name, filter);
    pcap_freealldevs(interfaces);
    init_handle(&dt.sniffer);

    nmap(&dt);

    debug_end(dt);
	pcap_close(dt.sniffer.handle);
    close(dt.socket);
    free_all_malloc();
    return (0);
}