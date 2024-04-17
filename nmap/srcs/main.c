#include "ft_nmap.h"

int g_end_server       = FALSE;
int g_sequence         = 0;
int g_max_send         = 15;
int g_task_id          = 0;
int g_retrieve         = 0;
int g_sent             = 0;
int g_queued           = 0;
int g_verbose          = OFF;
int g_scans_nb         = 0;

t_scan all_scans[] =
{
    {SYN,   TCP_SYN_ACK,         OPEN},
    {SYN,   TCP_RST,             CLOSED},
    {SYN,   NO_RESPONSE,         FILTERED},
    {SYN,   ICMP_UNR_C_3,        FILTERED},
    {SYN,   ICMP_UNR_C_NOT_3,    FILTERED},
    {ACK,   TCP_RST,             UNFILTERED},
    {ACK,   NO_RESPONSE,         FILTERED},
    {ACK,   ICMP_UNR_C_3,        FILTERED},
    {ACK,   ICMP_UNR_C_NOT_3,    FILTERED},
    {ICMP,  ICMP_ECHO_REPLY,     OPEN},
    {ICMP,  NO_RESPONSE,         CLOSED},
};

e_conclusion get_scan_conclusion(e_scan_type scan_type, e_response response)
{
    for (size_t i = 0; i < sizeof(all_scans) / sizeof(all_scans[0]); i++)
    {
        if (all_scans[i].scan_type == scan_type && all_scans[i].response == response)
            return (all_scans[i].conclusion);
    }
    printf(C_B_RED"[SHOULD NOT APPEAR] : no conclusion"C_RES"\n"); // 
    return NOT_CONCLUDED; // default
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
    debug_activated_options(parsed_cmd->act_options);
}

void    send_icmp(t_data *dt, t_task *task)
{
    for (int i = 0; i < NFDS; i++) // only one for now
    {
        if (dt->fds[i].revents == 0)
        {
            enqueue_task(dt, task);
            printf(C_B_RED"[REQUEUED] %d No revent / unavailable yet"C_RES"\n", task->id);
            continue;
        }
        if (dt->fds[i].revents != POLLOUT)
            exit_error_close_socket("Poll unexpected result", dt->socket);
        if (dt->fds[i].fd == dt->socket)
        {
            t_packet packet;
            craft_and_send_icmp(dt->socket, &packet, task);
        }
        else
            warning("Unknown fd is readable.");
    }
}

void    *worker_function(void *dt)
{
    (void)dt;
    printf(C_B_YELLOW"[NEW THREAD]"C_RES"\n");
    while (g_end_server == FALSE)
    {
        // debug_queue(*(t_data *)dt);
        t_task *task = dequeue_task(dt);
        if (task == NULL)
        {
            printf(C_B_RED"[ENDING SERVER] %d queue size"C_RES"\n", ft_lst_size(((t_data *)dt)->queue));
            g_end_server = TRUE;
            return NULL;         
        }
        print_info_task("Dequeued task", task->id);
        if (task->task_type == T_SEND)
        {
            if (task->scan_type == ICMP)
            {
                send_icmp((t_data *)dt, task);
            }
        }
    }
    return NULL;
}

void    nmap(t_data *dt, pcap_t *handle)
{
    pthread_t   workers[dt->threads];
    int         r;
        
    (void)handle;
    r = 0;
    for (int i = 0; i < dt->threads; i++)
        pthread_create(&workers[i], NULL, worker_function, dt);
    printf(C_B_YELLOW"[MAIN THREAD - START - PRINT NMAP START]"C_RES"\n");
    while (g_end_server == FALSE)
    {
        printf(C_G_YELLOW"[INFO]"C_RES" Waiting on poll()...\n");
        r = poll(dt->fds, NFDS, POLL_TIMEOUT);
        if (r < 0)
            exit_error("Poll failure.");
        if (r == 0)
            exit_error("Poll timed out.");
        sniff_packets(dt->sniffer.handle);
    }
    for (int i = 0; i < dt->threads; i++)
    {
        print_info_task("END THREAD", i);
        pthread_join(workers[i], NULL);
    }
    printf(C_B_YELLOW"[MAIN THREAD - END - RETRIEVED %d / %d (%d)]"C_RES"\n", g_retrieve, g_sent, g_queued);
}

int     main(int ac, char **av)
{
    t_data          dt;
    t_parsed_cmd    parsed_cmd;

    parse_input(&parsed_cmd, ac, av);
    if (is_activated_option(parsed_cmd.act_options, 'h'))
        option_h();
    initialise_data(&dt, &parsed_cmd);
    open_main_socket(&dt);
    debug_host(dt.host);
    init_queue(&dt);
    prepare_sniffer(&dt);

    nmap(&dt, dt.sniffer.handle);

	pcap_close(dt.sniffer.handle);
    close(dt.socket);
    free_all_malloc();
    return (0);
}