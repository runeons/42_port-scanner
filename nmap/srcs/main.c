#include "ft_nmap.h"

// cf. ft_nmap.h for details
t_lst *g_queue         = NULL;
int g_scan_types_nb    = 0;
int g_scans_tracker    = 0;
int g_socket           = 0;
int g_sequence         = 0;
int g_task_id          = 0;
int g_retrieve         = 0;
int g_sent             = 0;
int g_queued           = 0;
int g_verbose          = FALSE;


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
    if (DEBUG_PARSING)
        debug_activated_options(parsed_cmd->act_options);
}

void    send_icmp(t_data *dt, t_task *task)
{
    for (int i = 0; i < NFDS; i++) // only one for now
    {
        if (dt->fds[i].revents == 0)
        {
            enqueue_task(task);
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

// const struct iphdr          *ip_h;
// const struct icmphdr        *icmp_h;
// const char                  *icmp_payload;

// void    packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) // args = last arg of pcap_loop
// {
//     (void)args;
//     (void)header;
//     ip_h            = (struct iphdr *)          (packet + ETH_H_LEN);                           // packet + 14
//     icmp_h          = (struct icmphdr *)        (packet + ETH_H_LEN + IP_H_LEN);                // packet + 14 + 20
//     icmp_payload    = (char *)                  (packet + ETH_H_LEN + IP_H_LEN + ICMP_H_LEN);   // packet + 14 + 20 + 8
//     if (icmp_h->type != ICMP_ECHO_REPLY)
//         warning_int("Invalid ICMP type: (bytes)", icmp_h->type);
//     else
//     {
//         print_info_int("Retrieved packet", g_retrieve);
//         // printf(C_G_MAGENTA"[INFO]"C_RES" Retrieved packet "C_G_GREEN"[%d]"C_RES"\n", g_retrieve);
//         // printf(C_G_MAGENTA"[INFO]"C_RES" Retrieved packet of size "C_G_GREEN"[%d]"C_RES" with type "C_G_GREEN"[%d]"C_RES" and code "C_G_GREEN"[%d]"C_RES"\n", header->len, icmp_h->type, icmp_h->code);
//         // printf(C_G_MAGENTA"[INFO]"C_RES"PAYLOAD [%s]\n", icmp_payload);
//         g_retrieve++;
//     }
// }

void    recv_icmp(t_data *dt, t_task *task)
{
    (void)dt;
    (void)task;
    g_scans_tracker--;
}

void    handle_task(t_data *dt, t_task *task)
{
    if (task->task_type == T_SEND)
    {
        if (task->scan_type == ICMP)
        {
            send_icmp(dt, task);
        }
    }
    else if (task->task_type == T_RECV)
    {
        recv_icmp(dt, task);
    }
}

void    *worker_function(void *dt)
{
    print_info_thread("STARTING NEW THREAD");
    while (g_scans_tracker != 0)
    {
        // debug_queue();
        t_task *task = dequeue_task();
        if (task == NULL)
            continue;
        print_info_task("Dequeued task", task->id);
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
    while (g_scans_tracker != 0)
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

void    init_sniffer(t_sniffer *sniffer, char *device, char *filter)
{
    if (!(sniffer->device = ft_strdup(device)))
        exit_error("Malloc failure.");
    if (!(sniffer->filter = ft_strdup(filter)))
        exit_error("Malloc failure.");
}

int     main(int ac, char **av)
{
    t_data          dt;
    t_parsed_cmd    parsed_cmd;

    parse_input(&parsed_cmd, ac, av);
    if (is_activated_option(parsed_cmd.act_options, 'h'))
        option_h();
    init_data(&dt, &parsed_cmd);
    init_socket(&dt);
    fill_host(&dt, parsed_cmd.not_options->content);
    debug_host(dt.host);
    init_queue(&dt.host);
    init_sniffer(&dt.sniffer, "enp0s3", "src host 1.1.1.1");
    init_handle(&dt.sniffer);

    nmap(&dt);

    debug_end(dt);
	pcap_close(dt.sniffer.handle);
    close(dt.socket);
    free_all_malloc();
    return (0);
}