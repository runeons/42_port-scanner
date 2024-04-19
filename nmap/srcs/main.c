#include "ft_nmap.h"

// cf. ft_nmap.h for details
t_lst *g_queue         = NULL;
int g_scan_types_nb    = 0;
int g_scans_tracker    = 0;
int g_scan_tracker_id  = 0;
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

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

e_response determine_response_type(t_data *dt, t_task *task)
{
    (void)dt;
    struct ip *ip_hdr = (struct ip *)(task->packet + ETH_H_LEN);
    if (ip_hdr->ip_p == IPPROTO_TCP)
    {
        struct tcphdr *tcp_hdr = (struct tcphdr *)(task->packet + ETH_H_LEN + sizeof(struct ip));

        if (tcp_hdr->syn && tcp_hdr->ack)
            return TCP_SYN_ACK;
        else if (tcp_hdr->rst)
            return TCP_RST;
    }
    else if (ip_hdr->ip_p == IPPROTO_UDP)
        return UDP_ANY;
    else if (ip_hdr->ip_p == IPPROTO_ICMP)
    {
        struct icmp *icmp_hdr = (struct icmp *)(task->packet + ETH_H_LEN + sizeof(struct ip));

        if (icmp_hdr->icmp_type == ICMP_ECHOREPLY)
            return ICMP_ECHO_OK;
        else if (icmp_hdr->icmp_type == ICMP_UNREACH)
        {
            if (icmp_hdr->icmp_code == 3)
                return ICMP_UNR_C_3;
            else if (icmp_hdr->icmp_code == 1 || icmp_hdr->icmp_code == 2 ||
                     icmp_hdr->icmp_code == 9 || icmp_hdr->icmp_code == 10 ||
                     icmp_hdr->icmp_code == 13)
                return ICMP_UNR_C_NOT_3;
        }
    }
    return OTHER;
}

void    update_scan_tracker(t_data *dt, int scan_tracker_id, e_response response)
{
    t_lst *curr_port = dt->host.ports;

    while (curr_port != NULL)
    {
        t_port *port = curr_port->content;

        for (int i = 0; i < g_scan_types_nb; i++)
        {
            t_scan_tracker *tracker = &(port->scan_trackers[i]);
            if (tracker == NULL)
                printf(C_B_RED"[SHOULD NOT APPEAR] Empty tracker"C_RES"\n");
            if (tracker->id == scan_tracker_id)
            {
                tracker->scan.response = response;
                return;
            }
        }
        curr_port = curr_port->next;
    }
    printf(C_B_RED"[SHOULD NOT APPEAR] scan_tracker_id not found"C_RES"\n");
}

int     extract_response_id(t_data *dt, t_task *task, e_response response)
{
    (void)dt;
    int id = -1;

    if (response == ICMP_ECHO_OK)
    {
        struct icmp *icmp_hdr = (struct icmp *)(task->packet + ETH_H_LEN + sizeof(struct ip));
        if (icmp_hdr)
            id = icmp_hdr->icmp_id;
    }
    else
        printf(C_B_RED"[SHOULD NOT APPEAR] response != ICMP_ECHO_OK"C_RES"\n");
    return id;
}

void    handle_recv_task(t_data *dt, t_task *task)
{
    int         id;
    e_response  response;

    (void)dt;
    (void)task;
    response = determine_response_type(dt, task);
    id = extract_response_id(dt, task, response);
    // printf(C_G_RED"[QUICK DEBUG] id [%d] [%s]"C_RES"\n", id, response_string(response));
    update_scan_tracker(dt, id, response);
    // debug_task(*task);
    g_scans_tracker--;
}

void    handle_send_task(t_data *dt, t_task *task)
{
    for (int i = 0; i < NFDS; i++) // only one for now
    {
        if (dt->fds[i].revents == 0)
        {
            enqueue_task(task);
            printf(C_B_RED"[REQUEUED] %d No revent / unavailable yet"C_RES"\n", task->scan_tracker_id);
            continue;
        }
        if (dt->fds[i].revents != POLLOUT)
            exit_error_close_socket("Poll unexpected result", dt->socket);
        if (dt->fds[i].fd == dt->socket)
        {
            t_packet packet;
            if (task->scan_type == ICMP)
                craft_icmp_packet(&packet, task);
            send_packet(g_socket, &packet, &task->target_address, task->scan_tracker_id);
        }
        else
            warning("Unknown fd is readable.");
    }
}

void    handle_task(t_data *dt, t_task *task)
{
    if (task->task_type == T_SEND)
        handle_send_task(dt, task);
    else if (task->task_type == T_RECV)
        handle_recv_task(dt, task);
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