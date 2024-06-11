#include "../includes/ft_nmap.h"

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
    {ICMP,  ICMP_ECHO_OK,        OPEN},             // tmp (initial test only)
    {ICMP,  NO_RESPONSE,         CLOSED},           // tmp (initial test only)
    {UDP,   UDP_ANY,             OPEN},
    {UDP,   NO_RESPONSE,         OPEN_FILTERED},
    {UDP,   ICMP_UNR_C_3,        CLOSED},
    {UDP,   ICMP_UNR_C_NOT_3,    FILTERED},
    {FIN,   NO_RESPONSE,         OPEN_FILTERED},
    {FIN,   TCP_RST,             CLOSED},
    {FIN,   ICMP_UNR_C_3,        FILTERED},
    {FIN,   ICMP_UNR_C_NOT_3,    FILTERED},
    {NUL,   NO_RESPONSE,         OPEN_FILTERED},
    {NUL,   TCP_RST,             CLOSED},
    {NUL,   ICMP_UNR_C_3,        FILTERED},
    {NUL,   ICMP_UNR_C_NOT_3,    FILTERED},
    {XMAS,  NO_RESPONSE,         OPEN_FILTERED},
    {XMAS,  TCP_RST,             CLOSED},
    {XMAS,  ICMP_UNR_C_3,        FILTERED},
    {XMAS,  ICMP_UNR_C_NOT_3,    FILTERED},
};

e_conclusion get_scan_conclusion(e_scan_type scan_type, e_response response)
{
    for (size_t i = 0; i < sizeof(all_scans) / sizeof(all_scans[0]); i++)
    {
        if (all_scans[i].scan_type == scan_type && all_scans[i].response == response)
            return (all_scans[i].conclusion);
    }
    return NOT_CONCLUDED;
}

// static t_port *find_tport(t_data *dt, uint16_t dst_port){
//     t_lst *curr_port = dt->host.ports;
//     while (curr_port != NULL)
//     {
//         t_port *port = curr_port->content;
//         if (port->port_id == dst_port)
//             return port;
//         curr_port = curr_port->next;
//     }
//     return NULL;
// }

static t_scan_tracker *find_tracker(t_data *dt, uint16_t src_port, uint16_t dst_port){
    t_lst *curr_port = dt->host.ports;
    while (curr_port != NULL)
    {
        t_port *port = curr_port->content;
        if (port->port_id != dst_port)
            goto next_port;
        for (int i = 0; i < g_scan_types_nb; i++)
        {
            t_scan_tracker *tracker = &(port->scan_trackers[i]); //change scan_trackers to be constant size and we can easily access the correct index based on the scan type
            if (tracker == NULL) // TO PROTECT
                printf(C_B_RED"[SHOULD NOT APPEAR] Empty tracker"C_RES"\n");
            if (tracker->dst_port == src_port)
                return tracker;
        }
        next_port:
        curr_port = curr_port->next;
    }
    return NULL;
}

e_response determine_response_type(t_data *dt, t_task *task)
{
    (void)dt;
    struct ip *ip_hdr = (struct ip *)(task->packet + ETH_H_LEN);
    if (ip_hdr->ip_p == IPPROTO_TCP)
    {
        struct tcphdr *tcp_hdr = (struct tcphdr *)(task->packet + ETH_H_LEN + IP_H_LEN);

        if (tcp_hdr->syn && tcp_hdr->ack)
            return TCP_SYN_ACK;
        else if (tcp_hdr->rst)
            return TCP_RST;
    }
    else if (ip_hdr->ip_p == IPPROTO_UDP)
        return UDP_ANY;
    else if (ip_hdr->ip_p == IPPROTO_ICMP)
    {
        struct icmp *icmp_hdr = (struct icmp *)(task->packet + ETH_H_LEN + IP_H_LEN);

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
            if (tracker == NULL) // TO PROTECT
                printf(C_B_RED"[SHOULD NOT APPEAR] Empty tracker"C_RES"\n");
            if (tracker->id == scan_tracker_id)
            {
                tracker->scan.response = response;
                tracker->scan.conclusion = get_scan_conclusion(tracker->scan.scan_type, response);
                if (port->conclusion < tracker->scan.conclusion)
                    port->conclusion = tracker->scan.conclusion;
                if (tracker->scan.conclusion != NOT_CONCLUDED)
                {
                    decr_remaining_scans();
                }
                else
                {
                    printf(C_B_CYAN"[TO IMPLEMENT] - NOT CONCLUDED -> RESEND OR IGNORE / INCREMENT COUNTER"C_RES"\n");
                    decr_remaining_scans(); // remove when all scans are implemented (now, avoid infinite looping)
                }
                return;
            }
        }
        curr_port = curr_port->next;
    }
    printf(C_B_RED"[SHOULD NOT APPEAR] scan_tracker_id not found"C_RES"\n");
}

int     extract_response_id(t_data *dt, t_task *task, e_response response)
{
    int id = -1;
    switch (response){
        case ICMP_ECHO_OK:
        {
            struct icmp *icmp_hdr = (struct icmp *)(task->packet + ETH_H_LEN + sizeof(struct ip));
            if (icmp_hdr)
                id = icmp_hdr->icmp_id;
            break;            
        }
        case TCP_SYN_ACK: case TCP_RST:
        {
            struct tcphdr *tcp_hdr = (struct tcphdr *)(task->packet + ETH_H_LEN + sizeof(struct ip));
            if (tcp_hdr){
                t_scan_tracker *tracker = find_tracker(dt, htons(tcp_hdr->dest), htons(tcp_hdr->source)); //identification is based on our source port
                if (tracker)
                    id = tracker->id;
            }
            break;
        }
        case UDP_ANY:
        {
            struct tcphdr *udp_hdr = (struct tcphdr *)(task->packet + ETH_H_LEN + sizeof(struct ip));
                if (udp_hdr){
                    t_scan_tracker *tracker =  find_tracker(dt, htons(udp_hdr->dest), htons(udp_hdr->source));
                    if (tracker)
                        id = tracker->id;
                }
            break;
        }
        default:
            printf(C_B_CYAN"[TO IMPLEMENT] - response != ICMP_ECHO_OK"C_RES"\n");
    }
        
    return id;
}

void    handle_recv_task(t_data *dt, t_task *task)
{
    e_response      response;

    response = determine_response_type(dt, task);
    task->scan_tracker_id = extract_response_id(dt, task, response);
    update_scan_tracker(dt, task->scan_tracker_id, response);
    // debug_task(*task);
}

void    handle_send_task(t_data *dt, t_task *task)
{
    for (int i = 0; i < NFDS; i++)
    {
        if (dt->fds[i].fd == task->socket){
            if (dt->fds[i].revents == 0)
            {
                enqueue_task(task);
                printf(C_B_RED"[REQUEUED] %d No event detected for this socket"C_RES"\n", task->scan_tracker_id);
                continue;
            }

            if (!(dt->fds[i].revents & POLLOUT))
                exit_error_close_socket("Poll unexpected result", task->socket);

            t_packet packet;

            switch (task->scan_type){
                case ICMP:
                    craft_icmp_packet(&packet, task);
                    break;
                case SYN:
                case ACK:
                case FIN:
                case NUL:
                case XMAS:
                    construct_tcp_packet(&packet, task);
                    break;
                case UDP:
                    construct_udp_packet(&packet, task);
                    break;
                default:
                    warning("Unknown SCAN");
                    continue;
            }
            //printf("Searching port: %d || ", task->dst_port);
            send_packet(task->socket, &packet, &task->target_address, task->scan_tracker_id);
            t_scan_tracker *this_scan_tracker = find_tracker(dt, task->src_port,task->dst_port);
            assert(this_scan_tracker && "couldn't find the scan tracker in handle_send_task");
            if (this_scan_tracker){
                //printf("dst_port : %d\n", this_scan_tracker->dst_port);
                gettimeofday(&this_scan_tracker->last_send, NULL);
                //if (this_scan_tracker->count_sent >= this_scan_tracker->max_send)
                //    continue;
                this_scan_tracker->count_sent++;
                //printf("COUNT_SENT: %d\n", this_scan_tracker->count_sent);
            }
        }
        else
        {
            //warning("Unknown fd.");
            //printf("fd: %d != %d --- %d/%d\n", dt->fds[i].fd, task->socket, i, NFDS);
        }
    }
}

static void handle_check_task(t_data *dt, t_task *task){
    (void) task;
    int tmp_socket = -1;
    struct timeval      time_now = {0,0};
    gettimeofday(&time_now, NULL);

    t_lst *curr_port = dt->host.ports;
    while (curr_port != NULL)
    {
        t_port *port = curr_port->content;
        for (int i = 0; i < g_scan_types_nb; i++)
        {
            t_scan_tracker *tracker = &(port->scan_trackers[i]);
            if (tracker == NULL) // TO PROTECT
                printf(C_B_RED"[SHOULD NOT APPEAR] Empty tracker"C_RES"\n");
            
            //if (tracker->count_sent)
            //simplistic check in order to skip concluded, maybe we gonna need to skip only if the strongest scan type if done.
            if (tracker->scan.conclusion == NOT_CONCLUDED){
                if (tracker->count_sent > 0 && tracker->count_sent < tracker->max_send){
                    //printf("-----------------------------------------/nlast send %ld\n", tracker->last_send.tv_sec);
                    if (deltaT(&tracker->last_send ,&time_now) > 5000){
                        t_task          *send_task = create_task();
                        switch (tracker->scan.scan_type){
                            case ICMP:
                                tmp_socket = dt->fds[0].fd;
                                break;
                            case UDP:
                                tmp_socket = dt->fds[1].fd;
                                break;
                            case SYN:case ACK:case FIN:case NUL:case XMAS:
                                tmp_socket = dt->fds[2].fd;
                                break;
                            default:
                                printf("Invalid scan type | just skip this task");
                                continue;
                        }
                        tracker->dst_port = ((getpid() + g_sequence++) & 0xffff) | 0x8000; //add mutex
                        fill_send_task(send_task, tracker->id, dt->host.target_address, port->port_id, tracker->scan.scan_type, tmp_socket, dt->src_ip, tracker->dst_port);
                        //printf("dst_port: %d src_port: %d\n", port->port_id, tracker->dst_port);
                        //printf("It should be recycled\n");
                        //printf("sent_count : %d\n", tracker->count_sent);
                        enqueue_task(send_task);
                        //debug_task(*task);
                        //g_remaining_scans++;
                    }
                    
                }
                else
                {
                    decr_remaining_scans();
                    //printf("Remaining scans : %d\n", g_remaining_scans);
                }
            }
        }
        curr_port = curr_port->next;
    }
}

void    handle_task(t_data *dt, t_task *task)
{
    if (task->task_type == T_SEND)
        handle_send_task(dt, task);
    else if (task->task_type == T_RECV)
        handle_recv_task(dt, task);
    else if (task->task_type == T_CHECK)
        handle_check_task(dt, task);
}
